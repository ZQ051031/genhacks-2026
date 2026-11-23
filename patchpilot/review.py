"""Workspace, review decisions, and guarded changes to source files."""

import json
import os
import re
import sqlite3
import stat
import subprocess
import tempfile
from contextlib import closing, contextmanager
from pathlib import Path
from uuid import uuid4

from .scanner import digest, scan_tree, source_lines

GITHUB_URL = re.compile(r"https://github\.com/[\w.-]+/[\w.-]+/?", re.ASCII)


class ReviewError(Exception):
    """A scan, decision, or edit could not safely proceed."""


def atomic_write(path, data, mode=0o600):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(data)
            stream.close()
            temporary.chmod(mode)
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def state_home():
    return Path(os.environ.get("PATCHPILOT_HOME", Path.home() / ".patchpilot")).expanduser().resolve()


class Store:
    def __init__(self, home):
        self.home = home
        self.file = home / "review.json"

    def load(self):
        try:
            return json.loads(self.file.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise ReviewError("No scan is available. Scan a repository first.") from None
        except (OSError, ValueError) as error:
            raise ReviewError("Could not read the local review state.") from error

    def save(self, state):
        self.home.mkdir(mode=0o700, parents=True, exist_ok=True)
        atomic_write(self.file, json.dumps(state, ensure_ascii=False, indent=2).encode("utf-8"))

    @contextmanager
    def locked(self):
        self.home.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            with closing(sqlite3.connect(self.home / "review.lock")) as lock, lock:
                lock.execute("BEGIN IMMEDIATE")
                yield
        except sqlite3.Error as error:
            raise ReviewError("Could not lock the review state. Close other PatchPilot instances and retry.") from error

    def refresh(self, state):
        current = self.load()
        if current["run_id"] != state["run_id"]:
            raise ReviewError("The active scan changed. Reload and review again.")
        state.update(current)

    def scan(self, source):
        if not source:
            raise ReviewError("Enter a local directory or a public GitHub URL.")
        self.home.mkdir(mode=0o700, parents=True, exist_ok=True)
        run_id = uuid4().hex
        if "://" in source or source.startswith("git@"):
            if not GITHUB_URL.fullmatch(source) or any(part in {".", ".."} for part in source.rstrip("/").split("/")[-2:]):
                raise ReviewError("Use a local directory or a public https://github.com/OWNER/REPO URL.")
            root = self.home / "clones" / run_id
            root.parent.mkdir(mode=0o700, exist_ok=True)
            env = {key: value for key, value in os.environ.items() if not key.startswith(("GIT_", "GH_"))}
            env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                       GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="/bin/false")
            try:
                subprocess.run(
                    ["git", "-c", f"core.hooksPath={os.devnull}", "-c", "http.followRedirects=false",
                     "-c", "protocol.file.allow=never", "clone", "--depth", "1", "--template=",
                     "--", source, str(root)],
                    env=env, capture_output=True, check=True, timeout=90,
                )
            except (OSError, subprocess.SubprocessError):
                raise ReviewError("Could not clone the public GitHub repository. Check the URL, network, and Git installation.") from None
        else:
            root = Path(source).expanduser().resolve()
            if not root.is_dir():
                raise ReviewError("The local path is not a directory.")
        findings, files, warnings, scanned = scan_tree(root)
        state = {
            "run_id": run_id, "source": source, "root": str(root),
            "findings": findings, "files": files, "warnings": warnings, "scanned": scanned,
        }
        with self.locked():
            self.save(state)
        return state

    def find(self, state, finding_id):
        for finding in state["findings"]:
            if finding["id"] == finding_id:
                return finding
        raise ReviewError("Unknown finding ID.")

    def decide(self, state, finding_id, decision):
        if decision not in {"approved", "rejected"}:
            raise ReviewError("Choose approve or reject.")
        with self.locked():
            self.refresh(state)
            finding = self.find(state, finding_id)
            if finding["status"] == "applied":
                raise ReviewError("This patch has already been applied.")
            finding["status"] = decision
            self.save(state)

    def apply(self, state, finding_id):
        with self.locked():
            self.refresh(state)
            return self.apply_approved(state, finding_id)

    def apply_approved(self, state, finding_id):
        finding = self.find(state, finding_id)
        if finding["status"] != "approved":
            raise ReviewError("Only an explicitly approved patch can be applied.")
        root = Path(state["root"])
        target = root / finding["path"]
        if target.resolve() != target or not target.is_file():
            raise ReviewError("Patch target is missing or now points somewhere else; rescan before applying.")
        snapshot = state["files"][finding["path"]]
        original = target.read_bytes()
        if digest(original) != snapshot["sha256"]:
            raise ReviewError("The file changed since the scan or last applied patch; rescan and review again.")
        start, end = finding["start"], finding["end"]
        offset = 0
        for other in state["findings"]:
            if other["status"] != "applied" or other["path"] != finding["path"]:
                continue
            if other["end"] <= start:
                offset += len(other["replacement"]) - (other["end"] - other["start"])
            elif other["start"] < end:
                raise ReviewError("This patch overlaps an applied patch; rescan and review the remaining changes.")
        encoding = snapshot["encoding"]
        lines = source_lines(original.decode(encoding))
        candidate = "".join(lines[:start + offset] + finding["replacement"] + lines[end + offset:])
        try:
            compile(candidate, finding["path"], "exec")
            updated = candidate.encode(encoding)
        except (SyntaxError, UnicodeError):
            raise ReviewError("This patch no longer produces valid Python; rescan before applying.") from None
        if digest(target.read_bytes()) != snapshot["sha256"]:
            raise ReviewError("The file changed while applying this patch; rescan before applying.")
        atomic_write(target, updated, stat.S_IMODE(target.stat().st_mode) & 0o777)
        snapshot["sha256"] = digest(updated)
        finding["status"] = "applied"
        self.save(state)
        return target
