import json
import subprocess
import sys
from pathlib import Path

import pytest

from patchpilot.reports import render
from patchpilot.review import ReviewError, Store


@pytest.fixture
def review_case(tmp_path):
    path = tmp_path / "sample.py"
    path.write_text("import hashlib\nfingerprint = hashlib.md5(b'data')\nratio = 12 / 0\n")
    store = Store(tmp_path / ".state")
    return path, store, store.scan(str(tmp_path))


def test_pending_and_rejected_patches_cannot_apply(review_case):
    path, store, state = review_case
    before = path.read_bytes()
    item = state["findings"][0]
    with pytest.raises(ReviewError, match="explicitly approved"):
        store.apply(state, item["id"])
    store.decide(state, item["id"], "rejected")
    with pytest.raises(ReviewError, match="explicitly approved"):
        store.apply(state, item["id"])
    assert path.read_bytes() == before


def test_stale_review_snapshot_cannot_apply_a_revoked_approval(review_case):
    path, store, state = review_case
    before = path.read_bytes()
    identifier = state["findings"][0]["id"]
    store.decide(state, identifier, "approved")
    store.decide(store.load(), identifier, "rejected")
    with pytest.raises(ReviewError, match="explicitly approved"):
        store.apply(state, identifier)
    assert path.read_bytes() == before


def test_approval_is_not_application_and_offsets_are_adjusted(review_case):
    path, store, state = review_case
    before = path.read_bytes()
    for item in state["findings"]:
        store.decide(state, item["id"], "approved")
    assert path.read_bytes() == before
    for item in state["findings"]:
        store.apply(store.load(), item["id"])
    assert "_pp_hashlib.sha256" in path.read_text()
    assert "raise ValueError" in path.read_text()
    assert [item["status"] for item in store.load()["findings"]] == ["applied", "applied"]


def test_external_changes_invalidate_approval(review_case):
    path, store, state = review_case
    item = state["findings"][0]
    store.decide(state, item["id"], "approved")
    changed = path.read_text() + "# external edit\n"
    path.write_text(changed)
    with pytest.raises(ReviewError, match="file changed"):
        store.apply(state, item["id"])
    assert path.read_text() == changed


def test_overlapping_approved_edits_require_rescan(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text("import hashlib, random\nvalue = hashlib.md5(random.choice(chars))\n")
    store = Store(tmp_path / ".state")
    state = store.scan(str(tmp_path))
    first, second = state["findings"]
    for item in (first, second):
        store.decide(state, item["id"], "approved")
    store.apply(state, first["id"])
    with pytest.raises(ReviewError, match="overlaps"):
        store.apply(state, second["id"])


def test_reports_have_evidence_patches_and_decisions(review_case):
    _, store, state = review_case
    item = state["findings"][0]
    store.decide(state, item["id"], "approved")
    document = json.loads(render(state, "json"))
    assert document["summary"] == {"Critical": 0, "High": 0, "Medium": 2, "Low": 0}
    finding = document["findings"][0]
    assert finding["status"] == "approved" and finding["path"] == "sample.py"
    assert "hashlib.md5" in finding["snippet"] and "+++ b/sample.py" in finding["patch"]
    assert "replacement" not in finding
    markdown = render(state, "md")
    assert "Status: **approved**" in markdown and "```diff" in markdown
    assert "sample.py:2" in markdown and "collision-prone" in markdown


def test_public_github_source_clones_to_workspace(tmp_path, monkeypatch):
    store = Store(tmp_path / "state")

    def clone(arguments, **options):
        assert arguments[:3] == ["git", "-c", "core.hooksPath=/dev/null"]
        assert arguments[-2] == "https://github.com/example/project"
        assert options["env"]["GIT_TERMINAL_PROMPT"] == "0"
        assert options["check"] is True
        root = Path(arguments[-1])
        root.mkdir()
        (root / "code.py").write_text("ratio = 1 / 0\n")

    monkeypatch.setattr(subprocess, "run", clone)
    state = store.scan("https://github.com/example/project")
    assert Path(state["root"]).parent == tmp_path / "state" / "clones"
    assert state["findings"][0]["category"] == "Division by zero"
    with pytest.raises(ReviewError, match="public https"):
        store.scan("https://example.com/project")


def test_cli_persists_review_and_writes_reports(tmp_path, monkeypatch):
    source = tmp_path / "project"
    source.mkdir()
    file = source / "sample.py"
    file.write_text("import hashlib\nfingerprint = hashlib.md5(b'data')\nratio = 5 / 0\n")
    monkeypatch.setenv("PATCHPILOT_HOME", str(tmp_path / "state"))
    reports = tmp_path / "reports"

    def cli(*args, input=None):
        return subprocess.run([sys.executable, "-m", "patchpilot", *args], input=input,
                              text=True, capture_output=True)

    assert cli("scan", str(source), "--reports", str(reports)).returncode == 0
    assert cli("apply", "PP-001").returncode == 1
    assert cli("review", input="a\nr\n").returncode == 0
    assert "hashlib.md5" in file.read_text()
    assert cli("apply").returncode == 0
    assert "_pp_hashlib.sha256" in file.read_text() and "5 / 0" in file.read_text()
    assert cli("report", "--reports", str(reports)).returncode == 0
    exported = json.loads((reports / "patchpilot-report.json").read_text())
    assert [item["status"] for item in exported["findings"]] == ["applied", "rejected"]
    assert (reports / "patchpilot-report.md").exists()
