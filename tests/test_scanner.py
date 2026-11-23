import json
import shutil
import subprocess
from textwrap import dedent

import pytest

from patchpilot.review import Store
from patchpilot.scanner import scan_source, scan_tree


@pytest.mark.parametrize(
    ("source", "category", "repair"),
    [
        (dedent("""
            import sqlite3 as db
            cx = db.connect(":memory:")
            def users(name):
                return cx.execute(f"SELECT name FROM users WHERE name = '{name}'")
        """), "SQL injection", "(name,)"),
        ("API_KEY = 'FAKE_TEST_VALUE'", "Hardcoded credential", "environ['API_KEY']"),
        ("from pickle import loads as decode\nvalue = decode(payload)", "Unsafe deserialization", "_pp_json.loads(payload)"),
        ("result = eval(payload)", "Unsafe deserialization", "_pp_json.loads(payload)"),
        ("exec(payload)", "Unsafe code execution", "raise ValueError"),
        ("import subprocess as sp\nsp.run(['example'], shell=True)", "Command injection", "shell=False"),
        ("import hashlib as h\nvalue = h.sha1(data)", "Weak cryptography", "sha256"),
        ("import random\nvalue = random.choice(alphabet)", "Insecure randomness", "_pp_secrets.choice"),
        ("import os\ndef load(name):\n    return open(os.path.join('uploads', name))", "Path traversal", "relative_to(_pp_root)"),
        ("def profile(name):\n    return f'<p>{name}</p>'", "Unescaped HTML output", "_pp_html.escape(str(name))"),
        ("def require_auth():\n    pass", "Missing authentication", "raise PermissionError"),
        ("def ratio(total):\n    return total / 0", "Division by zero", "raise ValueError"),
        ("def read():\n    return missing_value", "Undefined variable", "raise NameError"),
        ("try:\n    read()\nexcept:\n    pass", "Overbroad exception handler", "except Exception:"),
    ],
)
def test_ast_rule(source, category, repair):
    matches = scan_source(source, "sample.py")
    assert len(matches) == 1
    match = matches[0]
    assert match["category"] == category
    assert match["line"] > 0 and match["snippet"] and match["why"]
    assert repair in match["patch"]


def test_ignores_safe_constructs_and_prose():
    assert not scan_source(dedent("""
        import hashlib
        import sqlite3
        def safe(name):
            cx = sqlite3.connect(":memory:")
            cx.execute("SELECT name FROM users WHERE name = ?", (name,))
            print("eval(payload) and random.choice(alphabet)")
            return name
        result = hashlib.sha256(b"data")
    """), "safe.py")


@pytest.mark.skipif(shutil.which("git") is None, reason="Git is needed to validate the diff externally")
def test_diffs_are_applicable_and_handle_missing_final_newline(tmp_path):
    source = tmp_path / "target.py"
    source.write_bytes(b"import hashlib\nvalue = hashlib.md5(b'data')")
    finding = scan_source(source.read_text(), source.name)[0]
    subprocess.run(["git", "apply", "--unidiff-zero", "-"], input=finding["patch"],
                   text=True, cwd=tmp_path, check=True, capture_output=True)
    assert source.read_bytes() == b"import hashlib\nimport hashlib as _pp_hashlib\nvalue = _pp_hashlib.sha256(b'data')"


def test_scan_records_parse_errors_and_skips_symlinks(tmp_path):
    (tmp_path / "good.py").write_text("total = 5 / 0\n")
    (tmp_path / "bad.py").write_text("def malformed\n")
    (tmp_path / "link.py").symlink_to(tmp_path / "good.py")
    findings, snapshots, warnings, scanned = scan_tree(tmp_path)
    assert scanned == 1
    assert [item["path"] for item in findings] == ["good.py"]
    assert list(snapshots) == ["good.py"]
    assert warnings == ["bad.py: skipped (SyntaxError)"]


def test_credential_redaction_and_application(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text("API_KEY = 'FAKE_TEST_PRIVATE_VALUE'\n")
    store = Store(tmp_path / ".state")
    state = store.scan(str(tmp_path))
    item, = state["findings"]
    assert "FAKE_TEST_PRIVATE_VALUE" not in json.dumps(state)
    assert "[REDACTED CREDENTIAL]" in item["snippet"] and item["redacted"]
    store.decide(state, item["id"], "approved")
    store.apply(state, item["id"])
    assert "FAKE_TEST_PRIVATE_VALUE" not in source.read_text()
    assert "_pp_os.environ['API_KEY']" in source.read_text()


def test_credentials_that_share_a_line_are_repaired_and_redacted_together(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text("API_KEY = 'FAKE_TEST_FIRST'; API_TOKEN = 'FAKE_TEST_SECOND'\n")
    store = Store(tmp_path / ".state")
    state = store.scan(str(tmp_path))
    item, = state["findings"]
    assert "FAKE_TEST_" not in json.dumps(state)
    assert "[REDACTED CREDENTIAL]" in item["patch"]
    store.decide(state, item["id"], "approved")
    store.apply(state, item["id"])
    assert "FAKE_TEST_" not in source.read_text()
    assert "API_KEY = _pp_os.environ['API_KEY']; API_TOKEN = _pp_os.environ['API_TOKEN']" in source.read_text()
