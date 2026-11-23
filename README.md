# PatchPilot

**Local, approval-first Python code review.** PatchPilot inspects code, explains the evidence behind each finding, and drafts a unified diff. You decide which patches, if any, to apply. Nothing in a scanned project is imported or executed.

Built as a solo project for **GenHacks 2026** in the **AI, Agentic Systems, Cybersecurity, and Dev Tools** track. The review agent is deterministic: it parses Python ASTs, matches narrowly scoped patterns, validates candidate patches, and waits for human approval. No model API, API keys, or paid services are required.

## Setup

Install Python 3.10+ and Git (only needed for public GitHub URLs). From the cloned repository:

```sh
pip install -r requirements.txt
```

All runtime code uses the Python standard library. The pinned dependencies are for testing.

## CLI

```sh
python -m patchpilot scan examples/vulnerable-app
python -m patchpilot review
python -m patchpilot apply PP-002  # only if you approved this finding
python -m patchpilot report       # refresh exported reports after review or apply
```

Scan accepts a directory or an HTTPS URL of the form `https://github.com/OWNER/REPO`. The scan makes no edits to source files. It writes `patchpilot-report.md` and `patchpilot-report.json` to your current directory; use `--reports DIR` to choose another location. Prefer an output directory outside the code under review.

In `review`, inspect each finding and choose **a** (approve), **r** (reject), **s** (skip), or **q** (quit). Approval is recorded separately from applying. With no ID, `apply` applies all approved, non-conflicting edits. Rejected and pending patches cannot be applied. After an unrelated edit or an overlapping patch, rescan and review again. For a working local project, read the proposed change and run its tests before committing.

For a GitHub URL, PatchPilot creates a shallow local checkout and shows where it lives. Approved edits affect that checkout only; nothing is pushed. For a local path, approved edits affect the supplied directory. Each new scan replaces the current review session. State lives in `~/.patchpilot` by default; set `PATCHPILOT_HOME` to override it.

### Example

```text
$ python -m patchpilot scan examples/vulnerable-app
1 Python file(s) analyzed · 10 finding(s) · Critical: 0 · High: 5 · Medium: 5 · Low: 0
...
PP-002 High     SQL injection — app.py:15
...
```

PatchPilot shows the query, explains how the f-string lets data change the SQL, and proposes binding the input to a parameter:

```diff
--- a/app.py
+++ b/app.py
@@ -15,1 +15,1 @@
-    return connection.execute(f"SELECT name FROM users WHERE name = '{name}'").fetchall()
+    return connection.execute('SELECT name FROM users WHERE name = ?', (name,)).fetchall()
```

## Local web app

```sh
python -m patchpilot web
```

Open **http://127.0.0.1:8765**. Enter a repository URL or folder. Inspect each finding's evidence, explanation, and diff. Click **Approve** or **Reject**. Approval alone changes no code; an approved card exposes a separate **Apply approved patch** button. Use the report links to download the latest Markdown or JSON. Use `--port 9000` if needed; the server binds only to loopback and has review state separate from the CLI.

To try applying a patch in either interface without editing the checked-in fixture, copy `examples/vulnerable-app` to a scratch directory and scan the copy.

## Coverage and limits

Rules detect a subset of SQLite f-string queries, hardcoded credential assignments, pickle/eval/exec uses, shell-enabled subprocess calls, weak hashes, predictable choices, unconfined file paths, raw HTML text interpolation, empty authentication guards, and definite coding mistakes such as literal zero divisors and some undefined returns. Python is supported; JavaScript is not scanned. PatchPilot does not perform cross-file analysis or prove exploitability. It can miss issues and report false positives. Some patches deliberately fail closed pending an application-specific fix; review the explanations before approving. Paths checked by the path rule assume a trusted upload root and do not defend against concurrent local symlink swaps.

Recognized credential literals are redacted in evidence and removal lines. The displayed credential diff is therefore a review preview; PatchPilot applies the edit against the fingerprinted original. Treat reports as potentially sensitive: redaction is not a comprehensive secret scanner. Non-credential diffs use zero context; use PatchPilot to apply them, or `git apply --unidiff-zero` if applying by hand to the original unmodified source.

## Tests

```sh
python -m pytest
```

## Project structure

```text
patchpilot/
  __main__.py       CLI and interactive review
  scanner.py        AST rules and candidate diffs
  review.py         Workspaces, review decisions, guarded writes
  reports.py        Markdown and JSON exports
  web.py            Local review interface
examples/
  vulnerable-app/  Static fixture (never execute as an app)
tests/             Scanner, review, report, CLI and web checks
DEMO_SCRIPT.md     Timed video walkthrough
```

MIT licensed.
