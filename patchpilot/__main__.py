"""Command-line entry point; run with python -m patchpilot."""

import argparse
import re
import sys
from pathlib import Path

from .reports import render, summary_text
from .review import ReviewError, Store, atomic_write, state_home


def safe_print(message, *, file=None):
    text = re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", lambda match: ascii(match[0])[1:-1], str(message))
    print(text, file=file)


def write_reports(state, directory):
    directory.mkdir(parents=True, exist_ok=True)
    for extension in ("md", "json"):
        atomic_write(directory / f"patchpilot-report.{extension}", render(state, extension).encode("utf-8"))
    safe_print(f"Reports: {directory.resolve()}")


def review(store, state):
    for item in state["findings"]:
        if item["status"] == "applied":
            continue
        safe_print(f"\n{item['id']} · {item['severity']} · {item['category']} [{item['status']}]")
        safe_print(f"{item['path']}:{item['line']}\n{item['snippet']}\n{item['why']}\n{item['patch']}")
        if item["redacted"]:
            print("The credential is redacted; PatchPilot verifies the original file before editing.")
        while True:
            try:
                answer = input("Approve / Reject / Skip / Quit [a/r/s/q]: ").strip().lower()
            except EOFError:
                return
            if answer == "q":
                return
            if answer in {"a", "r", "s", ""}:
                if answer in {"a", "r"}:
                    store.decide(state, item["id"], "approved" if answer == "a" else "rejected")
                break
            print("Enter a, r, s, or q.")


def parser():
    cli = argparse.ArgumentParser(prog="python -m patchpilot", description="Local, approval-first Python code review.")
    commands = cli.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="scan a local folder or public GitHub repository")
    scan.add_argument("source")
    scan.add_argument("--reports", type=Path, default=Path.cwd(), help="directory for Markdown and JSON reports")
    commands.add_parser("review", help="interactively approve or reject each finding")
    apply = commands.add_parser("apply", help="apply approved patches only")
    apply.add_argument("id", nargs="?", help="apply just this approved finding (default: all approved)")
    report = commands.add_parser("report", help="export both reports with the latest review decisions")
    report.add_argument("--reports", type=Path, default=Path.cwd())
    web = commands.add_parser("web", help="serve the local review application")
    web.add_argument("--port", type=int, default=8765)
    return cli


def main(argv=None):
    args = parser().parse_args(argv)
    store = Store(state_home() / "cli")
    try:
        if args.command == "web":
            from .web import serve

            serve(state_home() / "web", args.port)
            return 0
        if args.command == "scan":
            state = store.scan(args.source)
            safe_print(summary_text(state))
            safe_print(f"Workspace: {state['root']}")
            for finding in state["findings"]:
                safe_print(f"{finding['id']} {finding['severity']:<8} {finding['category']} — {finding['path']}:{finding['line']}")
            for warning in state["warnings"]:
                safe_print(f"Warning: {warning}", file=sys.stderr)
            write_reports(state, args.reports)
            print("Next: python -m patchpilot review")
            return 0
        state = store.load()
        if args.command == "review":
            review(store, state)
        elif args.command == "report":
            write_reports(state, args.reports)
        else:
            ids = [args.id] if args.id else [item["id"] for item in state["findings"] if item["status"] == "approved"]
            if not ids:
                print("No approved patches. Run python -m patchpilot review first.")
            failures = 0
            for finding_id in ids:
                try:
                    target = store.apply(state, finding_id)
                    safe_print(f"Applied {finding_id}: {target}")
                except (ReviewError, OSError) as error:
                    safe_print(f"{finding_id}: {error}", file=sys.stderr)
                    failures += 1
            return int(bool(failures))
        return 0
    except (ReviewError, OSError, OverflowError) as error:
        safe_print(f"PatchPilot: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
