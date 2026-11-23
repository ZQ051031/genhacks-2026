"""Shared Markdown and JSON views of a review session."""

import json
import re

from .scanner import SEVERITIES

FIELDS = ("id", "path", "line", "snippet", "severity", "category", "why", "patch", "redacted", "status")


def summary(state):
    return {level: sum(item["severity"] == level for item in state["findings"]) for level in SEVERITIES}


def summary_text(state):
    levels = " · ".join(f"{level}: {count}" for level, count in summary(state).items())
    return f"{state['scanned']} Python file(s) analyzed · {len(state['findings'])} finding(s) · {levels}"


def result(state):
    return {
        "source": state["source"], "workspace": state["root"], "files_scanned": state["scanned"],
        "summary": summary(state), "warnings": state["warnings"],
        "findings": [{key: item[key] for key in FIELDS} for item in state["findings"]],
    }


def fenced(content, language=""):
    length = max((len(run) for run in re.findall(r"`+", content)), default=0) + 1
    delimiter = "`" * max(length, 3)
    content = content.removesuffix("\n")
    return f"{delimiter}{language}\n{content}\n{delimiter}\n"


def render(state, fmt):
    data = result(state)
    if fmt == "json":
        return json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    lines = ["# PatchPilot review", "", summary_text(state), "", "Workspace:", "",
             fenced(data["workspace"])]
    if data["warnings"]:
        lines.extend(["## Scan warnings", "", fenced("\n".join(data["warnings"]))])
    for item in data["findings"]:
        lines.extend([
            f"## {item['id']} · {item['severity']} · {item['category']}",
            "",
            f"Status: **{item['status']}**",
            "",
            fenced(f"{item['path']}:{item['line']}"),
            item["why"],
            "",
            fenced(item["snippet"], "python"),
        ])
        if item["redacted"]:
            lines.extend(["Credential removal lines are redacted; PatchPilot verifies the original file before editing.", ""])
        lines.append(fenced(item["patch"], "diff"))
    return "\n".join(lines) + "\n"
