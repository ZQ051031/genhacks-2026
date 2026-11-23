"""Inspect Python source without executing it and propose localized repairs."""

import ast
import builtins
import hashlib
import io
import os
import re
import symtable
import tokenize
from dataclasses import dataclass
from pathlib import Path

SEVERITIES = ("Critical", "High", "Medium", "Low")
SKIP_DIRS = {"__pycache__", "node_modules", "venv", "vendor", "site-packages"}
SECRET_NAME = re.compile(r"(?:^|_)(?:password|passwd|api_key|secret|token|credential)s?(?:_|$)", re.I)
SQL_SELECT = re.compile(r"SELECT [\w*,. ]+ FROM \w+ WHERE \w+\s*=\s*", re.I)


@dataclass(frozen=True)
class Repair:
    node: ast.AST
    severity: str
    category: str
    reason: str
    replacement: str
    setup: tuple[str, ...] = ()
    also_replace: tuple[tuple[ast.AST, str], ...] = ()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def imported_names(tree):
    names = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for item in node.names:
                names[item.asname or item.name.split(".")[0]] = item.name if item.asname else item.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            for item in node.names:
                names[item.asname or item.name] = f"{node.module}.{item.name}"
    return names


def qualified(node, names):
    if isinstance(node, ast.Name):
        return names.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        return f"{qualified(node.value, names)}.{node.attr}"
    return ""


def string_assignment(node):
    if isinstance(node, ast.Assign) and len(node.targets) == 1:
        target = node.targets[0]
    elif isinstance(node, ast.AnnAssign):
        target = node.target
    else:
        return None
    if isinstance(target, ast.Name) and SECRET_NAME.search(target.id):
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, (str, bytes)) and node.value.value:
            return target.id, node.value
    return None


def credential_repairs(statements):
    assignments = sorted(filter(None, map(string_assignment, statements)),
                         key=lambda item: (item[1].lineno, item[1].col_offset))
    groups = []
    for name, node in assignments:
        change = (node, f"_pp_os.environ[{name.upper()!r}]")
        if groups and node.lineno <= groups[-1][-1][0].end_lineno:
            groups[-1].append(change)
        else:
            groups.append([change])
    for (node, value), *other in groups:
        yield Repair(node, "High", "Hardcoded credential",
                     "Credential literals can leak through source control. Rotate real credentials and read replacements from the environment.",
                     value, ("import os as _pp_os",), tuple(other))


def sql_repair(node, names, connections, cursors):
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "execute" or len(node.args) != 1 or node.keywords:
        return None
    receiver = node.func.value
    if qualified(receiver, names) not in connections | cursors:
        return None
    query = node.args[0]
    if not isinstance(query, ast.JoinedStr) or len(query.values) not in (2, 3):
        return None
    prefix, param, *suffix = query.values
    if not isinstance(prefix, ast.Constant) or not isinstance(param, ast.FormattedValue):
        return None
    if param.conversion != -1 or param.format_spec:
        return None
    after = suffix[0].value if suffix and isinstance(suffix[0], ast.Constant) else ""
    before = prefix.value
    quoted = before.endswith("'") and after.startswith("'")
    if quoted:
        before, after = before[:-1], after[1:]
    if not SQL_SELECT.fullmatch(before) or not re.fullmatch(r"\s*;?\s*", after):
        return None
    value = ast.unparse(param.value)
    if quoted:
        value = f"format({value})"
    return Repair(query, "High", "SQL injection",
                  "Formatting data directly into a SQLite query lets data change the SQL. Bind the value as a parameter.",
                  f"{before + '?' + after!r}, ({value},)")


def repaired_calls(node, names, connections, cursors):
    call = qualified(node.func, names)
    sql = sql_repair(node, names, connections, cursors)
    if sql:
        yield sql
    if call in {"pickle.loads", "eval"} and len(node.args) == 1 and not node.keywords:
        yield Repair(node, "High", "Unsafe deserialization",
                     "This interprets its input as executable instructions. Parse JSON data instead and check the input format at the caller.",
                     f"_pp_json.loads({ast.unparse(node.args[0])})", ("import json as _pp_json",))
    if call in {"exec", "pickle.load"} and len(node.args) == 1 and not node.keywords:
        if call == "pickle.load":
            yield Repair(node, "High", "Unsafe deserialization",
                         "Loading a pickle may run code. Switch the input producer and consumer to JSON.",
                         f"_pp_json.load({ast.unparse(node.args[0])})", ("import json as _pp_json",))
        else:
            yield Repair(node, "High", "Unsafe code execution",
                         "Executing dynamic Python code is unsafe. Fail closed until a fixed set of allowed operations is implemented.",
                         "raise ValueError('Dynamic execution is disabled')")
    if call.startswith("subprocess.") and call.rsplit(".", 1)[1] in {"run", "Popen", "call", "check_call", "check_output"}:
        for option in node.keywords:
            if option.arg == "shell" and isinstance(option.value, ast.Constant) and option.value.value is True:
                if node.args and isinstance(node.args[0], (ast.List, ast.Tuple)):
                    yield Repair(option.value, "High", "Command injection",
                                 "Running an argument list through a shell introduces shell interpretation. Pass the argument list directly.", "False")
                elif node.args:
                    yield Repair(node, "High", "Command injection",
                                 "A shell command string can interpret data as shell instructions. Disable it pending a fixed executable and validated arguments.",
                                 "raise ValueError('Shell command disabled; use validated arguments')")
    if call in {"hashlib.md5", "hashlib.sha1"}:
        yield Repair(node.func, "Medium", "Weak cryptography",
                     "This digest is collision-prone. Use SHA-256 for integrity and review stored digest compatibility.",
                     "_pp_hashlib.sha256", ("import hashlib as _pp_hashlib",))
    if call == "random.choice" and len(node.args) == 1 and not node.keywords:
        yield Repair(node.func, "Medium", "Insecure randomness",
                     "This generator is predictable and unsuitable for security-sensitive choices.",
                     "_pp_secrets.choice", ("import secrets as _pp_secrets",))


def all_identifiers(table):
    identifiers = set(table.get_identifiers())
    for child in table.get_children():
        identifiers.update(all_identifiers(child))
    return identifiers


def fresh_root_names(taken):
    sequence = 1
    while True:
        root = "_pp_root" if sequence == 1 else f"_pp_root_{sequence}"
        path_type = f"{root}_Path"
        if root not in taken and path_type not in taken:
            taken.update((root, path_type))
            return root, path_type
        sequence += 1


def repairs(tree, source, filename):
    names = imported_names(tree)
    statements = list(ast.walk(tree))
    calls = [node for node in statements if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)]
    connections = {target.id for node in calls if qualified(node.value.func, names) == "sqlite3.connect"
                   for target in node.targets if isinstance(target, ast.Name)}
    cursors = {target.id for node in calls if isinstance(node.value.func, ast.Attribute)
               and node.value.func.attr == "cursor" and qualified(node.value.func.value, names) in connections
               for target in node.targets if isinstance(target, ast.Name)}
    symbols = symtable.symtable(source, filename, "exec")
    identifiers = all_identifiers(symbols)
    module_names = {symbol.get_name() for symbol in symbols.get_symbols()
                    if symbol.is_assigned() or symbol.is_imported() or symbol.is_namespace()}
    yield from credential_repairs(statements)
    for node in statements:
        if isinstance(node, ast.Call):
            yield from repaired_calls(node, names, connections, cursors)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)):
            if isinstance(node.right, ast.Constant) and type(node.right.value) in (int, float) and node.right.value == 0:
                yield Repair(node, "Medium", "Division by zero",
                             "The divisor is always zero. Make the operation fail with an explicit diagnostic until the intended divisor is supplied.",
                             "raise ValueError('A nonzero divisor is required')")
        elif isinstance(node, ast.ExceptHandler) and node.type is None:
            yield Repair(node, "Medium", "Overbroad exception handler",
                         "A bare except also swallows system-exit and interrupt signals. Catch ordinary exceptions instead.",
                         "except Exception")
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in {"require_auth", "require_authentication"}:
            body = node.body[1:] if ast.get_docstring(node, clean=False) is not None else node.body
            if len(body) == 1 and isinstance(body[0], ast.Pass):
                yield Repair(body[0], "High", "Missing authentication",
                             "This authentication guard does nothing. Deny access until a real identity check is implemented.",
                             "raise PermissionError('Authentication is not configured')")
    for fn in tree.body:
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        table = next(table for table in symbols.get_children()
                     if table.get_name() == fn.name and table.get_lineno() == fn.lineno)
        for stmt in fn.body:
            if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Name):
                node = stmt.value
                if table.lookup(node.id).is_global() and node.id not in module_names and not hasattr(builtins, node.id):
                    yield Repair(node, "Medium", "Undefined variable",
                                 "The returned name has no definition. Raise an explicit error until the correct value is wired in.",
                                 f"raise NameError('Define {node.id} before returning it')")
    for node in statements:
        if isinstance(node, ast.Return) and isinstance(node.value, ast.JoinedStr):
            for value in node.value.values:
                if not isinstance(value, ast.FormattedValue) or value.conversion != -1 or value.format_spec:
                    continue
                index = node.value.values.index(value)
                prior = node.value.values[index - 1] if index else None
                following = node.value.values[index + 1] if index + 1 < len(node.value.values) else None
                if (isinstance(prior, ast.Constant) and isinstance(following, ast.Constant)
                        and re.fullmatch(r"<(p|div|span|h[1-6])>", prior.value)
                        and following.value == f"</{prior.value[1:]}"):
                    expr = value.value
                    escaped = f"_pp_html.escape(str({ast.unparse(expr)}))"
                    if isinstance(expr, ast.Tuple) and expr.elts:
                        first = expr.elts[0]
                        segment = ast.get_source_segment(source, expr)
                        if (segment.startswith("{") and segment.endswith("}")
                                and (expr.lineno, expr.col_offset) < (first.lineno, first.col_offset)):
                            escaped = "{" + escaped + "}"
                    yield Repair(expr, "Medium", "Unescaped HTML output",
                                 "The value is placed directly into HTML. Escape it before returning the markup.",
                                 escaped, ("import html as _pp_html",))
        if isinstance(node, ast.Call) and qualified(node.func, names) == "open" and node.args:
            path = node.args[0]
            if (isinstance(path, ast.Call) and qualified(path.func, names) == "os.path.join"
                    and len(path.args) == 2 and not path.keywords
                    and isinstance(path.args[0], ast.Constant) and isinstance(path.args[0].value, str)
                    and isinstance(path.args[1], ast.Name)):
                base, name = map(ast.unparse, path.args)
                root, path_type = fresh_root_names(identifiers)
                yield Repair(path, "High", "Path traversal",
                             "An unrestricted file name can escape the intended root. Anchor resolution to the configured directory.",
                             f"{root} / ({root} / {name}).resolve().relative_to({root})",
                             (f"from pathlib import Path as {path_type}", f"{root} = {path_type}({base}).resolve()"))


def source_lines(source):
    return list(io.StringIO(source, newline=""))


def scan_source(source, path, encoding="utf-8"):
    tree = ast.parse(source, filename=path)
    statements = [node for node in ast.walk(tree) if isinstance(node, ast.stmt)]
    lines = source_lines(source)
    redacted = set()
    for node in statements:
        secret = string_assignment(node)
        if secret:
            value = secret[1]
            redacted.update(range(value.lineno, value.end_lineno + 1))
    results = []
    for repair in repairs(tree, source, path):
        node = repair.node
        start, end = node.lineno - 1, node.end_lineno
        if repair.also_replace:
            end = repair.also_replace[-1][0].end_lineno
        old = lines[start:end]
        newline = "\r\n" if old[0].endswith("\r\n") else "\n"
        indent = old[0][:len(old[0]) - len(old[0].lstrip())]
        replacement = repair.replacement
        if isinstance(node, ast.ExceptHandler):
            end = start + 1
            old = lines[start:end]
            new = [re.sub(r"\bexcept\s*:", "except Exception:", old[0], count=1)]
        elif replacement.startswith("raise "):
            stmt = min((stmt for stmt in statements if (
                stmt.lineno <= node.lineno and stmt.end_lineno >= node.end_lineno)),
                key=lambda stmt: (stmt.end_lineno - stmt.lineno, -stmt.col_offset), default=None)
            if stmt is not node and getattr(stmt, "value", None) is not node:
                continue
            start, end = stmt.lineno - 1, stmt.end_lineno
            old = lines[start:end]
            indent = old[0][:len(old[0]) - len(old[0].lstrip())]
            if len(indent.encode()) != stmt.col_offset or old[-1].encode()[stmt.end_col_offset:].strip().startswith(b";"):
                continue
            new = [indent + replacement + (newline if old[-1].endswith("\n") else "")]
        else:
            original_bytes = [line.encode() for line in old]
            edits = ((node, replacement), *repair.also_replace)
            updated = b"".join(original_bytes)
            for expression, text in reversed(edits):
                before = sum(map(len, original_bytes[:expression.lineno - 1 - start])) + expression.col_offset
                after = sum(map(len, original_bytes[:expression.end_lineno - 1 - start])) + expression.end_col_offset
                updated = updated[:before] + text.encode() + updated[after:]
            if repair.setup:
                if not any(
                    stmt.lineno == node.lineno and stmt.col_offset == len(indent.encode()) for stmt in statements
                ):
                    continue
                inserted = [indent + line + newline for line in repair.setup]
            else:
                inserted = []
            new = inserted + source_lines(updated.decode())
        if old == new or (repair.category != "Hardcoded credential" and any(i in redacted for i in range(start + 1, end + 1))):
            continue
        candidate = "".join(lines[:start] + new + lines[end:])
        try:
            compile(candidate, path, "exec")
            candidate.encode(encoding)
        except (SyntaxError, UnicodeError):
            continue
        display = ["[REDACTED CREDENTIAL]" + ("\n" if line.endswith("\n") else "")
                   if index in redacted else line for index, line in enumerate(old, start + 1)]
        header = f"--- a/{path}\n+++ b/{path}\n@@ -{start + 1},{len(old)} +{start + 1},{len(new)} @@\n"
        changes = ["-" + line for line in display] + ["+" + line for line in new]
        patch = header + "".join(line if line.endswith("\n") else line + "\n\\ No newline at end of file\n" for line in changes)
        results.append({
            "path": path, "line": node.lineno, "snippet": "".join(display).rstrip("\r\n"),
            "severity": repair.severity, "category": repair.category, "why": repair.reason,
            "patch": patch, "redacted": repair.category == "Hardcoded credential",
            "status": "pending", "start": start, "end": end, "replacement": new,
        })
    return results


def scan_tree(root: Path):
    findings, warnings, files = [], [], {}
    scanned = 0
    for directory, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(name for name in dirs if not name.startswith(".") and name not in SKIP_DIRS
                         and not (Path(directory) / name).is_symlink())
        for name in sorted(names):
            path = Path(directory) / name
            if path.suffix != ".py" or path.is_symlink() or not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            if any(ord(char) < 32 or ord(char) == 127 for char in relative):
                warnings.append("Skipped a path containing control characters.")
                continue
            try:
                with path.open("rb") as stream:
                    raw = stream.read(1_000_001)
                if len(raw) > 1_000_000:
                    warnings.append(f"{relative}: exceeds the 1 MB analysis limit")
                    continue
                encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
                found = scan_source(raw.decode(encoding), relative, encoding)
            except (OSError, UnicodeError, SyntaxError, LookupError, RecursionError) as exc:
                warnings.append(f"{relative}: skipped ({type(exc).__name__})")
                continue
            scanned += 1
            if found:
                files[relative] = {"sha256": digest(raw), "encoding": encoding}
                findings.extend(found)
    findings.sort(key=lambda item: (SEVERITIES.index(item["severity"]), item["path"], item["line"], item["category"]))
    for number, finding in enumerate(findings, 1):
        finding["id"] = f"PP-{number:03d}"
    return findings, files, warnings, scanned
