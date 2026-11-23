"""Small loopback-only review UI with form-based, per-patch consent."""

import hmac
import secrets
from html import escape
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

from .reports import render, summary, summary_text
from .review import ReviewError, Store

STYLE = """
*{box-sizing:border-box}body{font:16px system-ui,sans-serif;background:#0d1421;color:#e6edf7;margin:0}
main{max-width:1060px;margin:auto;padding:clamp(18px,5vw,56px)}header{margin-bottom:25px}
h1{font-size:clamp(38px,8vw,66px);letter-spacing:-.07em;margin:8px 0}h2{margin:5px 0 12px}
p{line-height:1.6;margin:0 0 13px}.eyebrow,.muted,small{color:#a9b8d0}.eyebrow{letter-spacing:.16em}
.panel,article{background:#172236;border:1px solid #334061;border-radius:16px;padding:22px;margin:14px 0}
.row,.stats{display:flex;flex-wrap:wrap;gap:9px;align-items:center}.stats span,.badge{background:#202e4b;border-radius:20px;padding:6px 12px}
label{display:block;font-weight:650;margin-bottom:9px}input,button{font:inherit;border-radius:9px;padding:10px 14px}
input{flex:1;min-width:min(100%,230px);background:#0d1421;color:#fff;border:1px solid #61749b}
button{background:#202e4b;color:#e6edf7;border:1px solid #61749b;cursor:pointer;font-weight:650}
button.primary{background:#74ead0;color:#0b2321;border-color:#74ead0}a{color:#82eed5}
button:hover{filter:brightness(1.18)}:focus-visible{outline:3px solid #ffd180;outline-offset:2px}
pre{background:#0d1421;padding:14px;border-radius:9px;overflow:auto;color:#d2e2f9;font-size:.88rem}
code{overflow-wrap:anywhere}.error{border-color:#f3a69c}.badge{font-size:.8rem;text-transform:uppercase}
.critical,.high{color:#ffc2b7}.medium{color:#ffdd9f}.low{color:#b5d6ff}
"""


def page(state, token, error=""):
    token_field = f'<input type="hidden" name="csrf" value="{escape(token)}">'
    parts = [
        '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>PatchPilot · Review workspace</title><style>{STYLE}</style><main>",
        '<header><span class="eyebrow">GENHACKS 2026 · LOCAL CODE REVIEW</span><h1>PatchPilot</h1>',
        '<p class="muted">Scan Python, inspect the evidence, and decide exactly what changes.</p></header>',
        '<section class="panel"><form method="post" action="/scan">',
        token_field,
        '<label for="source">Repository URL or local folder</label><div class="row">',
        '<input required id="source" name="source" placeholder="https://github.com/owner/repo or ./examples/vulnerable-app">',
        '<button class="primary">Scan repository</button></div></form></section>',
    ]
    if error:
        parts.append(f'<p class="panel error" role="alert">{escape(error)}</p>')
    if state is not None:
        parts.extend([
            f'<section class="panel"><h2>Review results</h2><p>{escape(summary_text(state))}</p>',
            f'<p class="muted">Workspace: <code>{escape(state["root"])}</code></p>',
            '<div class="stats">',
            *(f'<span class="{level.lower()}">{level}: {count}</span>' for level, count in summary(state).items()),
            '</div><p><br><a href="/report.md">Markdown report</a> · <a href="/report.json">JSON report</a></p>',
        ])
        if state["warnings"]:
            parts.extend(["<details><summary>Scan warnings</summary><ul>",
                          *(f"<li>{escape(warning)}</li>" for warning in state["warnings"]), "</ul></details>"])
        parts.append("</section>")
        for item in state["findings"]:
            identifier, status = item["id"], item["status"]
            parts.extend([
                f'<article id="{identifier}"><div class="row"><span class="badge {item["severity"].lower()}">{item["severity"]}</span>',
                f'<span class="badge">{escape(status)}</span></div><h2>{identifier} · {escape(item["category"])}</h2>',
                f'<p><code>{escape(item["path"])}:{item["line"]}</code></p>',
                f'<pre>{escape(item["snippet"])}</pre><p>{escape(item["why"])}</p>',
                "<h3>Proposed unified diff</h3>",
            ])
            if item["redacted"]:
                parts.append("<p>The credential is redacted; PatchPilot verifies the original file before editing.</p>")
            parts.append(f'<pre>{escape(item["patch"])}</pre>')
            if status != "applied":
                parts.extend([
                    '<form method="post" action="/decision" class="row">', token_field,
                    f'<input type="hidden" name="run" value="{state["run_id"]}">',
                    f'<input type="hidden" name="id" value="{identifier}">',
                    '<button name="action" value="approved">Approve</button>',
                    '<button name="action" value="rejected">Reject</button>',
                ])
                if status == "approved":
                    parts.append('<button class="primary" name="action" value="apply">Apply approved patch</button>')
                parts.append("</form>")
            parts.append("</article>")
    parts.append("</main></html>")
    return "".join(parts)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        return

    def respond(self, status, body="", content_type="text/html; charset=utf-8", headers=()):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def trusted_host(self):
        return self.headers.get("Host") in self.server.allowed_hosts

    def current_state(self):
        try:
            return self.server.store.load()
        except ReviewError:
            return None

    def do_GET(self):
        if not self.trusted_host():
            self.respond(403, "Untrusted host.")
            return
        state = self.current_state()
        if self.path == "/":
            self.respond(200, page(state, self.server.token))
        elif self.path in {"/report.md", "/report.json"} and state is not None:
            extension = self.path.rsplit(".", 1)[1]
            mime = "application/json" if extension == "json" else "text/markdown; charset=utf-8"
            self.respond(200, render(state, extension), mime,
                         [("Content-Disposition", f'attachment; filename="patchpilot-report.{extension}"')])
        else:
            self.respond(404, "Not found.")

    def do_POST(self):
        if not self.trusted_host():
            self.respond(403, "Untrusted host.")
            return
        origin = self.headers.get("Origin")
        if origin is not None and origin != "http://" + self.headers["Host"]:
            self.respond(403, "Untrusted origin.")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 16384 or self.headers.get_content_type() != "application/x-www-form-urlencoded":
                raise ValueError
            fields = parse_qs(self.rfile.read(length).decode("utf-8"), max_num_fields=8, strict_parsing=True)
        except (ValueError, UnicodeError):
            self.respond(400, "Invalid form submission.")
            return
        token = fields.get("csrf", [""])[0]
        if not hmac.compare_digest(token.encode("utf-8"), self.server.token.encode("ascii")):
            self.respond(403, "Invalid form token.")
            return
        store = self.server.store
        state = self.current_state()
        anchor = ""
        try:
            if self.path == "/scan":
                store.scan(fields.get("source", [""])[0].strip())
            elif self.path == "/decision":
                if state is None or fields.get("run", [""])[0] != state["run_id"]:
                    raise ReviewError("This form is from a previous scan. Reload before reviewing.")
                identifier = fields.get("id", [""])[0]
                action = fields.get("action", [""])[0]
                if action == "apply":
                    store.apply(state, identifier)
                else:
                    store.decide(state, identifier, action)
                anchor = f"#{identifier}"
            else:
                self.respond(404, "Not found.")
                return
        except (ReviewError, OSError) as error:
            self.respond(400, page(state, self.server.token, str(error)))
            return
        self.respond(303, headers=[("Location", "/" + anchor)])


def make_server(home, port):
    server = HTTPServer(("127.0.0.1", port), Handler)
    bound_port = server.server_address[1]
    server.allowed_hosts = {f"127.0.0.1:{bound_port}", f"localhost:{bound_port}"}
    server.token = secrets.token_urlsafe(32)
    server.store = Store(home)
    return server


def serve(home, port):
    with make_server(home, port) as server:
        print(f"PatchPilot listening on http://127.0.0.1:{server.server_address[1]}", flush=True)
        server.serve_forever()
