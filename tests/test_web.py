import http.client
import json
import re
from threading import Thread
from urllib.parse import urlencode

from patchpilot.web import make_server


def test_web_review_and_report_flow(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    target = project / "app.py"
    before = 'def render(name):\n    return f"<p>{name}</p>"\n\nratio = 9 / 0\n'
    target.write_text(before)

    with make_server(tmp_path / "web-state", 0) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]

            def request(path, fields=None, host=None, authenticated=True):
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                try:
                    headers = {"Host": host} if host else {}
                    if authenticated:
                        path = server.access_path + path
                    if fields is not None:
                        headers["Content-Type"] = "application/x-www-form-urlencoded"
                        connection.request("POST", path, urlencode(fields), headers)
                    else:
                        connection.request("GET", path, headers=headers)
                    response = connection.getresponse()
                    return response.status, response.read().decode()
                finally:
                    connection.close()

            status, landing = request("/")
            assert status == 200
            token, = set(re.findall(r'name="csrf" value="([^"]+)"', landing))
            assert f'action="{server.access_path}/scan"' in landing
            assert request("/", host="attacker.invalid")[0] == 403
            assert request("/scan", {"source": str(project)})[0] == 403
            assert request("/scan", {"source": str(project), "csrf": token})[0] == 303
            status, review = request("/")
            assert status == 200
            guest_status, guest_view = request("/", authenticated=False)
            assert guest_status == 403 and token not in guest_view and "app.py:2" not in guest_view
            assert request("/report.json", authenticated=False)[0] == 403
            assert request("/report.md", authenticated=False)[0] == 403
            assert request("/scan", {"source": str(project), "csrf": token}, authenticated=False)[0] == 403
            assert f'href="{server.access_path}/report.json"' in review
            assert "&lt;p&gt;" in review and "<p>{name}</p>" not in review
            assert "Apply approved patch" not in review
            run, = set(re.findall(r'name="run" value="([^"]+)"', review))
            first = {"csrf": token, "id": "PP-001", "run": run}
            assert request("/decision", {**first, "action": "apply"})[0] == 400
            assert request("/decision", {**first, "action": "approved", "run": "old"})[0] == 400
            assert request("/decision", {**first, "action": "approved"})[0] == 303
            assert target.read_text() == before
            assert "Apply approved patch" in request("/")[1]
            assert request("/decision", {**first, "action": "apply"})[0] == 303
            assert "_pp_html.escape" in target.read_text()
            assert request("/decision", {**first, "id": "PP-002", "action": "rejected"})[0] == 303
            assert "ratio = 9 / 0" in target.read_text()
            status, document = request("/report.json")
            assert status == 200
            assert [item["status"] for item in json.loads(document)["findings"]] == ["applied", "rejected"]
            assert "# PatchPilot review" in request("/report.md")[1]
        finally:
            server.shutdown()
            thread.join()
