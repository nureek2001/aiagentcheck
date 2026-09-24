import io
import json
import threading
import zipfile
from http.server import ThreadingHTTPServer

import httpx
import pytest

from kmg_agent.dashboard import Dashboard, assessment, export_dashboard, handler
from kmg_agent.github_sync import unpack_artifact
from kmg_agent.progress import Progress
from kmg_agent.redaction import Redactor


@pytest.fixture
def server(tmp_path):
    app = Dashboard(tmp_path / "reports")
    http = ThreadingHTTPServer(("127.0.0.1", 0), handler(app))
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    with httpx.Client(base_url=f"http://127.0.0.1:{http.server_port}", trust_env=False) as client:
        yield app, client
    http.shutdown()
    http.server_close()
    thread.join(timeout=3)


def test_dashboard_is_read_only_by_default(server):
    app, client = server
    response = client.get("/")
    assert response.status_code == 200
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    state = client.get("/api/state").json()
    assert state["runs"] == [] and not state["can_propose"]
    assert app.process is None


def test_cross_origin_request_and_dns_rebinding_cannot_start_paid_request(server):
    app, client = server
    assert client.get("/api/state", headers={"Host": "attacker.test"}).status_code == 403
    assert client.post("/api/propose", json={}).status_code == 403
    assert (
        client.post(
            "/api/propose", headers={"Origin": "https://attacker.test", "X-CSRF-Token": app.csrf}, json={}
        ).status_code
        == 403
    )
    assert app.process is None


def test_paid_proposal_needs_explicit_confirmation(server):
    app, client = server
    response = client.post(
        "/api/propose",
        headers={"Origin": str(client.base_url).rstrip("/"), "X-CSRF-Token": app.csrf},
        json={"run": "x"},
    )
    assert response.status_code == 400
    assert app.process is None


def test_downloads_cannot_read_secrets_or_traverse(server, tmp_path):
    app, client = server
    (tmp_path / ".env").write_text("SECRET")
    run = app.reports / "run"
    run.mkdir()
    (run / "execution.log").write_text("safe")
    assert client.get("/download", params={"run": "run", "file": "execution.log"}).text == "safe"
    for run_id, filename in [("..", ".env"), ("run", "../../.env"), ("../run", "execution.log")]:
        assert client.get("/download", params={"run": run_id, "file": filename}).status_code == 404


def test_timeout_diagnostics_override_stale_running_progress(tmp_path):
    (tmp_path / "progress.json").write_text(json.dumps({"status": "running", "stage": "map"}))
    (tmp_path / "error.json").write_text(json.dumps({"exit_code": 2, "message": "deadline"}))
    result = assessment(tmp_path)
    assert result["progress"]["status"] == "completed"
    assert result["progress"]["stage"] == "error"


def test_progress_exposes_actual_counts_not_reasoning(tmp_path):
    progress = Progress(tmp_path, Redactor(["secret-value"]))
    progress.emit("Context 2/5")
    value = json.loads((tmp_path / "progress.json").read_text())
    assert value["completed"] == 2 and value["total"] == 5
    progress.emit("Verify ИБ-08")
    assert json.loads((tmp_path / "progress.json").read_text(encoding="utf-8"))["stage"] == "verify"


def test_export_cannot_break_out_of_embedded_json(tmp_path):
    payload = '</script><script>alert("source")</script>'
    (tmp_path / "error.json").write_text(json.dumps({"message": payload, "exit_code": 2}))
    export_dashboard(tmp_path)
    html = (tmp_path / "dashboard.html").read_text(encoding="utf-8")
    assert payload not in html
    assert "\\u003c/script>" in html
    assert '<script src="/app.js"' not in html


def test_artifact_import_rejects_zip_slip_and_does_not_import_html(tmp_path):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        archive.writestr("../escape.txt", "BAD")
        archive.writestr("dashboard.html", "<script>evil()</script>")
        archive.writestr("error.json", '{"exit_code":2}')
    output = tmp_path / "import"
    unpack_artifact(data.getvalue(), output, Redactor())
    assert not (tmp_path / "escape.txt").exists()
    assert not (output / "dashboard.html").exists()
    assert (output / "error.json").exists()


def test_invalid_report_artifact_is_rejected_before_writes(tmp_path):
    import jsonschema

    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        archive.writestr("report.json", '{"result":"pass"}')
    with pytest.raises(jsonschema.ValidationError):
        unpack_artifact(data.getvalue(), tmp_path / "import", Redactor())
    assert not (tmp_path / "import").exists()


def test_budget_updates_need_csrf_and_validate_bounds(server):
    app, client = server
    assert client.post('/api/budget', json={'max_tokens': 1000, 'max_requests': 1}).status_code == 403
    headers = {'Origin': str(client.base_url).rstrip('/'), 'X-CSRF-Token': app.csrf}
    assert client.post('/api/budget', headers=headers, json={'max_tokens': True, 'max_requests': 1}).status_code == 400
    assert client.post('/api/budget', headers=headers, json={'max_tokens': 500000, 'max_requests': 20}).status_code == 200
    assert app.budget_settings == {'max_tokens': 500000, 'max_requests': 20}
    assert app.process is None


def test_scan_and_publication_require_distinct_explicit_confirmation(server):
    app, client = server
    headers = {'Origin': str(client.base_url).rstrip('/'), 'X-CSRF-Token': app.csrf}
    assert client.post('/api/scan', headers=headers, json={}).status_code == 400
    assert client.post('/api/publish', headers=headers, json={'confirm_paid_request': True}).status_code == 400
    assert app.process is None
