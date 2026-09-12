import json
import sys
import threading
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import api
from database.database import initialize_database, get_connection


@pytest.fixture(scope="module")
def api_server():
    initialize_database()
    # Bind to ephemeral free port
    server = ThreadingHTTPServer(("127.0.0.1", 0), api.SentinelXIngestionHandler)
    port = server.server_address[1]
    base_url = f"http://127.0.0.1:{port}"

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield base_url

    server.shutdown()
    server.server_close()


def test_health_check(api_server):
    req = urllib.request.Request(f"{api_server}/health", method="GET")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert data.get("status") == "ok"
        assert "SentinelX" in data.get("service", "")


def test_unknown_routes(api_server):
    # GET unknown
    req = urllib.request.Request(f"{api_server}/unknown_endpoint", method="GET")
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req)
    assert exc_info.value.code == 404

    # POST unknown
    req2 = urllib.request.Request(f"{api_server}/unknown_endpoint", data=b"{}", method="POST")
    with pytest.raises(urllib.error.HTTPError) as exc_info2:
        urllib.request.urlopen(req2)
    assert exc_info2.value.code == 404


def test_events_unconfigured_token(api_server, monkeypatch):
    monkeypatch.setattr(api, "INGEST_TOKEN", "")
    req = urllib.request.Request(
        f"{api_server}/events",
        data=b'{"event_type": "LOGIN", "source_ip": "10.0.0.1", "status": "FAILED"}',
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req)
    assert exc_info.value.code == 503


def test_events_unauthorized(api_server, monkeypatch):
    monkeypatch.setattr(api, "INGEST_TOKEN", "secret-test-token")

    # Missing Authorization header
    req = urllib.request.Request(
        f"{api_server}/events",
        data=b'{"event_type": "LOGIN", "source_ip": "10.0.0.1", "status": "FAILED"}',
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req)
    assert exc_info.value.code == 401

    # Wrong token
    req_wrong = urllib.request.Request(
        f"{api_server}/events",
        data=b'{"event_type": "LOGIN", "source_ip": "10.0.0.1", "status": "FAILED"}',
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer wrong-token"
        },
        method="POST"
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info2:
        urllib.request.urlopen(req_wrong)
    assert exc_info2.value.code == 401


def test_events_validation_errors(api_server, monkeypatch):
    monkeypatch.setattr(api, "INGEST_TOKEN", "valid-token")
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer valid-token"
    }

    # Invalid JSON
    req = urllib.request.Request(f"{api_server}/events", data=b"not json", headers=headers, method="POST")
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req)
    assert exc.value.code == 400

    # Missing required field
    bad_payload = json.dumps({"source_ip": "192.168.1.1"}).encode("utf-8")
    req = urllib.request.Request(f"{api_server}/events", data=bad_payload, headers=headers, method="POST")
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req)
    assert exc.value.code == 400

    # Invalid IPv4
    bad_ip = json.dumps({
        "event_type": "LOGIN",
        "source_ip": "999.999.999.999",
        "status": "FAILED"
    }).encode("utf-8")
    req = urllib.request.Request(f"{api_server}/events", data=bad_ip, headers=headers, method="POST")
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req)
    assert exc.value.code == 400

    # Invalid Port (>65535)
    bad_port = json.dumps({
        "event_type": "LOGIN",
        "source_ip": "10.0.0.1",
        "status": "FAILED",
        "port": 70000
    }).encode("utf-8")
    req = urllib.request.Request(f"{api_server}/events", data=bad_port, headers=headers, method="POST")
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req)
    assert exc.value.code == 400


def test_events_successful_ingestion_and_sanitization(api_server, monkeypatch):
    monkeypatch.setattr(api, "INGEST_TOKEN", "valid-token")
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer valid-token"
    }

    # Ingest event with None / missing timestamp
    payload = {
        "event_type": "LOGIN",
        "source_ip": "10.42.42.42",
        "username": "api_test_user",
        "status": "FAILED",
        "port": 22,
        "message": "Automated ingestion test",
        "timestamp": None
    }
    req = urllib.request.Request(
        f"{api_server}/events",
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST"
    )

    with urllib.request.urlopen(req) as resp:
        assert resp.status == 201
        data = json.loads(resp.read().decode("utf-8"))
        assert data.get("success") is True
        event_id = data.get("event_id")
        assert event_id is not None

    # Verify event stored in database with non-empty, valid timestamp
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, source_ip FROM security_events WHERE id = ?", (event_id,))
        row = cursor.fetchone()
        assert row is not None
        assert row[0] != "None"
        assert row[0] != ""
        assert len(row[0]) > 5
        assert row[1] == "10.42.42.42"
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(pytest.main(["-v", __file__]))

