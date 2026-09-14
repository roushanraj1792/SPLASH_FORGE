"""
Phase 1 Integration Test — Authorized Laboratory Telemetry Pipeline
===================================================================
Validates the end-to-end laboratory telemetry bridge:
  Kali Generator -> Web-01 Service -> SentinelX Ingest (api.py) ->
  Detection Engine -> Incident Creation -> Telegram Alert Formatting

Verification Scope:
  1. Kali Generator strict target validation (192.168.56.30:8080 ONLY).
  2. Web-01 strict bind enforcement (no fallback to 0.0.0.0).
  3. Web-01 REST response behavior & access metrics.
  4. SentinelX ingestion persistence in SQLite security_events.
  5. Detection engine (brute_force.py) triggering on real telemetry.
  6. Incident creation and evidence linking.
  7. Telegram alert payload formatting.
"""

import json
import sys
import threading
import time
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import api
from database.database import (
    initialize_database,
    get_connection,
    get_recent_events,
    create_incident,
    link_events_to_incident,
    get_incident_events
)
from detection.brute_force import detect_brute_force
from services.risk_engine import enrich_alert_with_risk
from services.telegram_alert import send_incident_alert
from lab_targets.web01_service import (
    Web01Server,
    run_web01_service,
    InterfaceUnavailableError,
    MANDATORY_BIND_HOST,
    MANDATORY_BIND_PORT
)
from simulator.kali_campaign_generator import (
    validate_target_url,
    run_generator,
    SecurityViolation,
    MAX_ALLOWED_REQUESTS,
    MAX_ALLOWED_RATE,
    AUTHORIZED_LAB_HOST,
    AUTHORIZED_LAB_PORT
)


# ------------------------------------------------------------------------------
# 1. KALI GENERATOR STRICT SAFETY & TARGET VALIDATION TESTS
# ------------------------------------------------------------------------------

def test_kali_generator_strict_target_validation():
    """
    Verify Kali generator accepts ONLY http://192.168.56.30:8080 and strictly
    rejects all other destinations (localhost, 127.0.0.1, 10.x, other 192.168.x,
    public domains, public IPs, and wrong ports).
    """
    # 1. Sole Permitted Target: 192.168.56.30:8080
    valid_target = f"http://{AUTHORIZED_LAB_HOST}:{AUTHORIZED_LAB_PORT}"
    assert validate_target_url(valid_target) == valid_target
    assert validate_target_url(f"https://{AUTHORIZED_LAB_HOST}:{AUTHORIZED_LAB_PORT}") == f"https://{AUTHORIZED_LAB_HOST}:{AUTHORIZED_LAB_PORT}"

    # 2. 192.168.56.30 with wrong port MUST be rejected
    with pytest.raises(SecurityViolation, match="port"):
        validate_target_url(f"http://{AUTHORIZED_LAB_HOST}:80")

    with pytest.raises(SecurityViolation, match="port"):
        validate_target_url(f"http://{AUTHORIZED_LAB_HOST}:8000")

    with pytest.raises(SecurityViolation, match="port"):
        validate_target_url(f"http://{AUTHORIZED_LAB_HOST}:8502")

    # 3. 127.0.0.1 MUST be rejected
    with pytest.raises(SecurityViolation, match="strictly prohibited"):
        validate_target_url("http://127.0.0.1:8080")

    # 4. localhost MUST be rejected
    with pytest.raises(SecurityViolation, match="strictly prohibited"):
        validate_target_url("http://localhost:8080")

    # 5. 10.0.2.x MUST be rejected
    with pytest.raises(SecurityViolation, match="strictly prohibited"):
        validate_target_url("http://10.0.2.15:8080")

    # 6. Other private IPs (192.168.1.x, 10.x.x.x, 172.16.x.x) MUST be rejected
    with pytest.raises(SecurityViolation, match="strictly prohibited"):
        validate_target_url("http://192.168.1.100:8080")

    with pytest.raises(SecurityViolation, match="strictly prohibited"):
        validate_target_url("http://192.168.56.10:8080")

    with pytest.raises(SecurityViolation, match="strictly prohibited"):
        validate_target_url("http://10.10.10.10:8080")

    with pytest.raises(SecurityViolation, match="strictly prohibited"):
        validate_target_url("http://172.16.1.1:8080")

    # 7. Public domains and IPs MUST be rejected
    with pytest.raises(SecurityViolation, match="strictly prohibited"):
        validate_target_url("http://google.com:8080")

    with pytest.raises(SecurityViolation, match="strictly prohibited"):
        validate_target_url("http://8.8.8.8:8080")

    with pytest.raises(SecurityViolation):
        validate_target_url("")


def test_kali_generator_clamping_and_dry_run():
    """Verify request count and rate limits cannot exceed Phase 1 bounds."""
    # Dry run execution with permitted target (no network calls made)
    result = run_generator(
        target_url="http://192.168.56.30:8080",
        scenario="initial-demo",
        count=500,  # exceeds 100 limit
        rate=50.0,  # exceeds 10 req/s limit
        dry_run=True
    )

    # Must be clamped
    assert result["total_requests"] == MAX_ALLOWED_REQUESTS
    assert result["dry_run"] is True
    assert result["status_counts"][200] == 90
    assert result["status_counts"][401] == 10


# ------------------------------------------------------------------------------
# 2. WEB-01 STRICT BIND & REST ENDPOINTS TESTS
# ------------------------------------------------------------------------------

def test_web01_service_strict_bind_no_fallback():
    """
    Verify Web-01 binds specifically to 192.168.56.30:8080 and raises
    InterfaceUnavailableError without falling back to 0.0.0.0.
    """
    # 1. Attempting to configure host other than 192.168.56.30 must raise InterfaceUnavailableError
    with pytest.raises(InterfaceUnavailableError, match="Safety Policy Violation"):
        run_web01_service(host="0.0.0.0", port=8080)

    with pytest.raises(InterfaceUnavailableError, match="Safety Policy Violation"):
        run_web01_service(host="127.0.0.1", port=8080)

    # 2. Attempting to configure port other than 8080 must raise InterfaceUnavailableError
    with pytest.raises(InterfaceUnavailableError, match="Safety Policy Violation"):
        run_web01_service(host=MANDATORY_BIND_HOST, port=9000)

    # 3. If 192.168.56.30 is not present on this host, it must fail safely with InterfaceUnavailableError
    # and MUST NOT bind to 0.0.0.0
    try:
        run_web01_service(host=MANDATORY_BIND_HOST, port=MANDATORY_BIND_PORT)
    except InterfaceUnavailableError as err:
        assert "CRITICAL" in str(err) or "unavailable" in str(err).lower()
        assert "0.0.0.0 is strictly prohibited" in str(err)


def test_web01_service_endpoints():
    """Verify Web-01 provides authentic HTTP responses for benign & probe requests."""
    # Bind to ephemeral port for isolated functional endpoint testing
    server = Web01Server(("127.0.0.1", 0), ingest_url="", ingest_token="")
    port = server.server_address[1]
    base_url = f"http://127.0.0.1:{port}"

    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        # 1. GET /
        with urllib.request.urlopen(f"{base_url}/") as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["target"] == "Web-01"
            assert data["status"] == "ONLINE"

        # 2. GET /api/v1/health
        with urllib.request.urlopen(f"{base_url}/api/v1/health") as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["health"] == "HEALTHY"

        # 3. GET /admin/system (Forbidden)
        req_admin = urllib.request.Request(f"{base_url}/admin/system")
        try:
            urllib.request.urlopen(req_admin)
            pytest.fail("Expected HTTP 403 Forbidden")
        except urllib.error.HTTPError as err:
            assert err.code == 403

        # 4. POST /api/v1/login (Failed Auth)
        fail_payload = json.dumps({"username": "admin", "password": "WrongPassword!"}).encode("utf-8")
        req_login_fail = urllib.request.Request(
            f"{base_url}/api/v1/login",
            data=fail_payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        try:
            urllib.request.urlopen(req_login_fail)
            pytest.fail("Expected HTTP 401 Unauthorized")
        except urllib.error.HTTPError as err:
            assert err.code == 401

        # 5. POST /api/v1/login (Successful Auth)
        success_payload = json.dumps({"username": "demo_analyst", "password": "LabPassword2026!"}).encode("utf-8")
        req_login_succ = urllib.request.Request(
            f"{base_url}/api/v1/login",
            data=success_payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req_login_succ) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["success"] is True

        # 6. GET /unknown (404)
        req_404 = urllib.request.Request(f"{base_url}/not-a-real-page")
        try:
            urllib.request.urlopen(req_404)
            pytest.fail("Expected HTTP 404")
        except urllib.error.HTTPError as err:
            assert err.code == 404

    finally:
        server.shutdown()
        server.server_close()


# ------------------------------------------------------------------------------
# 3. END-TO-END PIPELINE TEST
# ------------------------------------------------------------------------------

def test_full_phase1_pipeline(monkeypatch):
    """
    Test the complete chain:
    Kali Traffic Generator -> Web-01 Service -> SentinelX Ingest ->
    Detection Engine -> Incident Creation -> Telegram Alert Formatting
    """
    initialize_database()

    # Step A: Spin up SentinelX Ingestion Daemon on ephemeral port
    TEST_TOKEN = "phase1-pipeline-auth-token"
    monkeypatch.setattr(api, "INGEST_TOKEN", TEST_TOKEN)

    ingest_server = ThreadingHTTPServer(("127.0.0.1", 0), api.SentinelXIngestionHandler)
    ingest_port = ingest_server.server_address[1]
    ingest_url = f"http://127.0.0.1:{ingest_port}/events"

    ingest_thread = threading.Thread(target=ingest_server.serve_forever, daemon=True)
    ingest_thread.start()

    # Step B: Spin up Web-01 Target Server configured to forward telemetry to Ingest API
    web01_server = Web01Server(
        ("127.0.0.1", 0),
        ingest_url=ingest_url,
        ingest_token=TEST_TOKEN
    )
    web01_port = web01_server.server_address[1]
    web01_url = f"http://127.0.0.1:{web01_port}"

    web01_thread = threading.Thread(target=web01_server.serve_forever, daemon=True)
    web01_thread.start()

    try:
        # Step C: Kali transmits 10 failed login attempts against Web-01
        run_res = run_generator(
            target_url=web01_url,
            scenario="auth-only",
            count=10,
            rate=10.0,
            dry_run=False,
            allow_test_target=True  # Used strictly in unit test harness
        )

        assert run_res["total_requests"] == 10
        assert run_res["status_counts"].get(401) == 10

        # Allow background telemetry dispatchers to commit to SQLite
        time.sleep(1.0)

        # Step D: Verify telemetry events persisted in SentinelX SQLite
        events = get_recent_events(limit=50)
        web01_events = [
            ev for ev in events
            if "target=Web-01" in str(ev.get("message", "")) and ev.get("event_type") == "LOGIN"
        ]

        assert len(web01_events) >= 10, f"Expected >= 10 Web-01 events, found {len(web01_events)}"
        for ev in web01_events[:10]:
            assert ev["status"] == "FAILED"
            assert ev["source_ip"] == "127.0.0.1"
            assert ev["port"] == web01_port
            assert "POST /api/v1/login" in ev["action"]

        # Step E: Trigger Detection Engine (Brute Force T1110)
        alerts = detect_brute_force(web01_events)
        assert len(alerts) >= 1, "Brute force detection failed to trigger on Web-01 telemetry"
        alert = alerts[0]
        assert alert["alert_type"] == "BRUTE_FORCE"
        assert alert["mitre_technique"] == "T1110"
        assert alert["source_ip"] == "127.0.0.1"
        assert len(alert["evidence"]["event_ids"]) >= 5

        # Step F: Enrich with Risk Engine
        enriched = enrich_alert_with_risk(alert)
        assert enriched["risk_score"] == 70
        assert enriched["risk_level"] == "HIGH"

        # Step G: Create Incident and Link Evidence
        incident_id = create_incident(enriched)
        assert incident_id.startswith("INC-")

        link_events_to_incident(incident_id, alert["evidence"]["event_ids"])
        linked = get_incident_events(incident_id)
        assert len(linked) >= 5

        # Step H: Verify Telegram Alert formatting
        telegram_payload = {
            "incident_id": incident_id,
            "alert_type": enriched["alert_type"],
            "title": enriched["title"],
            "source_ip": enriched["source_ip"],
            "severity": enriched["severity"],
            "risk_score": enriched["risk_score"],
            "mitre_technique": enriched["mitre_technique"],
            "description": enriched["message"]
        }

        # Verify send_incident_alert formats cleanly without raising unhandled errors
        res = send_incident_alert(telegram_payload)
        # Even if token is not configured in this test environment, it returns a clean dict failure
        assert isinstance(res, dict)
        assert "message" in res

    finally:
        web01_server.shutdown()
        web01_server.server_close()
        ingest_server.shutdown()
        ingest_server.server_close()


if __name__ == "__main__":
    pytest.main(["-v", __file__])
