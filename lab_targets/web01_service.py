"""
Web-01 — Authorized Laboratory Target Web Application
=====================================================
Part of the SentinelX Red-to-Blue Security Laboratory.

Role:
  Exposes realistic, controlled HTTP endpoints (portal, health probe,
  authentication, administration, and search) for authorized security testing.
  Every incoming request generates authentic access/security telemetry that is
  forwarded out-of-band to the SentinelX ingestion API (api.py).

Security & Boundary Rules:
  - Listens only on configured lab interfaces (defaults to 192.168.56.30:8080,
    with configurable fallback to 0.0.0.0:8080 or 127.0.0.1:8080).
  - Holds the SentinelX ingestion token; never exposes this token to clients.
  - Generates real HTTP status codes (200, 401, 403, 404).
  - Forwards telemetry strictly to the SentinelX ingestion API.
"""

import argparse
import json
import os
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlparse

import dotenv
import requests

# Load SentinelX environment configuration safely without overriding
PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = PROJECT_ROOT / ".env"
if ENV_FILE.is_file():
    dotenv.load_dotenv(ENV_FILE, override=False)

# Configuration defaults
DEFAULT_HOST = os.getenv("WEB01_HOST", "192.168.56.30")
DEFAULT_PORT = int(os.getenv("WEB01_PORT", "8080"))
DEFAULT_INGEST_URL = os.getenv(
    "SENTINELX_INGEST_URL",
    "http://192.168.56.1:8502/events"
)
DEFAULT_INGEST_TOKEN = os.getenv("SENTINELX_INGEST_TOKEN", "").strip()

# Mock authorized credentials for testing
VALID_CREDENTIALS = {
    "demo_analyst": "LabPassword2026!",
    "web_service": "ServiceAuth2026!",
}


def dispatch_telemetry(
    event: Dict[str, Any],
    ingest_url: str,
    ingest_token: str,
    timeout: float = 3.0
) -> Tuple[bool, str]:
    """
    Ship a structured security telemetry event to SentinelX.
    Fails safely without raising unhandled exceptions to prevent Web-01 downtime.
    """
    if not ingest_url or not ingest_token:
        return False, "Ingest URL or token not configured."

    headers = {
        "Authorization": f"Bearer {ingest_token}",
        "Content-Type": "application/json",
        "User-Agent": "SentinelX-Web01-Forwarder/1.0"
    }

    try:
        response = requests.post(
            ingest_url,
            json=event,
            headers=headers,
            timeout=timeout
        )
        if response.status_code == 201:
            return True, "Event ingested successfully."
        return False, f"Ingest API returned HTTP {response.status_code}: {response.text[:120]}"
    except Exception as exc:
        return False, f"Telemetry forwarding error: {exc}"


class Web01RequestHandler(BaseHTTPRequestHandler):
    """
    HTTP Request Handler for the authorized Web-01 lab application.
    Processes benign and test traffic, emits real responses, and records telemetry.
    """

    server_version = "Web01-CorporatePortal/2.4"

    def log_message(self, format: str, *args: Any) -> None:
        """Custom access logging for clean terminal output."""
        print(f"[Web-01] {self.address_string()} - {format % args}")

    def send_json_response(
        self,
        status_code: int,
        payload: Dict[str, Any],
        headers: Optional[Dict[str, str]] = None
    ) -> None:
        """Helper to send structured JSON HTTP response."""
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Target-Asset", "Web-01")
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def record_and_forward_telemetry(
        self,
        method: str,
        path: str,
        status_code: int,
        start_time: float,
        username: str = "",
        extra_info: str = ""
    ) -> None:
        """
        Extract factual request metrics and forward out-of-band to SentinelX.
        """
        duration_ms = max(1, int((time.time() - start_time) * 1000))
        client_ip = self.client_address[0]
        now_iso = datetime.now(timezone.utc).isoformat()
        user_agent = self.headers.get("User-Agent", "Unknown-Agent").strip()
        scenario_tag = self.headers.get("X-Lab-Scenario", "").strip()
        campaign_tag = self.headers.get("X-Lab-Campaign-ID", "").strip()

        # Map to canonical SentinelX schema
        is_login = path.rstrip("/").endswith("/login")
        if is_login:
            event_type = "LOGIN"
            status = "SUCCESS" if status_code == 200 else "FAILED"
            severity = "LOW" if status_code == 200 else "HIGH"
        else:
            event_type = "NETWORK_CONNECTION"
            status = "SUCCESS" if status_code < 400 else "FAILED"
            severity = "LOW" if status_code < 400 else "MEDIUM"

        action = f"{method} {path}"
        server_port = getattr(self.server, "server_port", 8080)

        # Structure additional web context inside the 2048-char message field
        msg_parts = [
            "target=Web-01",
            f"http_status={status_code}",
            f"duration_ms={duration_ms}",
            f"ua='{user_agent[:120]}'"
        ]
        if scenario_tag:
            msg_parts.append(f"scenario={scenario_tag[:64]}")
        if campaign_tag:
            msg_parts.append(f"camp={campaign_tag[:32]}")
        if extra_info:
            msg_parts.append(f"note='{extra_info[:120]}'")

        structured_message = f"{action} ({status}) | " + " ".join(msg_parts)

        telemetry_event = {
            "timestamp": now_iso,
            "source_ip": client_ip,
            "username": username[:128] if username else "",
            "event_type": event_type,
            "action": action[:128],
            "status": status,
            "message": structured_message[:2048],
            "severity": severity,
            "port": server_port
        }

        ingest_url = getattr(self.server, "ingest_url", DEFAULT_INGEST_URL)
        ingest_token = getattr(self.server, "ingest_token", DEFAULT_INGEST_TOKEN)

        if ingest_url and ingest_token:
            # Dispatch asynchronously in background worker to never block Web-01 client responses
            thread = threading.Thread(
                target=dispatch_telemetry,
                args=(telemetry_event, ingest_url, ingest_token),
                daemon=True
            )
            thread.start()

        # Append to server-level in-memory log for testing/inspection
        if hasattr(self.server, "telemetry_history"):
            self.server.telemetry_history.append(telemetry_event)

    # --------------------------------------------------------------------------
    # HTTP METHOD HANDLERS
    # --------------------------------------------------------------------------

    def do_GET(self) -> None:
        start_time = time.time()
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/":
            self.send_json_response(200, {
                "target": "Web-01",
                "service": "SentinelX Authorized Lab Portal",
                "status": "ONLINE",
                "environment": "AUTHORIZED_CYBER_LAB",
                "endpoints": [
                    "/",
                    "/api/v1/health",
                    "/api/v1/login",
                    "/admin/system",
                    "/search"
                ]
            })
            self.record_and_forward_telemetry("GET", path, 200, start_time)

        elif path == "/api/v1/health":
            self.send_json_response(200, {
                "target": "Web-01",
                "health": "HEALTHY",
                "uptime": "Active",
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
            self.record_and_forward_telemetry("GET", path, 200, start_time)

        elif path == "/admin/system":
            # Restricted endpoint
            self.send_json_response(403, {
                "error": "Forbidden",
                "message": "Administrative credentials required to access /admin/system."
            })
            self.record_and_forward_telemetry("GET", path, 403, start_time, extra_info="Unauthorized admin access probe")

        elif path == "/search":
            query = parse_qs(parsed.query).get("q", [""])[0]
            self.send_json_response(200, {
                "target": "Web-01",
                "query": query,
                "results_count": 0,
                "message": "Search completed cleanly."
            })
            self.record_and_forward_telemetry("GET", path, 200, start_time, extra_info=f"query={query[:64]}")

        else:
            self.send_json_response(404, {
                "error": "Not Found",
                "path": path,
                "message": "The requested resource does not exist on Web-01."
            })
            self.record_and_forward_telemetry("GET", path, 404, start_time)

    def do_POST(self) -> None:
        start_time = time.time()
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        content_length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(content_length) if content_length > 0 else b"{}"

        try:
            payload = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
        except Exception:
            payload = {}

        if path in ["/login", "/api/v1/login"]:
            username = str(payload.get("username", "")).strip()
            password = str(payload.get("password", "")).strip()

            if username in VALID_CREDENTIALS and VALID_CREDENTIALS[username] == password:
                self.send_json_response(200, {
                    "success": True,
                    "target": "Web-01",
                    "authenticated_as": username,
                    "session_token": f"web01-token-{int(time.time())}"
                })
                self.record_and_forward_telemetry("POST", path, 200, start_time, username=username)
            else:
                self.send_json_response(401, {
                    "success": False,
                    "target": "Web-01",
                    "error": "Invalid laboratory credentials."
                })
                self.record_and_forward_telemetry(
                    "POST",
                    path,
                    401,
                    start_time,
                    username=username or "anonymous",
                    extra_info="Authentication failure"
                )
        else:
            self.send_json_response(404, {
                "error": "Not Found",
                "path": path,
                "message": "Target POST endpoint does not exist."
            })
            self.record_and_forward_telemetry("POST", path, 404, start_time)


class Web01Server(ThreadingHTTPServer):
    """
    Threading HTTP Server for Web-01 providing stateful configuration storage.
    """

    def __init__(
        self,
        server_address: Tuple[str, int],
        ingest_url: str = DEFAULT_INGEST_URL,
        ingest_token: str = DEFAULT_INGEST_TOKEN
    ):
        self.ingest_url = ingest_url
        self.ingest_token = ingest_token
        self.telemetry_history = []
        super().__init__(server_address, Web01RequestHandler)


MANDATORY_BIND_HOST = "192.168.56.30"
MANDATORY_BIND_PORT = 8080


class InterfaceUnavailableError(OSError):
    """Raised when the mandatory Web-01 interface (192.168.56.30:8080) is not available."""
    pass


def run_web01_service(
    host: str = MANDATORY_BIND_HOST,
    port: int = MANDATORY_BIND_PORT,
    ingest_url: str = DEFAULT_INGEST_URL,
    ingest_token: str = DEFAULT_INGEST_TOKEN
) -> None:
    """
    Launch the Web-01 laboratory service.
    Binds strictly to 192.168.56.30:8080. Fallback to 0.0.0.0 is prohibited by safety policy.
    """
    if host != MANDATORY_BIND_HOST or port != MANDATORY_BIND_PORT:
        raise InterfaceUnavailableError(
            f"Safety Policy Violation: Web-01 must bind specifically to "
            f"{MANDATORY_BIND_HOST}:{MANDATORY_BIND_PORT}. Configured: {host}:{port}"
        )

    print("=" * 60)
    print("  AUTHORIZED LAB TARGET: Web-01 Service")
    print("=" * 60)
    print(f"Target Identity     : Web-01")
    print(f"Mandatory Bind Host : {host}")
    print(f"Mandatory Bind Port : {port}")
    print(f"SentinelX Ingest URL: {ingest_url}")
    print(f"SentinelX Token Set : {'Yes' if bool(ingest_token) else 'NO (Telemetry forwarding disabled)'}")
    print("=" * 60)

    try:
        server = Web01Server((host, port), ingest_url=ingest_url, ingest_token=ingest_token)
    except OSError as bind_err:
        raise InterfaceUnavailableError(
            f"CRITICAL: Failed to bind specifically to {host}:{port} ({bind_err}). "
            f"Interface is unavailable. Fallback to 0.0.0.0 is strictly prohibited."
        ) from bind_err

    actual_host, actual_port = server.server_address
    print(f"[Web-01] Listening specifically on http://{actual_host}:{actual_port}")
    print("[Web-01] Ready to receive authorized laboratory traffic. Press Ctrl+C to stop.\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Web-01] Shutting down cleanly...")
    finally:
        server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Web-01 Authorized Laboratory Target Service")
    parser.add_argument("--host", default=MANDATORY_BIND_HOST, help="Host to bind (must be 192.168.56.30)")
    parser.add_argument("--port", type=int, default=MANDATORY_BIND_PORT, help="Port to bind (must be 8080)")
    parser.add_argument("--ingest-url", default=DEFAULT_INGEST_URL, help="SentinelX Ingestion API endpoint")
    parser.add_argument("--ingest-token", default=DEFAULT_INGEST_TOKEN, help="SentinelX Ingestion Bearer token")
    args = parser.parse_args()

    run_web01_service(
        host=args.host,
        port=args.port,
        ingest_url=args.ingest_url,
        ingest_token=args.ingest_token
    )
