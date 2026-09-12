import json
import os
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from database.database import initialize_database, insert_event


HOST = "0.0.0.0"
PORT = int(os.getenv("SENTINELX_INGEST_PORT", "8502"))

INGEST_TOKEN = os.getenv("SENTINELX_INGEST_TOKEN", "").strip()

MAX_BODY_SIZE = 16 * 1024


REQUIRED_FIELDS = {
    "event_type",
    "source_ip",
    "status",
}


ALLOWED_EVENT_TYPES = {
    "LOGIN",
    "NETWORK_CONNECTION",
    "CONNECTION_ATTEMPT",
    "PRIVILEGE_CHANGE",
    "PRIVILEGE_ESCALATION",
    "POWERSHELL",
}


ALLOWED_STATUS = {
    "SUCCESS",
    "FAILED",
}


class SentinelXIngestionHandler(BaseHTTPRequestHandler):

    server_version = "SentinelX-Ingestion/1.0"

    def log_message(self, format, *args):

        print(
            f"[INGEST] {self.address_string()} - {format % args}"
        )


    def send_json(self, status_code, payload):

        response = json.dumps(
            payload
        ).encode("utf-8")

        self.send_response(
            status_code
        )

        self.send_header(
            "Content-Type",
            "application/json"
        )

        self.send_header(
            "Content-Length",
            str(len(response))
        )

        self.send_header(
            "Cache-Control",
            "no-store"
        )

        self.end_headers()

        self.wfile.write(
            response
        )


    def do_GET(self):

        if self.path == "/health":

            self.send_json(
                200,
                {
                    "status": "ok",
                    "service": "SentinelX ingestion API"
                }
            )

            return


        self.send_json(
            404,
            {
                "error": "Not found"
            }
        )


    def do_POST(self):

        if self.path != "/events":

            self.send_json(
                404,
                {
                    "error": "Not found"
                }
            )

            return


        # ------------------------------------------
        # AUTHENTICATION
        # ------------------------------------------

        if not INGEST_TOKEN:

            self.send_json(
                503,
                {
                    "error": "Ingestion authentication is not configured."
                }
            )

            return


        authorization = (
            self.headers.get(
                "Authorization",
                ""
            ).strip()
        )


        expected_authorization = (
            f"Bearer {INGEST_TOKEN}"
        )


        if authorization != expected_authorization:

            self.send_json(
                401,
                {
                    "error": "Unauthorized"
                }
            )

            return


        # ------------------------------------------
        # CONTENT TYPE
        # ------------------------------------------

        content_type = (
            self.headers.get(
                "Content-Type",
                ""
            ).split(";")[0].strip().lower()
        )


        if content_type != "application/json":

            self.send_json(
                415,
                {
                    "error": "Content-Type must be application/json."
                }
            )

            return


        # ------------------------------------------
        # BODY SIZE
        # ------------------------------------------

        content_length_header = (
            self.headers.get(
                "Content-Length"
            )
        )


        try:

            content_length = int(
                content_length_header
            )

        except (
            TypeError,
            ValueError
        ):

            self.send_json(
                400,
                {
                    "error": "Invalid Content-Length."
                }
            )

            return


        if (
            content_length <= 0
            or content_length > MAX_BODY_SIZE
        ):

            self.send_json(
                413,
                {
                    "error": "Request body too large or empty."
                }
            )

            return


        # ------------------------------------------
        # READ BODY
        # ------------------------------------------

        try:

            body = self.rfile.read(
                content_length
            )

            payload = json.loads(
                body.decode("utf-8")
            )

        except (
            UnicodeDecodeError,
            json.JSONDecodeError
        ):

            self.send_json(
                400,
                {
                    "error": "Invalid JSON."
                }
            )

            return


        # ------------------------------------------
        # PAYLOAD VALIDATION
        # ------------------------------------------

        if not isinstance(
            payload,
            dict
        ):

            self.send_json(
                400,
                {
                    "error": "JSON payload must be an object."
                }
            )

            return


        missing_fields = [
            field
            for field in REQUIRED_FIELDS
            if not payload.get(field)
        ]


        if missing_fields:

            self.send_json(
                400,
                {
                    "error": "Missing required fields.",
                    "fields": sorted(
                        missing_fields
                    )
                }
            )

            return


        event_type = str(
            payload.get(
                "event_type",
                ""
            )
        ).strip().upper()


        status = str(
            payload.get(
                "status",
                ""
            )
        ).strip().upper()


        source_ip = str(
            payload.get(
                "source_ip",
                ""
            )
        ).strip()


        if event_type not in ALLOWED_EVENT_TYPES:

            self.send_json(
                400,
                {
                    "error": "Unsupported event_type."
                }
            )

            return


        if status not in ALLOWED_STATUS:

            self.send_json(
                400,
                {
                    "error": "Unsupported status."
                }
            )

            return


        # ------------------------------------------
        # SOURCE IP VALIDATION
        # ------------------------------------------

        parts = source_ip.split(".")


        if (
            len(parts) != 4
            or any(
                not part.isdigit()
                or not 0 <= int(part) <= 255
                for part in parts
            )
        ):

            self.send_json(
                400,
                {
                    "error": "Invalid IPv4 source_ip."
                }
            )

            return


        # ------------------------------------------
        # NORMALIZE EVENT
        # ------------------------------------------

        raw_ts = payload.get("timestamp")
        clean_ts = str(raw_ts).strip() if raw_ts is not None else ""
        if not clean_ts or clean_ts.lower() in ("none", "null"):
            clean_ts = datetime.now().isoformat()

        event = {

            "timestamp": clean_ts,

            "source_ip": source_ip,

            "username": str(
                payload.get(
                    "username",
                    ""
                )
            ).strip(),

            "event_type": event_type,

            "action": str(
                payload.get(
                    "action",
                    ""
                )
            ).strip(),

            "status": status,

            "message": str(
                payload.get(
                    "message",
                    ""
                )
            ).strip(),

            "severity": str(
                payload.get(
                    "severity",
                    "LOW"
                )
            ).strip().upper(),

            "port": payload.get(
                "port"
            )
        }


        # ------------------------------------------
        # PORT VALIDATION
        # ------------------------------------------

        if event["port"] is not None:

            try:

                event["port"] = int(
                    event["port"]
                )

            except (
                TypeError,
                ValueError
            ):

                self.send_json(
                    400,
                    {
                        "error": "Invalid port."
                    }
                )

                return


            if not 1 <= event["port"] <= 65535:

                self.send_json(
                    400,
                    {
                        "error": "Port must be between 1 and 65535."
                    }
                )

                return


        # ------------------------------------------
        # STRING LENGTH LIMITS
        # ------------------------------------------

        string_limits = {

            "username": 128,

            "action": 128,

            "message": 2048,

            "severity": 32,

            "timestamp": 64

        }


        for field, maximum in string_limits.items():

            if len(
                event[field]
            ) > maximum:

                self.send_json(
                    400,
                    {
                        "error": f"{field} is too long."
                    }
                )

                return


        # ------------------------------------------
        # INSERT EVENT
        # ------------------------------------------

        try:

            event_id = insert_event(
                event
            )

        except Exception as error:

            print(
                "[INGEST ERROR]",
                repr(error)
            )

            self.send_json(
                500,
                {
                    "error": "Event could not be stored."
                }
            )

            return


        print(
            f"[INGEST] Event {event_id} received "
            f"from {source_ip} "
            f"type={event_type}"
        )


        self.send_json(
            201,
            {
                "success": True,
                "event_id": event_id
            }
        )


def main():

    initialize_database()


    if not INGEST_TOKEN:

        raise RuntimeError(
            "SENTINELX_INGEST_TOKEN is not configured."
        )


    server = ThreadingHTTPServer(
        (
            HOST,
            PORT
        ),
        SentinelXIngestionHandler
    )


    print(
        "=========================================="
    )

    print(
        "SentinelX Remote Ingestion API"
    )

    print(
        "=========================================="
    )

    print(
        f"Listening on http://{HOST}:{PORT}"
    )

    print(
        "POST /events"
    )

    print(
        "GET  /health"
    )

    print(
        "Authentication: Bearer token"
    )

    print(
        "=========================================="
    )


    try:

        server.serve_forever()

    except KeyboardInterrupt:

        print(
            "\nStopping SentinelX ingestion API..."
        )

    finally:

        server.server_close()


if __name__ == "__main__":

    main()