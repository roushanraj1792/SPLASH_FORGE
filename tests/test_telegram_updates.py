import os

from dotenv import load_dotenv

from services.telegram_alert import (
    send_telegram_message,
    send_test_alert,
    send_incident_alert,
)

load_dotenv()


def test_telegram_configuration():
    assert os.getenv("TELEGRAM_BOT_TOKEN"), (
        "TELEGRAM_BOT_TOKEN is not configured"
    )

    assert os.getenv("TELEGRAM_CHAT_ID"), (
        "TELEGRAM_CHAT_ID is not configured"
    )


def test_telegram_message():
    result = send_telegram_message(
        "SentinelX pytest Telegram integration test."
    )

    assert result.get("success") is True, (
        f"Telegram message failed: {result.get('message')}"
    )


def test_telegram_test_alert():
    result = send_test_alert()

    assert result.get("success") is True, (
        f"Telegram test alert failed: {result.get('message')}"
    )


def test_telegram_incident_alert():
    incident = {
        "incident_id": "TEST-PYTEST-001",
        "title": "SentinelX Telegram Pytest Test",
        "severity": "HIGH",
        "source_ip": "192.168.1.250",
        "risk_score": 70,
        "mitre_technique": "T1110",
    }

    result = send_incident_alert(incident)

    assert result.get("success") is True, (
        f"Telegram incident alert failed: {result.get('message')}"
    )
