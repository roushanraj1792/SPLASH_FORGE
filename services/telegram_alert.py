import html
import os
import requests
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()


# --------------------------------------------------
# TELEGRAM CONFIGURATION
# --------------------------------------------------

TELEGRAM_BOT_TOKEN = os.getenv(
    "TELEGRAM_BOT_TOKEN"
)

TELEGRAM_CHAT_ID = os.getenv(
    "TELEGRAM_CHAT_ID"
)


# --------------------------------------------------
# SEND TELEGRAM MESSAGE
# --------------------------------------------------

def send_telegram_message(message):

    if not TELEGRAM_BOT_TOKEN:
        return {
            "success": False,
            "message": "TELEGRAM_BOT_TOKEN is not configured."
        }

    if not TELEGRAM_CHAT_ID:
        return {
            "success": False,
            "message": "TELEGRAM_CHAT_ID is not configured."
        }

    url = (
        f"https://api.telegram.org/bot"
        f"{TELEGRAM_BOT_TOKEN}/sendMessage"
    )

    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "HTML",
        "disable_web_page_preview": True
    }

    try:
        response = requests.post(
            url,
            json=payload,
            timeout=10
        )

        response_data = response.json()

        if response.status_code == 200:
            return {
                "success": True,
                "message": "Telegram message sent successfully."
            }

        return {
            "success": False,
            "message": response_data.get(
                "description",
                "Telegram API request failed."
            )
        }

    except requests.RequestException as error:
        return {
            "success": False,
            "message": f"Telegram request error: {error}"
        }

    except ValueError:
        return {
            "success": False,
            "message": "Invalid response received from Telegram API."
        }


# --------------------------------------------------
# SEND TEST ALERT
# --------------------------------------------------

def send_test_alert():

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    message = (
        "🛡️ SentinelX Test Alert\n\n"
        "Telegram integration is working successfully.\n\n"
        f"Time: {timestamp}"
    )

    return send_telegram_message(message)


# --------------------------------------------------
# SEND INCIDENT ALERT
# --------------------------------------------------

def send_incident_alert(incident):

    incident_id = html.escape(str(incident.get(
        "incident_id",
        "UNKNOWN"
    )))

    title = html.escape(str(incident.get(
        "title",
        "Security Incident"
    )))

    severity = html.escape(str(incident.get(
        "severity",
        "UNKNOWN"
    )))

    source_ip = html.escape(str(incident.get(
        "source_ip",
        "UNKNOWN"
    )))

    risk_score = html.escape(str(incident.get(
        "risk_score",
        "N/A"
    )))

    mitre = html.escape(str(incident.get(
        "mitre_technique",
        "N/A"
    )))

    message = (
        "🚨 SentinelX Security Alert\n\n"
        f"Incident: {incident_id}\n"
        f"Title: {title}\n"
        f"Severity: {severity}\n"
        f"Risk Score: {risk_score}/100\n"
        f"Source IP: <code>{source_ip}</code>\n"
        f"MITRE ATT&CK: {mitre}\n\n"
        "SentinelX SOC detected a security incident."
    )

    return send_telegram_message(message)
