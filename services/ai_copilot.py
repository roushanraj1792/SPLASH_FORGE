import os
import json
from typing import Dict, List, Any

from dotenv import load_dotenv
from google import genai

load_dotenv()


# ============================================================
# SENTINELX AI SOC COPILOT
# ============================================================

GEMINI_MODEL = "gemini-3.6-flash"


# ============================================================
# DATA NORMALIZATION
# ============================================================

def normalize_record(record: Any) -> Dict:
    """
    Convert supported database/application records into a dictionary.

    Supports:
    - dict
    - sqlite3.Row
    - objects exposing keys()
    """

    if isinstance(record, dict):
        return dict(record)

    if hasattr(record, "keys"):
        try:
            return {
                key: record[key]
                for key in record.keys()
            }
        except Exception:
            return {}

    return {}


def normalize_events(events: List[Any]) -> List[Dict]:
    """
    Normalize all correlated security events into dictionaries.
    Invalid/unusable records are skipped safely.
    """

    normalized = []

    if not events:
        return normalized

    for event in events:

        event_data = normalize_record(event)

        if event_data:
            normalized.append(event_data)

    return normalized


# ============================================================
# INCIDENT CONTEXT
# ============================================================

def build_incident_context(
    incident: Dict,
    events: List[Dict]
) -> str:
    """
    Build a structured security context for AI analysis.
    """

    incident_data = normalize_record(incident)
    normalized_events = normalize_events(events)

    context = []

    context.append("SENTINELX SECURITY INCIDENT")
    context.append("================================")

    context.append(
        f"Incident ID: {incident_data.get('incident_id', 'N/A')}"
    )

    context.append(
        f"Alert Type: {incident_data.get('alert_type', 'N/A')}"
    )

    context.append(
        f"Title: {incident_data.get('title', 'N/A')}"
    )

    context.append(
        f"Source IP: {incident_data.get('source_ip', 'N/A')}"
    )

    context.append(
        f"Severity: {incident_data.get('severity', 'N/A')}"
    )

    context.append(
        f"Risk Score: {incident_data.get('risk_score', 'N/A')}/100"
    )

    context.append(
        f"Risk Level: {incident_data.get('risk_level', 'N/A')}"
    )

    context.append(
        f"MITRE ATT&CK: {incident_data.get('mitre_technique', 'N/A')}"
    )

    context.append(
        f"Status: {incident_data.get('status', 'N/A')}"
    )

    context.append(
        f"Description: {incident_data.get('description', 'N/A')}"
    )

    context.append("")
    context.append("CORRELATED SECURITY EVENTS")
    context.append("================================")

    for event in normalized_events:

        context.append(
            f"Event ID: {event.get('id', 'N/A')}"
        )

        context.append(
            f"Timestamp: {event.get('timestamp', 'N/A')}"
        )

        context.append(
            f"Source IP: {event.get('source_ip', 'N/A')}"
        )

        context.append(
            f"Username: {event.get('username', 'N/A')}"
        )

        context.append(
            f"Event Type: {event.get('event_type', 'N/A')}"
        )

        context.append(
            f"Action: {event.get('action', 'N/A')}"
        )

        context.append(
            f"Status: {event.get('status', 'N/A')}"
        )

        context.append(
            f"Message: {event.get('message', 'N/A')}"
        )

        context.append(
            f"Port: {event.get('port', 'N/A')}"
        )

        context.append("")

    return "\n".join(context)


# ============================================================
# RULE-BASED FALLBACK
# ============================================================

def generate_rule_based_analysis(
    incident: Dict,
    events: List[Dict]
) -> Dict:
    """
    Deterministic fallback analysis.
    SentinelX remains functional even if Gemini is unavailable.
    """

    incident_data = normalize_record(incident)
    normalized_events = normalize_events(events)

    severity = str(
        incident_data.get("severity", "LOW")
    ).upper()

    risk_score = incident_data.get(
        "risk_score",
        0
    )

    mitre = incident_data.get(
        "mitre_technique",
        "N/A"
    )

    alert_type = incident_data.get(
        "alert_type",
        "UNKNOWN"
    )

    source_ip = incident_data.get(
        "source_ip",
        "UNKNOWN"
    )

    if severity == "CRITICAL":
        priority = "Immediate response required."

    elif severity == "HIGH":
        priority = "High-priority investigation required."

    elif severity == "MEDIUM":
        priority = "Analyst investigation recommended."

    else:
        priority = "Low-priority monitoring recommended."

    investigation_steps = [
        "Review all correlated security events.",
        "Validate whether the observed activity is expected or malicious.",
        f"Investigate the mapped MITRE ATT&CK technique {mitre}.",
        "Review related events before and after the detected activity."
    ]

    recommended_response = [
        "Continue monitoring the detected source activity.",
        "Validate the source and affected entities using available SOC telemetry.",
        "If malicious activity is confirmed, apply the predefined SentinelX containment policy.",
        "Document the investigation and response actions."
    ]

    return {
        "incident_summary": (
            f"SentinelX detected {alert_type} activity "
            f"from {source_ip} based on the supplied security evidence."
        ),

        "severity_explanation": (
            f"Risk score is {risk_score}/100 with "
            f"{severity} severity. {priority}"
        ),

        "mitre_explanation": (
            f"The incident is mapped to MITRE ATT&CK "
            f"technique {mitre}. The technique mapping "
            f"comes from the SentinelX detection engine."
        ),

        "investigation_steps": investigation_steps,

        "recommended_response": recommended_response,

        "evidence_count": len(normalized_events),

        "ai_source": "Rule-Based Fallback"
    }


# ============================================================
# GEMINI AI ANALYSIS
# ============================================================

def generate_gemini_analysis(
    incident: Dict,
    events: List[Dict]
) -> Dict:
    """
    Generate AI-assisted SOC analysis using Gemini.

    Gemini is used only for analysis and recommendations.
    It cannot execute commands or perform containment.
    """

    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY environment variable is not set."
        )

    client = genai.Client(
        api_key=api_key
    )

    incident_data = normalize_record(incident)
    normalized_events = normalize_events(events)

    context = build_incident_context(
        incident_data,
        normalized_events
    )

    prompt = f"""
You are SentinelX AI SOC Copilot.

You are assisting a cybersecurity analyst in a defensive SOC.

IMPORTANT SAFETY RULES:

- Analyze only the supplied SentinelX security incident.
- The supplied incident context and correlated events are the ONLY source of incident-specific facts.
- Never invent, assume, estimate, or fabricate evidence.
- Never invent timestamps, IP addresses, usernames, hostnames, destination IPs, ports, processes, commands, tools, malware, files, attack methods, or network details.
- Never claim a host is compromised unless the supplied evidence explicitly proves compromise.
- Never claim an IP is internal or external unless the supplied evidence explicitly establishes this.
- Never claim a specific tool such as Nmap, PowerShell, malware, scanner, or custom script was used unless it is explicitly present in the supplied evidence.
- Never claim that a connection succeeded or failed unless the supplied event status explicitly shows this.
- Never invent an exact investigation timestamp.
- If information is unavailable, say exactly: "Not available in supplied evidence."
- Clearly distinguish observed evidence from possible explanations and investigation recommendations.
- General cybersecurity knowledge may be used only for explaining MITRE ATT&CK techniques or giving defensive investigation recommendations.
- Do not add new incident facts from general cybersecurity knowledge.
- SentinelX deterministic detection results are authoritative for alert type, severity, risk score, and MITRE ATT&CK mapping.
- Do not change or override SentinelX detection results.

DEFENSIVE SOC RULES:

- Do not execute commands.
- Do not perform containment.
- Do not provide destructive commands.
- Do not provide offensive attack instructions.
- Provide only defensive investigation and response recommendations.

Analyze the following SentinelX incident:

{context}

Return ONLY valid JSON.

Do not use Markdown.
Do not use code fences.
Do not add explanations outside JSON.

Use exactly this structure:

{{
    "incident_summary": "Evidence-based summary using only facts explicitly present in the supplied incident and events.",

    "severity_explanation": "Explain the supplied severity and risk score using only the available evidence.",

    "mitre_explanation": "Explain the mapped MITRE ATT&CK technique using general defensive knowledge. Do not invent incident-specific facts.",

    "investigation_steps": [
        "Investigation step 1",
        "Investigation step 2",
        "Investigation step 3",
        "Investigation step 4"
    ],

    "recommended_response": [
        "Defensive recommendation 1",
        "Defensive recommendation 2",
        "Defensive recommendation 3"
    ]
}}
"""

    response = client.models.generate_content(
        model=GEMINI_MODEL,
        contents=prompt
    )

    text = response.text.strip()

    # Remove Markdown code fences if Gemini adds them.
    if text.startswith("```"):
        text = text.replace("```json", "")
        text = text.replace("```", "")
        text = text.strip()

    result = json.loads(text)

    required_fields = [
        "incident_summary",
        "severity_explanation",
        "mitre_explanation",
        "investigation_steps",
        "recommended_response"
    ]

    for field in required_fields:
        if field not in result:
            raise ValueError(
                f"Gemini response missing required field: {field}"
            )

    if not isinstance(
        result["investigation_steps"],
        list
    ):
        raise ValueError(
            "investigation_steps must be a list."
        )

    if not isinstance(
        result["recommended_response"],
        list
    ):
        raise ValueError(
            "recommended_response must be a list."
        )

    result["evidence_count"] = len(
        normalized_events
    )

    result["ai_source"] = "Gemini AI"

    return result


# ============================================================
# MAIN COPILOT FUNCTION
# ============================================================

def analyze_incident(
    incident: Dict,
    events: List[Dict]
) -> Dict:
    """
    Main SentinelX AI Copilot entry point.

    Gemini is attempted first.
    If Gemini fails, deterministic fallback is returned.
    """

    incident_data = normalize_record(
        incident
    )

    normalized_events = normalize_events(
        events
    )

    context = build_incident_context(
        incident_data,
        normalized_events
    )

    try:

        analysis = generate_gemini_analysis(
            incident_data,
            normalized_events
        )

        analysis["context"] = context

        return analysis

    except Exception as error:

        fallback = generate_rule_based_analysis(
            incident_data,
            normalized_events
        )

        fallback["context"] = context

        fallback["ai_error"] = str(error)

        return fallback

