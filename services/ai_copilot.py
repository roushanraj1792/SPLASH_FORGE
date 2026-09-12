import os
import json
import re
from datetime import datetime
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
# GROUNDED IOC & OBSERVABLE INDICATOR EXTRACTION
# ============================================================

def extract_incident_iocs(
    incident: Dict,
    events: List[Dict]
) -> Dict[str, Any]:
    """
    Extract strictly grounded observable indicators (IOCs) from
    incident and correlated events.
    Never hallucinates or invents indicators outside the supplied evidence.
    """

    incident_data = normalize_record(incident)
    normalized_events = normalize_events(events)

    source_ips = set()
    if incident_data.get("source_ip"):
        source_ips.add(str(incident_data["source_ip"]).strip())

    usernames = set()
    ports = set()
    event_types = set()
    actions = set()
    timestamps = []

    for ev in normalized_events:
        ip = ev.get("source_ip")
        if ip and str(ip).strip():
            source_ips.add(str(ip).strip())

        user = ev.get("username")
        if user and str(user).strip() not in ["", "—", "None", "null", "N/A"]:
            usernames.add(str(user).strip())

        port = ev.get("port")
        if port is not None and str(port).strip() not in ["", "—", "None", "null"]:
            try:
                ports.add(int(port))
            except (ValueError, TypeError):
                ports.add(str(port).strip())

        ev_type = ev.get("event_type")
        if ev_type and str(ev_type).strip():
            event_types.add(str(ev_type).strip())

        action = ev.get("action")
        if action and str(action).strip():
            actions.add(str(action).strip())

        ts = ev.get("timestamp")
        if ts and str(ts).strip():
            timestamps.append(str(ts).strip())

    timestamps.sort()

    return {
        "source_ips": sorted(list(source_ips)),
        "usernames": sorted(list(usernames)),
        "targeted_ports": sorted(
            list(ports),
            key=lambda x: (isinstance(x, str), x)
        ),
        "observed_event_types": sorted(list(event_types)),
        "observed_actions": sorted(list(actions)),
        "earliest_seen": (
            timestamps[0]
            if timestamps
            else "Not available in supplied evidence."
        ),
        "latest_seen": (
            timestamps[-1]
            if timestamps
            else "Not available in supplied evidence."
        ),
        "evidence_event_count": len(normalized_events)
    }


# ============================================================
# CHRONOLOGICAL ATTACK CHAIN / THREAT TIMELINE
# ============================================================

def build_incident_timeline(
    events: List[Dict]
) -> List[Dict]:
    """
    Construct a chronological attack chain timeline from correlated evidence.
    Computes relative time offset (T+Xs) and classifies attack progression stage.
    """

    normalized_events = normalize_events(events)
    if not normalized_events:
        return []

    parsed_events = []
    for ev in normalized_events:
        ts_raw = ev.get("timestamp")
        dt_obj = None
        if ts_raw:
            try:
                clean_ts = str(ts_raw).replace("Z", "+00:00")
                dt_obj = datetime.fromisoformat(clean_ts)
            except Exception:
                dt_obj = None
        parsed_events.append((dt_obj, ts_raw or "", ev))

    # Sort ascending chronologically
    parsed_events.sort(
        key=lambda item: (item[0] is None, item[0] or item[1])
    )

    base_dt = next(
        (item[0] for item in parsed_events if item[0] is not None),
        None
    )

    timeline = []
    for idx, (dt_obj, ts_str, ev) in enumerate(parsed_events, 1):
        if base_dt and dt_obj:
            delta_sec = int((dt_obj - base_dt).total_seconds())
            delta_str = (
                f"T+{delta_sec}s"
                if delta_sec >= 0
                else f"T{delta_sec}s"
            )
        else:
            delta_str = f"T+{idx}s"

        ev_type = str(ev.get("event_type", "")).upper()
        action = str(ev.get("action", "")).upper()
        status = str(ev.get("status", "")).upper()
        msg = ev.get("message", "")

        # Classify attack progression milestone
        if "PORT_SCAN" in ev_type or "SCAN" in action:
            stage = "Reconnaissance / Service Discovery"
        elif "POWERSHELL" in ev_type or "POWERSHELL" in action or "EXEC" in action:
            stage = "Execution / Suspicious Command"
        elif "PRIVILEGE" in ev_type or "SUDO" in action or "ADMIN" in action:
            stage = "Privilege Escalation Attempt"
        elif "LOGIN" in ev_type or "AUTH" in ev_type:
            if status == "SUCCESS":
                stage = "Initial Access / Account Compromise"
            else:
                stage = "Credential Access / Brute-Force Attempt"
        elif status in ["FAILED", "DENIED", "BLOCKED"]:
            stage = "Unauthorized Access Attempt"
        else:
            stage = "Correlated Threat Telemetry"

        timeline.append({
            "step": idx,
            "timestamp": ts_str or "Not available in supplied evidence.",
            "delta_str": delta_str,
            "stage": stage,
            "source_ip": ev.get("source_ip", "Unknown"),
            "username": ev.get("username") or "—",
            "event_type": ev.get("event_type", "UNKNOWN"),
            "action": ev.get("action", "UNKNOWN"),
            "status": ev.get("status", "UNKNOWN"),
            "port": ev.get("port"),
            "message": msg or f"{action} ({status})"
        })

    return timeline


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

    iocs = extract_incident_iocs(incident_data, normalized_events)
    timeline = build_incident_timeline(normalized_events)

    time_range_str = (
        f"between {iocs['earliest_seen']} and {iocs['latest_seen']}"
        if iocs["earliest_seen"] != iocs["latest_seen"]
        else f"at {iocs['earliest_seen']}"
    )

    what_happened = (
        f"SentinelX correlated {len(normalized_events)} security event(s) originating "
        f"from source {source_ip} demonstrating {alert_type} patterns {time_range_str}."
    )

    why_suspicious = (
        f"Observed behavior deviates from baseline security thresholds with {alert_type} activity "
        f"(Risk Score: {risk_score}/100, Severity: {severity}). The activity directly maps to "
        f"MITRE ATT&CK technique {mitre} identified by the SentinelX detection engine."
    )

    verification_guidance = [
        "Verify source IP containment status in the SentinelX Active Blocklist registry.",
        "Inspect subsequent live telemetry feed to confirm 0 ongoing attempts from the quarantined source.",
        "Check identity logs for affected usernames to ensure credentials remain secure.",
        "When containment verification is complete or benign activity confirmed, use Reversible Containment to unblock."
    ]

    return {
        "incident_summary": (
            f"SentinelX detected {alert_type} activity "
            f"from {source_ip} based on the supplied security evidence."
        ),

        "what_happened": what_happened,

        "why_suspicious": why_suspicious,

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

        "verification_guidance": verification_guidance,

        "evidence_count": len(normalized_events),

        "iocs": iocs,

        "timeline": timeline,

        "ai_source": "Rule-Based Fallback"
    }


def extract_json_from_text(text: str) -> Dict[str, Any]:
    """
    Safely extract and parse JSON from LLM outputs.
    Handles Markdown code fences (```json ... ```), preamble commentary,
    and trailing text.
    """
    if not text or not isinstance(text, str):
        raise ValueError("Empty or invalid response received from model.")

    clean_text = text.strip()

    # Pattern 1: Look for markdown code fence with json or generic
    code_block_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", clean_text, re.IGNORECASE)
    if code_block_match:
        block_content = code_block_match.group(1).strip()
        try:
            return json.loads(block_content)
        except json.JSONDecodeError:
            pass

    # Pattern 2: Find outermost matching curly braces { ... }
    first_brace = clean_text.find("{")
    last_brace = clean_text.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        candidate = clean_text[first_brace:last_brace + 1].strip()
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass

    # Pattern 3: Direct parsing fallback
    return json.loads(clean_text)


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

    "what_happened": "Factual narrative of what occurred based strictly on the supplied evidence.",

    "why_suspicious": "Explain why this activity is suspicious based only on the supplied incident metrics and events.",

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
    ],

    "verification_guidance": [
        "Verification step 1 to validate containment and recovery",
        "Verification step 2"
    ]
}}
"""

    response = client.models.generate_content(
        model=GEMINI_MODEL,
        contents=prompt
    )

    result = extract_json_from_text(response.text)

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

    # Safe defaults for enhanced workflow fields if omitted
    if "what_happened" not in result or not result["what_happened"]:
        result["what_happened"] = result["incident_summary"]

    if "why_suspicious" not in result or not result["why_suspicious"]:
        result["why_suspicious"] = result["severity_explanation"]

    if (
        "verification_guidance" not in result
        or not isinstance(result["verification_guidance"], list)
    ):
        result["verification_guidance"] = [
            "Verify host IP containment status in SentinelX Active Blocklist.",
            "Monitor incoming telemetry to confirm 0 ongoing attempts from source.",
            "Review identity audit logs for targeted usernames to confirm safety."
        ]

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
    Observable IOCs and attack chain timeline are always attached.
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

    iocs = extract_incident_iocs(
        incident_data,
        normalized_events
    )

    timeline = build_incident_timeline(
        normalized_events
    )

    try:

        analysis = generate_gemini_analysis(
            incident_data,
            normalized_events
        )

        analysis["context"] = context
        analysis["iocs"] = iocs
        analysis["timeline"] = timeline

        return analysis

    except Exception as error:

        fallback = generate_rule_based_analysis(
            incident_data,
            normalized_events
        )

        fallback["context"] = context
        fallback["iocs"] = iocs
        fallback["timeline"] = timeline
        fallback["ai_error"] = str(error)

        return fallback

