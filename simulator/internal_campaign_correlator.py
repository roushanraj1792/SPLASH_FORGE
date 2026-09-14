"""
Internal Campaign Correlation Engine — Deterministic In-Memory Layer
====================================================================
Part of the SentinelX Detection & Incident Response Platform.

Role:
  Correlates related individual security events into unified, multi-stage
  campaigns. Analyzes temporal proximity, multi-source distribution, and
  attack lifecycle progression across authentication, execution, and privilege
  stages.

Safety & Operational Boundary Rules:
  - ZERO network traffic: no HTTP requests, no sockets, no external connections.
  - ZERO database modifications: does not read/write to database.
  - ZERO automated response actions: no firewall changes, no IP blocking.
  - ZERO external service calls: no Telegram, no Gemini, no external APIs.
  - Bounded in-memory processing: hard limit on input events (max 1000).
  - Deterministic output: identical event collections yield identical campaign results.
"""

from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import ipaddress
from typing import Any, Dict, List, Optional, Sequence, Union


# ------------------------------------------------------------------------------
# CONSTANTS & CONSTRAINTS
# ------------------------------------------------------------------------------

MAX_EVENTS_BOUND = 1000
DEFAULT_CORRELATION_WINDOW_MINUTES = 30.0

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

# MITRE Technique Mapping for Recognized Stages
STAGE_DEFINITIONS = {
    "authentication_attack": {
        "mitre_technique": "T1110",
        "display_name": "Authentication Attack (Brute Force)",
        "priority": 1,
    },
    "successful_authentication": {
        "mitre_technique": "T1078",
        "display_name": "Compromised Authentication (Valid Accounts)",
        "priority": 2,
    },
    "suspicious_powershell": {
        "mitre_technique": "T1059.001",
        "display_name": "Suspicious Execution (PowerShell)",
        "priority": 3,
    },
    "privilege_escalation": {
        "mitre_technique": "T1068",
        "display_name": "Privilege Escalation",
        "priority": 4,
    },
    "reconnaissance": {
        "mitre_technique": "T1046",
        "display_name": "Network Reconnaissance (Port Scan)",
        "priority": 0,
    },
}


# ------------------------------------------------------------------------------
# EXCEPTIONS
# ------------------------------------------------------------------------------

class CampaignCorrelationError(ValueError):
    """Raised when correlator inputs are malformed or exceed safety limits."""
    pass


# ------------------------------------------------------------------------------
# VALIDATION UTILITIES
# ------------------------------------------------------------------------------

def parse_iso_timestamp(ts: Any) -> datetime:
    """Parse and normalize ISO-8601 timestamp string into UTC datetime."""
    if not isinstance(ts, str) or not ts.strip():
        raise CampaignCorrelationError(f"Invalid timestamp value: {repr(ts)}")
    try:
        cleaned = ts.strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception as exc:
        raise CampaignCorrelationError(f"Failed to parse timestamp '{ts}': {exc}") from exc


def validate_ip_address(ip_str: Any) -> str:
    """Validate that source IP is a syntactically valid IPv4 address."""
    if not isinstance(ip_str, str) or not ip_str.strip():
        raise CampaignCorrelationError(f"Invalid source_ip: {repr(ip_str)}")
    cleaned = ip_str.strip()
    try:
        addr = ipaddress.ip_address(cleaned)
        if not isinstance(addr, ipaddress.IPv4Address):
            raise CampaignCorrelationError(f"Only IPv4 addresses supported: '{ip_str}'")
        return cleaned
    except ValueError as exc:
        raise CampaignCorrelationError(f"Malformed IPv4 address '{ip_str}': {exc}") from exc


def validate_event_dict(event: Any, index: int = 0) -> None:
    """Strictly validate a single event dictionary against SentinelX schema."""
    if not isinstance(event, dict):
        raise CampaignCorrelationError(f"Event at index {index} must be a dictionary, got: {type(event).__name__}")

    # Check required fields
    for field in ("timestamp", "source_ip", "event_type", "status"):
        if field not in event or event[field] is None:
            raise CampaignCorrelationError(f"Event at index {index} missing required field: '{field}'")

    # Validate timestamp
    parse_iso_timestamp(event["timestamp"])

    # Validate IP
    validate_ip_address(event["source_ip"])

    # Validate event_type & status
    event_type = str(event["event_type"]).strip().upper()
    if event_type not in ALLOWED_EVENT_TYPES:
        raise CampaignCorrelationError(f"Event at index {index} has unsupported event_type: '{event['event_type']}'")

    status = str(event["status"]).strip().upper()
    if status not in ALLOWED_STATUS:
        raise CampaignCorrelationError(f"Event at index {index} has unsupported status: '{event['status']}'")


def validate_events_collection(events: Any, max_bound: int = MAX_EVENTS_BOUND) -> None:
    """Validate the input collection of events."""
    if events is None:
        raise CampaignCorrelationError("Events collection cannot be None.")

    if not isinstance(events, (list, tuple)):
        raise CampaignCorrelationError(f"Events must be a list or tuple, got: {type(events).__name__}")

    if len(events) > max_bound:
        raise CampaignCorrelationError(
            f"Event collection size ({len(events)}) exceeds maximum bounded limit ({max_bound})."
        )

    for i, event in enumerate(events):
        validate_event_dict(event, index=i)


# ------------------------------------------------------------------------------
# STAGE CLASSIFICATION
# ------------------------------------------------------------------------------

def classify_event_stage(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Classify an event into a recognized attack lifecycle stage.
    Returns stage definition dictionary or None if unclassified.
    """
    event_type = str(event.get("event_type", "")).strip().upper()
    status = str(event.get("status", "")).strip().upper()
    action = str(event.get("action", "")).strip().upper()
    message = str(event.get("message", "")).lower()

    # 1. Authentication Attacks (Failed login attempts)
    if event_type == "LOGIN" and status == "FAILED":
        return {
            "stage_key": "authentication_attack",
            **STAGE_DEFINITIONS["authentication_attack"]
        }

    # 2. Compromised / Successful Authentication
    if event_type == "LOGIN" and status == "SUCCESS":
        return {
            "stage_key": "successful_authentication",
            **STAGE_DEFINITIONS["successful_authentication"]
        }

    # 3. Suspicious PowerShell Execution
    if event_type == "POWERSHELL":
        return {
            "stage_key": "suspicious_powershell",
            **STAGE_DEFINITIONS["suspicious_powershell"]
        }

    # 4. Privilege Escalation
    if event_type in ("PRIVILEGE_CHANGE", "PRIVILEGE_ESCALATION") or "PRIVILEGE" in action:
        return {
            "stage_key": "privilege_escalation",
            **STAGE_DEFINITIONS["privilege_escalation"]
        }

    # 5. Reconnaissance / Port Scan
    if event_type in ("NETWORK_CONNECTION", "CONNECTION_ATTEMPT"):
        return {
            "stage_key": "reconnaissance",
            **STAGE_DEFINITIONS["reconnaissance"]
        }

    return None


# ------------------------------------------------------------------------------
# CORRELATION ENGINE
# ------------------------------------------------------------------------------

def _build_stage_summary(
    stage_key: str,
    stage_events: List[Dict[str, Any]],
    stage_index: int
) -> Dict[str, Any]:
    """Build structured summary for an individual correlated stage."""
    info = STAGE_DEFINITIONS.get(stage_key, {
        "mitre_technique": "UNKNOWN",
        "display_name": stage_key.replace("_", " ").title(),
        "priority": 99,
    })

    # Sort stage events chronologically
    sorted_evs = sorted(stage_events, key=lambda e: parse_iso_timestamp(e["timestamp"]))

    sources = sorted(list({ev["source_ip"] for ev in sorted_evs}))
    event_ids = [ev["id"] for ev in sorted_evs if ev.get("id") is not None]
    first_seen = sorted_evs[0]["timestamp"]
    last_seen = sorted_evs[-1]["timestamp"]

    # Generate explainable summary
    count = len(sorted_evs)
    src_repr = ", ".join(sources[:3]) + (f" (+{len(sources)-3} more)" if len(sources) > 3 else "")
    summary = f"{count} event(s) observed for {info['display_name']} from {src_repr}"

    return {
        "stage_index": stage_index,
        "stage_key": stage_key,
        "display_name": info["display_name"],
        "mitre_technique": info["mitre_technique"],
        "event_count": count,
        "event_ids": event_ids,
        "sources": sources,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "summary": summary
    }


def _determine_campaign_type(sources: List[str], stages: List[Dict[str, Any]]) -> str:
    """Determine high-level architectural classification of the campaign."""
    is_multi_source = len(sources) > 1
    is_multi_stage = len(stages) > 1

    if is_multi_source and is_multi_stage:
        return "MULTI_STAGE_DISTRIBUTED"
    elif is_multi_stage and not is_multi_source:
        return "MULTI_STAGE_FOCUSED"
    elif is_multi_source and not is_multi_stage:
        return "SINGLE_STAGE_DISTRIBUTED"
    else:
        return "SINGLE_STAGE_FOCUSED"


def _generate_deterministic_campaign_id(
    campaign_index: int,
    first_seen: str,
    sources: List[str]
) -> str:
    """Generate a deterministic, clean campaign identifier."""
    # Seed with sources and timestamp for uniqueness across independent batches
    payload = f"{first_seen}_{'_'.join(sorted(sources))}".encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()[:8].upper()
    return f"CAMP-CORR-{campaign_index:03d}-{digest}"


def correlate_campaigns(
    events: Sequence[Dict[str, Any]],
    time_window_minutes: float = DEFAULT_CORRELATION_WINDOW_MINUTES,
    campaign_id_prefix: Optional[str] = None,
    max_events_bound: int = MAX_EVENTS_BOUND
) -> List[Dict[str, Any]]:
    """
    Correlate security events into structured, deterministic campaigns.

    Parameters:
      events: Sequence of SentinelX-compliant event dictionaries.
      time_window_minutes: Maximum time gap (minutes) between consecutive events
                           to consider them part of the same operational campaign.
      campaign_id_prefix: Optional custom prefix for generated campaign IDs.
      max_events_bound: Safety upper bound on total events processed.

    Returns:
      List of correlated campaign dictionaries, ordered chronologically.
    """
    validate_events_collection(events, max_bound=max_events_bound)

    if not events:
        return []

    if time_window_minutes <= 0:
        raise CampaignCorrelationError("time_window_minutes must be positive.")

    # 1. Sort events chronologically (deterministic sort)
    # Tie-breaking keys: id (if present), source_ip, event_type
    def sort_key(ev: Dict[str, Any]):
        ts = parse_iso_timestamp(ev["timestamp"])
        ev_id = ev.get("id") if isinstance(ev.get("id"), (int, str)) else ""
        return (ts, str(ev_id), str(ev.get("source_ip", "")), str(ev.get("event_type", "")))

    sorted_events = sorted(events, key=sort_key)

    # 2. Cluster events into temporal campaign clusters
    # Two consecutive events belong to the same cluster if delta <= time_window_minutes
    clusters: List[List[Dict[str, Any]]] = []
    current_cluster: List[Dict[str, Any]] = [sorted_events[0]]

    max_gap_seconds = time_window_minutes * 60.0

    for ev in sorted_events[1:]:
        prev_time = parse_iso_timestamp(current_cluster[-1]["timestamp"])
        curr_time = parse_iso_timestamp(ev["timestamp"])
        gap_seconds = (curr_time - prev_time).total_seconds()

        if gap_seconds <= max_gap_seconds:
            current_cluster.append(ev)
        else:
            clusters.append(current_cluster)
            current_cluster = [ev]

    if current_cluster:
        clusters.append(current_cluster)

    # 3. Analyze each cluster into a full Campaign structure
    campaigns: List[Dict[str, Any]] = []

    for idx, cluster in enumerate(clusters, start=1):
        # Group cluster events by recognized stages
        stages_map = defaultdict(list)
        unclassified_events = []

        for ev in cluster:
            classification = classify_event_stage(ev)
            if classification:
                stages_map[classification["stage_key"]].append(ev)
            else:
                unclassified_events.append(ev)

        # Order stages according to natural attack progression
        # Order: reconnaissance -> authentication_attack -> successful_authentication -> suspicious_powershell -> privilege_escalation
        stage_order_keys = [
            "reconnaissance",
            "authentication_attack",
            "successful_authentication",
            "suspicious_powershell",
            "privilege_escalation"
        ]

        ordered_stages: List[Dict[str, Any]] = []
        stage_idx = 1
        for skey in stage_order_keys:
            if skey in stages_map:
                ordered_stages.append(
                    _build_stage_summary(skey, stages_map[skey], stage_idx)
                )
                stage_idx += 1

        # Any extra stages not in standard order
        for skey, s_evs in sorted(stages_map.items()):
            if skey not in stage_order_keys:
                ordered_stages.append(
                    _build_stage_summary(skey, s_evs, stage_idx)
                )
                stage_idx += 1

        cluster_sources = sorted(list({ev["source_ip"] for ev in cluster}))
        first_observed = cluster[0]["timestamp"]
        last_observed = cluster[-1]["timestamp"]
        t_first = parse_iso_timestamp(first_observed)
        t_last = parse_iso_timestamp(last_observed)
        duration_sec = max(0.0, (t_last - t_first).total_seconds())

        techniques = sorted(list({
            s["mitre_technique"] for s in ordered_stages if s["mitre_technique"] != "UNKNOWN"
        }))

        corr_type = _determine_campaign_type(cluster_sources, ordered_stages)

        if campaign_id_prefix:
            c_id = f"{campaign_id_prefix}-{idx:03d}"
        else:
            c_id = _generate_deterministic_campaign_id(idx, first_observed, cluster_sources)

        # Build descriptive name & explainable reason
        stage_names = [s["display_name"] for s in ordered_stages]
        if corr_type == "MULTI_STAGE_DISTRIBUTED":
            campaign_name = "Distributed Multi-Stage Compromise Campaign"
            reason = (
                f"Coordinated {len(ordered_stages)}-stage attack sequence observed across "
                f"{len(cluster_sources)} botnet nodes spanning {duration_sec:.1f}s. "
                f"Progression: {' -> '.join(stage_names)}."
            )
        elif corr_type == "MULTI_STAGE_FOCUSED":
            campaign_name = "Targeted Multi-Stage Attack Sequence"
            reason = (
                f"Multi-stage intrusion chain observed from single source {cluster_sources[0]} "
                f"spanning {duration_sec:.1f}s. Progression: {' -> '.join(stage_names)}."
            )
        elif corr_type == "SINGLE_STAGE_DISTRIBUTED":
            campaign_name = f"Distributed {stage_names[0] if stage_names else 'Activity'} Campaign"
            reason = (
                f"Coordinated single-stage activity detected across {len(cluster_sources)} sources "
                f"within {duration_sec:.1f}s window."
            )
        else:
            campaign_name = f"Focused {stage_names[0] if stage_names else 'Activity'} Campaign"
            reason = (
                f"Single-source activity observed from {cluster_sources[0]} "
                f"with {len(cluster)} event(s) across {duration_sec:.1f}s."
            )

        campaign_record = {
            "campaign_id": c_id,
            "campaign_name": campaign_name,
            "correlation_type": corr_type,
            "event_count": len(cluster),
            "stage_count": len(ordered_stages),
            "sources": cluster_sources,
            "techniques": techniques,
            "ordered_stages": ordered_stages,
            "first_observed": first_observed,
            "last_observed": last_observed,
            "duration_seconds": duration_sec,
            "correlation_reason": reason,
            "unclassified_event_count": len(unclassified_events),
        }
        campaigns.append(campaign_record)

    return campaigns


def correlate_single_campaign(
    events: Sequence[Dict[str, Any]],
    time_window_minutes: float = DEFAULT_CORRELATION_WINDOW_MINUTES,
    campaign_id_prefix: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Convenience helper for situations where a single cohesive campaign is expected.
    Returns the largest/primary campaign dictionary, or None if no events.
    """
    campaigns = correlate_campaigns(
        events=events,
        time_window_minutes=time_window_minutes,
        campaign_id_prefix=campaign_id_prefix
    )
    if not campaigns:
        return None

    # Return campaign with highest event count
    return max(campaigns, key=lambda c: c["event_count"])
