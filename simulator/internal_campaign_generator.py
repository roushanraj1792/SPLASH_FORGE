"""
Internal Synthetic Campaign Engine — Bounded In-Memory Generator
=================================================================
Part of the SentinelX Detection & Incident Response Platform.

Role:
  Simulates a coordinated, multi-stage, distributed botnet-style security
  campaign INSIDE SentinelX without requiring external VMs (Kali / Web-01).

Safety & Security Boundary Rules:
  - ZERO real network traffic: no HTTP requests, no sockets, no external connections.
  - ZERO localhost attack traffic, no scanning, no real brute-force, no DoS.
  - ZERO malware, exploits, shellcode, or destructive operations.
  - All telemetry events are pure in-memory Python dictionaries strictly conforming
    to the SentinelX security event schema.
  - Synthetic source IPs are guaranteed to belong to safe lab/documentation ranges
    (RFC 5737 TEST-NET or private RFC 1918 subnets) and must NEVER be contacted.
  - Deterministic generation: identical parameters yield identical telemetry events.
  - Bounded campaign size: strictly enforced upper limit of 200 events.
  - Default-safe / dry-run mode: does not write to the database automatically.
"""

from datetime import datetime, timedelta, timezone
import ipaddress
from typing import Any, Dict, List, Optional, Tuple, Union


# ------------------------------------------------------------------------------
# SAFETY & BOUNDARY CONSTANTS
# ------------------------------------------------------------------------------

MIN_CAMPAIGN_EVENTS = 4
MAX_CAMPAIGN_EVENTS = 200
DEFAULT_CAMPAIGN_EVENTS = 24
DEFAULT_TIME_STEP_SECONDS = 5.0

# RFC 5737 (TEST-NET-1, TEST-NET-2, TEST-NET-3) and RFC 1918 Private Ranges
SAFE_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1 (Documentation/Lab)
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2 (Documentation/Lab)
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3 (Documentation/Lab)
    ipaddress.ip_network("10.0.0.0/8"),        # Private RFC 1918
    ipaddress.ip_network("172.16.0.0/12"),     # Private RFC 1918
    ipaddress.ip_network("192.168.0.0/16"),    # Private RFC 1918
]

# Standard synthetic bot nodes in RFC 5737 TEST-NET-2
DEFAULT_BOT_NODES = {
    "node_a": "198.51.100.11",  # Authentication attack node (Brute force failed logins)
    "node_b": "198.51.100.12",  # Credential access node (Successful logins)
    "node_c": "198.51.100.13",  # Execution node (Suspicious PowerShell)
    "node_d": "198.51.100.14",  # Privilege escalation node (Privilege change events)
}

# Standard reference timestamp for deterministic generation
DEFAULT_REFERENCE_TIME = datetime(2026, 9, 15, 1, 0, 0, tzinfo=timezone.utc)

# Allowed SentinelX event types & status values (aligned with api.py & database.py)
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

ALLOWED_SEVERITIES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}


# ------------------------------------------------------------------------------
# EXCEPTIONS
# ------------------------------------------------------------------------------

class SecurityViolation(ValueError):
    """Raised when an attempt is made to use unsafe, public, or unauthorized addresses."""
    pass


class CampaignConfigurationError(ValueError):
    """Raised when invalid campaign parameters or stage counts are specified."""
    pass


# ------------------------------------------------------------------------------
# SAFETY VALIDATORS
# ------------------------------------------------------------------------------

def is_safe_lab_ip(ip_str: str) -> bool:
    """
    Validate that an IP address belongs strictly to an authorized lab or documentation subnet.
    Rejects public routable addresses, loopback, multicast, and broadcast.
    """
    if not isinstance(ip_str, str) or not ip_str.strip():
        return False

    try:
        addr = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False

    # Must be IPv4
    if not isinstance(addr, ipaddress.IPv4Address):
        return False

    # Strictly reject loopback, multicast, unspecified (0.0.0.0)
    if addr.is_loopback or addr.is_multicast or addr.is_unspecified or addr.is_reserved:
        return False

    # Must be contained within one of the designated safe lab/private subnets
    return any(addr in net for net in SAFE_NETWORKS)


def validate_source_ip(ip_str: str) -> str:
    """
    Ensure the provided IP address is safe. Raises SecurityViolation if unsafe.
    """
    cleaned = str(ip_str).strip()
    if not is_safe_lab_ip(cleaned):
        raise SecurityViolation(
            f"SECURITY VIOLATION: Source IP '{ip_str}' is prohibited. "
            "Only designated safe lab subnets (RFC 5737 TEST-NET 192.0.2.0/24, "
            "198.51.100.0/24, 203.0.113.0/24 or RFC 1918 private subnets) are permitted. "
            "Public routable IPs and loopback addresses are strictly prohibited."
        )
    return cleaned


def validate_event_schema(event: Dict[str, Any]) -> None:
    """
    Strictly validate that an event conforms to the SentinelX ingestion schema.
    Raises ValueError if any field violates SentinelX constraints.
    """
    if not isinstance(event, dict):
        raise ValueError("Event must be a dictionary.")

    # Required fields
    for req in ("timestamp", "source_ip", "event_type", "action", "status", "message", "severity"):
        if req not in event:
            raise ValueError(f"Missing required event field: '{req}'.")

    # Type & status validation
    if event["event_type"] not in ALLOWED_EVENT_TYPES:
        raise ValueError(f"Unsupported event_type: '{event['event_type']}'.")

    if event["status"] not in ALLOWED_STATUS:
        raise ValueError(f"Unsupported status: '{event['status']}'.")

    if str(event["severity"]).upper() not in ALLOWED_SEVERITIES:
        raise ValueError(f"Unsupported severity: '{event['severity']}'.")

    # IP safety validation
    validate_source_ip(event["source_ip"])

    # String length constraints (from api.py)
    string_limits = {
        "username": 128,
        "action": 128,
        "message": 2048,
        "severity": 32,
        "timestamp": 64,
    }
    for field, max_len in string_limits.items():
        val = event.get(field)
        if val is not None and len(str(val)) > max_len:
            raise ValueError(f"Field '{field}' exceeds max length of {max_len} characters.")

    # Port constraints
    port = event.get("port")
    if port is not None:
        if not isinstance(port, int) or not (1 <= port <= 65535):
            raise ValueError(f"Invalid port: {port}. Must be integer between 1 and 65535, or None.")


# ------------------------------------------------------------------------------
# STAGE EVENT BUILDERS
# ------------------------------------------------------------------------------

def _build_auth_attack_events(
    source_ip: str,
    count: int,
    start_time: datetime,
    step_seconds: float,
    target_user: str = "admin"
) -> Tuple[List[Dict[str, Any]], datetime]:
    """
    Stage 1: Distributed Authentication Attacks (Brute Force / T1110)
    Generates failed login attempts that trigger SentinelX detect_brute_force (threshold >= 5).
    """
    events = []
    current_time = start_time
    for i in range(1, count + 1):
        event = {
            "timestamp": current_time.isoformat(),
            "source_ip": source_ip,
            "username": target_user,
            "event_type": "LOGIN",
            "action": "LOGIN",
            "status": "FAILED",
            "message": f"Synthetic campaign authentication failure #{i} for user '{target_user}'",
            "severity": "LOW",
            "port": None
        }
        events.append(event)
        current_time += timedelta(seconds=step_seconds)
    return events, current_time


def _build_successful_auth_events(
    source_ip: str,
    count: int,
    start_time: datetime,
    step_seconds: float,
    target_user: str = "admin"
) -> Tuple[List[Dict[str, Any]], datetime]:
    """
    Stage 2: Compromised / Suspicious Authentication (T1078)
    Generates successful login events that trigger SentinelX detect_suspicious_authentication (threshold >= 5).
    """
    events = []
    current_time = start_time
    for i in range(1, count + 1):
        event = {
            "timestamp": current_time.isoformat(),
            "source_ip": source_ip,
            "username": target_user,
            "event_type": "LOGIN",
            "action": "LOGIN",
            "status": "SUCCESS",
            "message": f"Synthetic campaign successful login #{i} for user '{target_user}'",
            "severity": "LOW",
            "port": None
        }
        events.append(event)
        current_time += timedelta(seconds=step_seconds)
    return events, current_time


def _build_suspicious_powershell_events(
    source_ip: str,
    count: int,
    start_time: datetime,
    step_seconds: float,
    username: str = "svc_deployer"
) -> Tuple[List[Dict[str, Any]], datetime]:
    """
    Stage 3: Suspicious Execution (PowerShell / T1059.001)
    Generates PowerShell events containing known suspicious indicators (ExecutionPolicy Bypass, EncodedCommand).
    Triggers SentinelX detect_suspicious_powershell (threshold >= 2).
    """
    patterns = [
        "PowerShell execution detected with ExecutionPolicy Bypass",
        "PowerShell command detected with EncodedCommand payload",
        "PowerShell download cradle detected: DownloadString from internal mirror",
        "PowerShell execution invoking hidden IEX expression"
    ]
    events = []
    current_time = start_time
    for i in range(1, count + 1):
        pattern_text = patterns[(i - 1) % len(patterns)]
        event = {
            "timestamp": current_time.isoformat(),
            "source_ip": source_ip,
            "username": username,
            "event_type": "POWERSHELL",
            "action": "POWERSHELL",
            "status": "SUCCESS",
            "message": f"Synthetic campaign #{i}: {pattern_text}",
            "severity": "HIGH",
            "port": None
        }
        events.append(event)
        current_time += timedelta(seconds=step_seconds)
    return events, current_time


def _build_privilege_escalation_events(
    source_ip: str,
    count: int,
    start_time: datetime,
    step_seconds: float,
    username: str = "svc_deployer"
) -> Tuple[List[Dict[str, Any]], datetime]:
    """
    Stage 4: Privilege Change / Escalation Activity (T1068)
    Generates privilege modification events that trigger SentinelX detect_privilege_escalation (threshold >= 3).
    """
    events = []
    current_time = start_time
    for i in range(1, count + 1):
        event = {
            "timestamp": current_time.isoformat(),
            "source_ip": source_ip,
            "username": username,
            "event_type": "PRIVILEGE_CHANGE",
            "action": "PRIVILEGE_ESCALATION",
            "status": "SUCCESS",
            "message": f"Synthetic campaign privilege elevation attempt #{i} granted administrative role",
            "severity": "HIGH",
            "port": None
        }
        events.append(event)
        current_time += timedelta(seconds=step_seconds)
    return events, current_time


# ------------------------------------------------------------------------------
# CORE GENERATOR ENGINE
# ------------------------------------------------------------------------------

def generate_campaign(
    campaign_id: str = "CAMP-BOT-001",
    scenario: str = "distributed-botnet",
    total_events: int = DEFAULT_CAMPAIGN_EVENTS,
    bot_nodes: Optional[Dict[str, str]] = None,
    base_time: Optional[Union[datetime, str]] = None,
    time_step_seconds: float = DEFAULT_TIME_STEP_SECONDS,
    dry_run: bool = True,
    strict_limits: bool = True
) -> Dict[str, Any]:
    """
    Generate a deterministic, safe, bounded synthetic campaign dataset.

    Parameters:
      campaign_id: Identifier for the campaign (default 'CAMP-BOT-001').
      scenario: Scenario profile ('distributed-botnet', 'auth-attacks-only', 'powershell-only', 'privilege-only').
      total_events: Total number of events to generate (clamped between 4 and 200).
      bot_nodes: Optional mapping of bot node identifiers to synthetic IP addresses.
                 All IPs must be valid RFC 5737 or RFC 1918 safe addresses.
      base_time: Reference starting timestamp (datetime or ISO-8601 string).
                 Defaults to 2026-09-15T01:00:00+00:00 for determinism.
      time_step_seconds: Seconds between consecutive events (default 5.0s).
      dry_run: Default-safe flag (default True). Generates data in-memory without persistence.
      strict_limits: If True, raises CampaignConfigurationError when event count exceeds bounds.
                     If False, clamps event count into [MIN_CAMPAIGN_EVENTS, MAX_CAMPAIGN_EVENTS].

    Returns:
      Dict with campaign metadata, stage summaries, and the list of SentinelX-compliant event dictionaries.
    """
    # 1. Parameter Validation: total_events
    if not isinstance(total_events, int) or isinstance(total_events, bool):
        raise CampaignConfigurationError(f"total_events must be an integer. Got: {type(total_events).__name__}")

    if strict_limits:
        if total_events < MIN_CAMPAIGN_EVENTS:
            raise CampaignConfigurationError(
                f"total_events ({total_events}) is below minimum allowed ({MIN_CAMPAIGN_EVENTS})."
            )
        if total_events > MAX_CAMPAIGN_EVENTS:
            raise CampaignConfigurationError(
                f"total_events ({total_events}) exceeds maximum bounded limit ({MAX_CAMPAIGN_EVENTS})."
            )
        actual_count = total_events
    else:
        actual_count = max(MIN_CAMPAIGN_EVENTS, min(total_events, MAX_CAMPAIGN_EVENTS))

    # 2. Parameter Validation: scenario
    supported_scenarios = {
        "distributed-botnet",
        "auth-attacks-only",
        "powershell-only",
        "privilege-only",
    }
    if scenario not in supported_scenarios:
        raise CampaignConfigurationError(
            f"Unknown scenario: '{scenario}'. Supported: {sorted(list(supported_scenarios))}"
        )

    # 3. Node Configuration & Safety Validation
    nodes = dict(DEFAULT_BOT_NODES)
    if bot_nodes:
        if not isinstance(bot_nodes, dict):
            raise CampaignConfigurationError("bot_nodes must be a dictionary.")
        for k, v in bot_nodes.items():
            nodes[k] = validate_source_ip(v)
    else:
        for ip in nodes.values():
            validate_source_ip(ip)

    # 4. Reference Time Setup
    if base_time is None:
        start_dt = DEFAULT_REFERENCE_TIME
    elif isinstance(base_time, datetime):
        start_dt = base_time if base_time.tzinfo else base_time.replace(tzinfo=timezone.utc)
    elif isinstance(base_time, str):
        try:
            start_dt = datetime.fromisoformat(base_time.replace("Z", "+00:00"))
        except (ValueError, TypeError) as exc:
            raise CampaignConfigurationError(f"Invalid ISO-8601 base_time: '{base_time}'") from exc
    else:
        raise CampaignConfigurationError("base_time must be None, a datetime object, or an ISO-8601 string.")

    if not isinstance(time_step_seconds, (int, float)) or time_step_seconds <= 0:
        raise CampaignConfigurationError("time_step_seconds must be a positive number.")

    # 5. Build Scenario Plan
    events: List[Dict[str, Any]] = []
    stages_summary: List[Dict[str, Any]] = []
    current_dt = start_dt

    if scenario == "distributed-botnet":
        # Multi-stage coordinated distributed campaign:
        # Minimum required to trigger all 4 detections:
        # Stage 1: Brute Force (>= 5 failed logins)
        # Stage 2: Suspicious Auth (>= 5 successful logins)
        # Stage 3: Suspicious PowerShell (>= 2 events)
        # Stage 4: Privilege Escalation (>= 3 events)
        # Base requirements sum: 15 events.
        
        # Distribute actual_count proportionally across the 4 stages
        weight_s1 = 0.35  # Auth attack
        weight_s2 = 0.25  # Suspicious auth
        weight_s3 = 0.20  # PowerShell
        weight_s4 = 0.20  # Privilege escalation

        c_s1 = max(1, int(actual_count * weight_s1))
        c_s2 = max(1, int(actual_count * weight_s2))
        c_s3 = max(1, int(actual_count * weight_s3))
        c_s4 = max(1, actual_count - (c_s1 + c_s2 + c_s3))

        # Adjust to ensure exact sum matches actual_count
        while (c_s1 + c_s2 + c_s3 + c_s4) < actual_count:
            c_s1 += 1
        while (c_s1 + c_s2 + c_s3 + c_s4) > actual_count and c_s4 > 1:
            c_s4 -= 1

        # Stage 1: Distributed Authentication Attacks
        ev_s1, current_dt = _build_auth_attack_events(
            nodes["node_a"], c_s1, current_dt, time_step_seconds, target_user="admin"
        )
        events.extend(ev_s1)
        stages_summary.append({
            "stage": "authentication_attack",
            "source_ip": nodes["node_a"],
            "event_count": len(ev_s1),
            "description": "Distributed failed authentication attempts (T1110)"
        })

        # Stage 2: Compromised / Successful Authentication
        ev_s2, current_dt = _build_successful_auth_events(
            nodes["node_b"], c_s2, current_dt, time_step_seconds, target_user="admin"
        )
        events.extend(ev_s2)
        stages_summary.append({
            "stage": "successful_authentication",
            "source_ip": nodes["node_b"],
            "event_count": len(ev_s2),
            "description": "Compromised account credential access (T1078)"
        })

        # Stage 3: Suspicious PowerShell Execution
        ev_s3, current_dt = _build_suspicious_powershell_events(
            nodes["node_c"], c_s3, current_dt, time_step_seconds, username="svc_deployer"
        )
        events.extend(ev_s3)
        stages_summary.append({
            "stage": "suspicious_powershell",
            "source_ip": nodes["node_c"],
            "event_count": len(ev_s3),
            "description": "PowerShell execution policy bypass & encoded payloads (T1059.001)"
        })

        # Stage 4: Privilege Escalation
        ev_s4, current_dt = _build_privilege_escalation_events(
            nodes["node_d"], c_s4, current_dt, time_step_seconds, username="svc_deployer"
        )
        events.extend(ev_s4)
        stages_summary.append({
            "stage": "privilege_escalation",
            "source_ip": nodes["node_d"],
            "event_count": len(ev_s4),
            "description": "Unauthorized administrative privilege assignment (T1068)"
        })

    elif scenario == "auth-attacks-only":
        ev_s1, current_dt = _build_auth_attack_events(
            nodes["node_a"], actual_count, current_dt, time_step_seconds, target_user="admin"
        )
        events.extend(ev_s1)
        stages_summary.append({
            "stage": "authentication_attack",
            "source_ip": nodes["node_a"],
            "event_count": len(ev_s1),
            "description": "Pure failed login attack flood"
        })

    elif scenario == "powershell-only":
        ev_s3, current_dt = _build_suspicious_powershell_events(
            nodes["node_c"], actual_count, current_dt, time_step_seconds, username="svc_deployer"
        )
        events.extend(ev_s3)
        stages_summary.append({
            "stage": "suspicious_powershell",
            "source_ip": nodes["node_c"],
            "event_count": len(ev_s3),
            "description": "Pure PowerShell execution sequence"
        })

    elif scenario == "privilege-only":
        ev_s4, current_dt = _build_privilege_escalation_events(
            nodes["node_d"], actual_count, current_dt, time_step_seconds, username="svc_deployer"
        )
        events.extend(ev_s4)
        stages_summary.append({
            "stage": "privilege_escalation",
            "source_ip": nodes["node_d"],
            "event_count": len(ev_s4),
            "description": "Pure privilege escalation sequence"
        })

    # 6. Validate every produced event against the SentinelX schema
    for ev in events:
        validate_event_schema(ev)

    unique_ips = sorted(list({ev["source_ip"] for ev in events}))

    return {
        "campaign_id": campaign_id,
        "scenario": scenario,
        "dry_run": dry_run,
        "total_events": len(events),
        "source_ips": unique_ips,
        "stages": stages_summary,
        "events": events
    }


def generate_campaign_events(
    campaign_id: str = "CAMP-BOT-001",
    scenario: str = "distributed-botnet",
    total_events: int = DEFAULT_CAMPAIGN_EVENTS,
    bot_nodes: Optional[Dict[str, str]] = None,
    base_time: Optional[Union[datetime, str]] = None,
    time_step_seconds: float = DEFAULT_TIME_STEP_SECONDS,
    strict_limits: bool = True
) -> List[Dict[str, Any]]:
    """
    Convenience helper that directly returns the list of SentinelX-compliant
    event dictionaries for immediate consumption by detection engines or ingestion pipelines.
    """
    result = generate_campaign(
        campaign_id=campaign_id,
        scenario=scenario,
        total_events=total_events,
        bot_nodes=bot_nodes,
        base_time=base_time,
        time_step_seconds=time_step_seconds,
        dry_run=True,
        strict_limits=strict_limits
    )
    return result["events"]
