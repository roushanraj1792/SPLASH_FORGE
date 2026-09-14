"""
Internal Attack Story Engine — Deterministic In-Memory Narrative Layer
=====================================================================
Part of the SentinelX Detection & Incident Response Platform.

Role:
  Translates deterministic campaign correlation data (Phase 1B) into a
  chronologically ordered, explainable, human-readable yet machine-structured
  attack story.

Pipeline Flow:
  Synthetic Events (Phase 1A)
  → Campaign Correlator (Phase 1B)
  → Attack Story Engine (Phase 1C)

Safety & Operational Boundary Rules:
  - ZERO network traffic: no HTTP requests, no sockets, no external connections.
  - ZERO database modifications: does not write to SQLite or modify incidents.
  - ZERO automated response actions: no firewall changes, no IP blocking.
  - ZERO external service calls: no Telegram, no Gemini, no external APIs.
  - Bounded in-memory processing: strictly enforces limits on stages and events.
  - Deterministic output: identical campaign input yields identical attack story output.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Union

from simulator.internal_campaign_correlator import (
    correlate_campaigns,
    correlate_single_campaign,
    parse_iso_timestamp,
    STAGE_DEFINITIONS
)


# ------------------------------------------------------------------------------
# CONSTANTS & CONSTRAINTS
# ------------------------------------------------------------------------------

MAX_STORY_STAGES_BOUND = 100
MAX_EVIDENCE_REFERENCES_BOUND = 5000

# Explainable narrative descriptions for recognized stages
STAGE_NARRATIVES = {
    "reconnaissance": {
        "title": "Network Reconnaissance & Service Discovery",
        "narrative": (
            "The adversary performed network-level port and service probing "
            "to identify accessible services and potential attack vectors."
        ),
        "mitre_technique": "T1046",
    },
    "authentication_attack": {
        "title": "Initial Access via Credential Brute Force",
        "narrative": (
            "Multiple rapid authentication failures were detected, indicating an active "
            "brute-force or credential stuffing operation attempting unauthorized entry."
        ),
        "mitre_technique": "T1110",
    },
    "successful_authentication": {
        "title": "Compromised Authentication & Valid Account Foothold",
        "narrative": (
            "Adversary successfully authenticated using valid account credentials, "
            "establishing an authorized foothold following or alongside credential attacks."
        ),
        "mitre_technique": "T1078",
    },
    "suspicious_powershell": {
        "title": "Execution of Obfuscated PowerShell Commands",
        "narrative": (
            "Suspicious PowerShell execution observed using ExecutionPolicy bypasses and "
            "encoded payloads to bypass standard script inspection controls."
        ),
        "mitre_technique": "T1059.001",
    },
    "privilege_escalation": {
        "title": "Unauthorized Administrative Privilege Escalation",
        "narrative": (
            "Adversary executed privilege modification actions that resulted in "
            "elevated system or administrative rights on the target host."
        ),
        "mitre_technique": "T1068",
    },
}


# ------------------------------------------------------------------------------
# EXCEPTIONS
# ------------------------------------------------------------------------------

class AttackStoryError(ValueError):
    """Raised when campaign input to attack story builder is malformed or invalid."""
    pass


# ------------------------------------------------------------------------------
# VALIDATION UTILITIES
# ------------------------------------------------------------------------------

def validate_campaign_dict(campaign: Any) -> None:
    """Strictly validate the campaign dictionary before building an attack story."""
    if not isinstance(campaign, dict):
        raise AttackStoryError(f"Campaign must be a dictionary, got: {type(campaign).__name__}")

    if not campaign:
        raise AttackStoryError("Campaign dictionary cannot be empty.")

    campaign_id = campaign.get("campaign_id")
    if not isinstance(campaign_id, str) or not campaign_id.strip():
        raise AttackStoryError(f"Missing or invalid 'campaign_id': {repr(campaign_id)}")

    ordered_stages = campaign.get("ordered_stages")
    if ordered_stages is None or not isinstance(ordered_stages, (list, tuple)):
        raise AttackStoryError(f"Missing or invalid 'ordered_stages' in campaign: {repr(ordered_stages)}")

    if len(ordered_stages) > MAX_STORY_STAGES_BOUND:
        raise AttackStoryError(
            f"Stage count ({len(ordered_stages)}) exceeds safety limit ({MAX_STORY_STAGES_BOUND})."
        )

    # Validate each stage structure
    for idx, stage in enumerate(ordered_stages):
        if not isinstance(stage, dict):
            raise AttackStoryError(f"Stage at index {idx} must be a dictionary.")

        for req in ("stage_key", "sources", "first_seen", "last_seen"):
            if req not in stage or stage[req] is None:
                raise AttackStoryError(f"Stage at index {idx} missing required field '{req}'.")

        # Validate timestamps
        try:
            t_first = parse_iso_timestamp(stage["first_seen"])
            t_last = parse_iso_timestamp(stage["last_seen"])
        except Exception as exc:
            raise AttackStoryError(
                f"Stage at index {idx} has invalid timestamp: {exc}"
            ) from exc

        if t_last < t_first:
            raise AttackStoryError(
                f"Stage at index {idx} has invalid timestamp sequence: last_seen ({stage['last_seen']}) "
                f"is earlier than first_seen ({stage['first_seen']})."
            )

        # Validate sources
        if not isinstance(stage["sources"], (list, tuple)):
            raise AttackStoryError(f"Stage at index {idx} 'sources' must be a list or tuple.")

        # Validate event IDs if present
        event_ids = stage.get("event_ids")
        if event_ids is not None:
            if not isinstance(event_ids, (list, tuple)):
                raise AttackStoryError(f"Stage at index {idx} 'event_ids' must be a list or tuple.")


# ------------------------------------------------------------------------------
# CONFIDENCE SCORING
# ------------------------------------------------------------------------------

def _calculate_story_confidence(stage_count: int, event_count: int, is_multi_source: bool) -> Dict[str, Any]:
    """Calculate deterministic confidence metrics for the attack story."""
    if stage_count >= 3:
        level = "HIGH"
        score = 0.95 if is_multi_source else 0.90
        reason = f"Comprehensive multi-stage attack lifecycle observed across {stage_count} sequential stages."
    elif stage_count == 2:
        level = "HIGH"
        score = 0.85
        reason = "Two-stage attack progression observed with consistent temporal linkage."
    elif event_count >= 5:
        level = "MEDIUM"
        score = 0.75
        reason = f"High-volume single-stage activity observed with {event_count} telemetry events."
    else:
        level = "LOW"
        score = 0.60
        reason = "Limited event evidence observed for this activity."

    return {
        "confidence": level,
        "confidence_score": score,
        "reason": reason
    }


# ------------------------------------------------------------------------------
# ATTACK STORY BUILDER
# ------------------------------------------------------------------------------

def build_attack_story(campaign: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a deterministic chronological attack story from a Phase 1B campaign dictionary.

    Parameters:
      campaign: Structured campaign dictionary produced by internal_campaign_correlator.

    Returns:
      Comprehensive attack story dictionary with overall narrative, ordered story stages,
      MITRE techniques, evidence references, and deterministic confidence scoring.
    """
    validate_campaign_dict(campaign)

    campaign_id = campaign["campaign_id"]
    campaign_name = campaign.get("campaign_name", "Security Incident Campaign")
    raw_stages = list(campaign["ordered_stages"])

    # 1. Sort stages deterministically by first_seen timestamp to ensure strict chronology
    def stage_sort_key(s: Dict[str, Any]):
        t = parse_iso_timestamp(s["first_seen"])
        return (t, s.get("stage_index", 0), str(s.get("stage_key", "")))

    sorted_stages = sorted(raw_stages, key=stage_sort_key)

    # 2. Build structured, explainable story stages
    story_stages: List[Dict[str, Any]] = []
    all_evidence_ids: List[Any] = []
    all_techniques_set = set()
    all_sources_set = set()

    for idx, stage in enumerate(sorted_stages, start=1):
        skey = stage["stage_key"]
        narrative_info = STAGE_NARRATIVES.get(skey, {
            "title": stage.get("display_name", skey.replace("_", " ").title()),
            "narrative": stage.get("summary", f"Observed activity for {skey}."),
            "mitre_technique": stage.get("mitre_technique", "UNKNOWN"),
        })

        t_first = parse_iso_timestamp(stage["first_seen"])
        t_last = parse_iso_timestamp(stage["last_seen"])
        duration = max(0.0, (t_last - t_first).total_seconds())

        sources = sorted(list(set(stage["sources"])))
        all_sources_set.update(sources)

        technique = stage.get("mitre_technique") or narrative_info["mitre_technique"]
        if technique and technique != "UNKNOWN":
            all_techniques_set.add(technique)

        # Deduplicate event IDs while preserving order
        raw_event_ids = stage.get("event_ids") or []
        seen_ids = set()
        deduped_ids = []
        for eid in raw_event_ids:
            if eid not in seen_ids:
                seen_ids.add(eid)
                deduped_ids.append(eid)

        all_evidence_ids.extend(deduped_ids)

        evidence_refs = [
            {"event_id": eid, "source_ip": sources[0] if len(sources) == 1 else "multiple", "stage_key": skey}
            for eid in deduped_ids
        ]

        # Stage-level confidence explanation
        ev_count = stage.get("event_count", len(deduped_ids))
        stage_reason = f"{ev_count} event(s) observed from {', '.join(sources)} spanning {duration:.1f}s."

        story_stage = {
            "stage_number": idx,
            "stage_id": f"STAGE-{idx:03d}",
            "stage_key": skey,
            "title": narrative_info["title"],
            "display_name": stage.get("display_name", narrative_info["title"]),
            "mitre_technique": technique,
            "explanation": narrative_info["narrative"],
            "sources": sources,
            "first_seen": stage["first_seen"],
            "last_seen": stage["last_seen"],
            "duration_seconds": duration,
            "event_count": ev_count,
            "event_ids": deduped_ids,
            "evidence_references": evidence_refs,
            "confidence": "HIGH" if ev_count >= 2 else "MEDIUM",
            "reason": stage_reason
        }
        story_stages.append(story_stage)

    # 3. Overall campaign story metrics
    campaign_sources = sorted(list(all_sources_set if all_sources_set else set(campaign.get("sources", []))))
    all_techniques = sorted(list(all_techniques_set if all_techniques_set else set(campaign.get("techniques", []))))

    # Deduplicate total evidence references
    seen_all = set()
    total_deduped_evidence_ids = []
    for eid in all_evidence_ids:
        if eid not in seen_all:
            seen_all.add(eid)
            total_deduped_evidence_ids.append(eid)

    total_events = campaign.get("event_count", len(total_deduped_evidence_ids))

    first_ts = story_stages[0]["first_seen"] if story_stages else campaign.get("first_observed", "")
    last_ts = story_stages[-1]["last_seen"] if story_stages else campaign.get("last_observed", "")
    t_start = parse_iso_timestamp(first_ts)
    t_end = parse_iso_timestamp(last_ts)
    total_duration = max(0.0, (t_end - t_start).total_seconds())

    conf_meta = _calculate_story_confidence(len(story_stages), total_events, len(campaign_sources) > 1)

    # 4. Generate comprehensive human-readable narrative
    stage_titles = [s["title"] for s in story_stages]
    progression_str = " -> ".join(stage_titles) if stage_titles else "Single-phase operation"

    if len(story_stages) > 1:
        overall_narrative = (
            f"A coordinated {len(story_stages)}-stage intrusion sequence was identified across "
            f"{len(campaign_sources)} synthetic bot source(s) spanning {total_duration:.1f} seconds "
            f"from {first_ts} to {last_ts}. "
            f"The adversary progressed through the following attack chain: {progression_str}. "
            f"Associated MITRE ATT&CK techniques: {', '.join(all_techniques) if all_techniques else 'None'}. "
            f"{conf_meta['reason']}"
        )
    else:
        single_title = story_stages[0]["title"] if story_stages else "Activity"
        overall_narrative = (
            f"A focused security event sequence of type '{single_title}' was identified "
            f"originating from {len(campaign_sources)} source(s) spanning {total_duration:.1f} seconds "
            f"from {first_ts} to {last_ts}. "
            f"Total events observed: {total_events}. "
            f"{conf_meta['reason']}"
        )

    story_summary = (
        f"Campaign {campaign_id}: {len(story_stages)} stage(s), {total_events} event(s), "
        f"{len(campaign_sources)} source(s) over {total_duration:.1f}s."
    )

    return {
        "campaign_id": campaign_id,
        "story_title": f"Attack Progression Story: {campaign_name}",
        "overall_narrative": overall_narrative,
        "story_summary": story_summary,
        "ordered_stages": story_stages,
        "sources": campaign_sources,
        "event_count": total_events,
        "first_timestamp": first_ts,
        "last_timestamp": last_ts,
        "duration_seconds": total_duration,
        "mitre_techniques": all_techniques,
        "evidence_references": total_deduped_evidence_ids,
        "confidence": conf_meta["confidence"],
        "confidence_score": conf_meta["confidence_score"],
        "correlation_reason": campaign.get("correlation_reason", ""),
        "story_reason": conf_meta["reason"]
    }


def build_attack_story_from_events(
    events: Sequence[Dict[str, Any]],
    time_window_minutes: float = 30.0,
    campaign_id_prefix: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Convenience helper executing the complete Phase 1 pipeline:
    Synthetic Events -> Phase 1B Correlation -> Phase 1C Attack Story.
    """
    campaign = correlate_single_campaign(
        events=events,
        time_window_minutes=time_window_minutes,
        campaign_id_prefix=campaign_id_prefix
    )
    if not campaign:
        return None
    return build_attack_story(campaign)


def build_attack_stories_from_events(
    events: Sequence[Dict[str, Any]],
    time_window_minutes: float = 30.0,
    campaign_id_prefix: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Execute pipeline across all detected campaigns in the event stream.
    """
    campaigns = correlate_campaigns(
        events=events,
        time_window_minutes=time_window_minutes,
        campaign_id_prefix=campaign_id_prefix
    )
    return [build_attack_story(camp) for camp in campaigns]
