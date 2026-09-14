"""
Internal Evidence Graph Layer — Deterministic In-Memory Knowledge Graph
=======================================================================
Part of the SentinelX Detection & Incident Response Platform.

Role:
  Consumes structured attack stories (Phase 1C) and constructs a deterministic,
  in-memory, machine-readable Evidence Graph connecting:
    Campaign -> Attack Story Stage -> Event Evidence -> MITRE Technique

Conceptual Hierarchy:
  Campaign
   ├── Stage
   │    ├── Event Evidence
   │    └── MITRE Technique
   ├── Stage
   │    ├── Event Evidence
   │    └── MITRE Technique
   └── ...

Node Types:
  - CAMPAIGN: Root campaign metadata and scope
  - STAGE: Attack lifecycle stage in chronological sequence
  - EVENT: Underlying security telemetry event / evidence
  - TECHNIQUE: MITRE ATT&CK technique reference

Edge Relationships:
  - CAMPAIGN_CONTAINS_STAGE: Connects campaign to its chronological stages
  - STAGE_SUPPORTED_BY_EVENT: Connects stage to telemetry evidence events
  - STAGE_USES_TECHNIQUE: Connects stage to MITRE ATT&CK techniques

Safety & Operational Boundary Rules:
  - ZERO network traffic: no HTTP requests, no sockets, no external connections.
  - ZERO database modifications: read-only analysis in memory.
  - ZERO automated response actions: no firewall changes, no containment.
  - ZERO external service calls: no Telegram, no Gemini, no external APIs.
  - Strict deduplication: no duplicate nodes, no duplicate edges.
  - Bounded in-memory processing: strictly enforces limits on stages and events.
  - Deterministic output: identical attack stories yield identical graph structures.
"""

from datetime import datetime, timezone
import hashlib
import ipaddress
import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

from simulator.internal_attack_story import (
    build_attack_story,
    build_attack_story_from_events,
    parse_iso_timestamp,
    STAGE_NARRATIVES,
    AttackStoryError
)


# ------------------------------------------------------------------------------
# CONSTANTS & CONSTRAINTS
# ------------------------------------------------------------------------------

MAX_GRAPH_STAGES_BOUND = 100
MAX_GRAPH_EVENTS_BOUND = 2000
MAX_TOTAL_NODES_BOUND = 3000

MITRE_TECHNIQUE_NAMES = {
    "T1046": "Network Service Discovery",
    "T1110": "Brute Force",
    "T1078": "Valid Accounts",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1068": "Exploitation for Privilege Escalation",
}

VALID_RELATIONSHIPS = {
    "CAMPAIGN_CONTAINS_STAGE",
    "STAGE_SUPPORTED_BY_EVENT",
    "STAGE_USES_TECHNIQUE",
}

VALID_NODE_TYPES = {
    "CAMPAIGN",
    "STAGE",
    "EVENT",
    "TECHNIQUE",
}


# ------------------------------------------------------------------------------
# EXCEPTIONS
# ------------------------------------------------------------------------------

class EvidenceGraphError(ValueError):
    """Raised when attack story input to evidence graph builder is malformed or invalid."""
    pass


# ------------------------------------------------------------------------------
# VALIDATION UTILITIES
# ------------------------------------------------------------------------------

def validate_technique_id(tech_id: Any) -> str:
    """Validate MITRE technique ID format (e.g. 'T1110' or 'T1059.001')."""
    if not isinstance(tech_id, str) or not tech_id.strip():
        raise EvidenceGraphError(f"Invalid MITRE technique ID: {repr(tech_id)}")
    cleaned = tech_id.strip().upper()
    if not re.match(r"^T\d{4}(\.\d{3})?$", cleaned):
        raise EvidenceGraphError(f"Malformed MITRE technique ID format: '{tech_id}'")
    return cleaned


def validate_ip_address(ip_str: Any) -> str:
    """Validate that source IP is a syntactically valid IPv4 address."""
    if not isinstance(ip_str, str) or not ip_str.strip():
        raise EvidenceGraphError(f"Invalid source_ip: {repr(ip_str)}")
    cleaned = ip_str.strip()
    try:
        addr = ipaddress.ip_address(cleaned)
        if not isinstance(addr, ipaddress.IPv4Address):
            raise EvidenceGraphError(f"Only IPv4 addresses supported: '{ip_str}'")
        return cleaned
    except ValueError as exc:
        raise EvidenceGraphError(f"Malformed IPv4 address '{ip_str}': {exc}") from exc


def validate_attack_story_input(story: Any) -> None:
    """Strictly validate attack story structure before constructing graph."""
    if not isinstance(story, dict):
        raise EvidenceGraphError(f"Attack story must be a dictionary, got: {type(story).__name__}")

    if not story:
        raise EvidenceGraphError("Attack story dictionary cannot be empty.")

    campaign_id = story.get("campaign_id")
    if not isinstance(campaign_id, str) or not campaign_id.strip():
        raise EvidenceGraphError(f"Missing or invalid 'campaign_id': {repr(campaign_id)}")

    ordered_stages = story.get("ordered_stages")
    if ordered_stages is None or not isinstance(ordered_stages, (list, tuple)):
        raise EvidenceGraphError(f"Missing or invalid 'ordered_stages': {repr(ordered_stages)}")

    if len(ordered_stages) > MAX_GRAPH_STAGES_BOUND:
        raise EvidenceGraphError(
            f"Stage count ({len(ordered_stages)}) exceeds safety limit ({MAX_GRAPH_STAGES_BOUND})."
        )

    # Validate each stage
    total_events_count = 0
    for idx, stage in enumerate(ordered_stages):
        if not isinstance(stage, dict):
            raise EvidenceGraphError(f"Stage at index {idx} must be a dictionary.")

        stage_number = stage.get("stage_number", idx + 1)
        if not isinstance(stage_number, int) or stage_number < 1:
            raise EvidenceGraphError(f"Stage at index {idx} has invalid stage_number: {stage_number}")

        # Validate timestamps if present
        for ts_field in ("first_seen", "last_seen"):
            ts_val = stage.get(ts_field)
            if ts_val is not None:
                try:
                    parse_iso_timestamp(ts_val)
                except Exception as exc:
                    raise EvidenceGraphError(
                        f"Stage {stage_number} has invalid timestamp in '{ts_field}': {exc}"
                    ) from exc

        # Validate source IPs if present
        sources = stage.get("sources", [])
        if not isinstance(sources, (list, tuple)):
            raise EvidenceGraphError(f"Stage {stage_number} 'sources' must be a list or tuple.")
        for ip in sources:
            validate_ip_address(ip)

        # Validate technique if present
        tech = stage.get("mitre_technique")
        if tech is not None and str(tech).strip().upper() not in ("UNKNOWN", "NONE", ""):
            validate_technique_id(tech)

        # Event IDs
        ev_ids = stage.get("event_ids", [])
        if not isinstance(ev_ids, (list, tuple)):
            raise EvidenceGraphError(f"Stage {stage_number} 'event_ids' must be a list or tuple.")
        total_events_count += len(ev_ids)

    if total_events_count > MAX_GRAPH_EVENTS_BOUND:
        raise EvidenceGraphError(
            f"Total events in story ({total_events_count}) exceeds safety limit ({MAX_GRAPH_EVENTS_BOUND})."
        )


# ------------------------------------------------------------------------------
# DETERMINISTIC IDENTIFIERS
# ------------------------------------------------------------------------------

def make_campaign_node_id(campaign_id: str) -> str:
    """Generate deterministic CAMPAIGN node ID."""
    return f"campaign:{campaign_id.strip()}"


def make_stage_node_id(campaign_id: str, stage_number: int) -> str:
    """Generate deterministic STAGE node ID."""
    return f"stage:{campaign_id.strip()}:{stage_number}"


def make_event_node_id(event_ref: Any, stage_number: int, event_idx: int) -> str:
    """
    Generate deterministic EVENT node ID.
    If event_ref has an explicit ID, use 'event:<id>'.
    Otherwise derive stable deterministic identifier based on stage and index.
    """
    if event_ref is not None:
        if isinstance(event_ref, (int, str)) and str(event_ref).strip():
            return f"event:{str(event_ref).strip()}"
        elif isinstance(event_ref, dict) and event_ref.get("event_id") is not None:
            return f"event:{str(event_ref['event_id']).strip()}"

    # Stable fallback
    return f"event:stage{stage_number}:ev{event_idx:03d}"


def make_technique_node_id(technique_id: str) -> str:
    """Generate deterministic TECHNIQUE node ID."""
    return f"technique:{technique_id.strip().upper()}"


# ------------------------------------------------------------------------------
# GRAPH BUILDER
# ------------------------------------------------------------------------------

def build_evidence_graph(story: Dict[str, Any]) -> Dict[str, Any]:
    """
    Construct a deterministic Evidence Graph from a Phase 1C Attack Story dictionary.

    Parameters:
      story: Validated Attack Story dictionary produced by build_attack_story.

    Returns:
      Dictionary containing:
        - campaign: Root campaign entity metadata
        - nodes: List of deduplicated node dictionaries (CAMPAIGN, STAGE, EVENT, TECHNIQUE)
        - edges: List of deduplicated relationship dictionaries
        - summary: Graph structural metrics and explainable narrative
    """
    validate_attack_story_input(story)

    campaign_id = story["campaign_id"].strip()
    campaign_title = story.get("story_title", f"Campaign {campaign_id}")
    raw_stages = list(story.get("ordered_stages", []))

    # Sort stages deterministically by stage_number to preserve strict chronological order
    sorted_stages = sorted(raw_stages, key=lambda s: s.get("stage_number", 0))

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    seen_node_ids: Set[str] = set()
    seen_edge_keys: Set[Tuple[str, str, str]] = set()

    def add_node(node_id: str, node_type: str, label: str, metadata: Dict[str, Any]) -> None:
        if node_id in seen_node_ids:
            return
        if len(seen_node_ids) >= MAX_TOTAL_NODES_BOUND:
            raise EvidenceGraphError(
                f"Evidence graph node count reached safety bound ({MAX_TOTAL_NODES_BOUND})."
            )
        seen_node_ids.add(node_id)
        nodes.append({
            "node_id": node_id,
            "node_type": node_type,
            "label": label,
            "metadata": metadata
        })

    def add_edge(source_id: str, target_id: str, relationship: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        edge_key = (source_id, target_id, relationship)
        if edge_key in seen_edge_keys:
            return
        seen_edge_keys.add(edge_key)
        edges.append({
            "source": source_id,
            "target": target_id,
            "relationship": relationship,
            "metadata": metadata or {}
        })

    # 1. Create Root CAMPAIGN Node
    camp_node_id = make_campaign_node_id(campaign_id)
    camp_sources = sorted(list(set(story.get("sources", []))))
    camp_event_count = story.get("event_count", 0)

    add_node(
        node_id=camp_node_id,
        node_type="CAMPAIGN",
        label=campaign_title,
        metadata={
            "campaign_id": campaign_id,
            "story_title": campaign_title,
            "sources": camp_sources,
            "event_count": camp_event_count,
            "stage_count": len(sorted_stages),
            "first_timestamp": story.get("first_timestamp", ""),
            "last_timestamp": story.get("last_timestamp", ""),
            "duration_seconds": story.get("duration_seconds", 0.0),
            "confidence": story.get("confidence", "UNKNOWN"),
            "confidence_score": story.get("confidence_score", 0.0),
            "story_summary": story.get("story_summary", "")
        }
    )

    all_stage_sources: Set[str] = set(camp_sources)
    all_techniques: Set[str] = set()
    all_events_represented: Set[str] = set()

    # 2. Iterate through Stages and Build Subgraphs
    for stage in sorted_stages:
        stage_num = stage.get("stage_number", 1)
        stage_id = stage.get("stage_id", f"STAGE-{stage_num:03d}")
        stage_key = stage.get("stage_key", f"stage_{stage_num}")
        stage_title = stage.get("title", stage.get("display_name", f"Stage {stage_num}"))
        stage_sources = sorted(list(set(stage.get("sources", []))))
        all_stage_sources.update(stage_sources)

        stage_node_id = make_stage_node_id(campaign_id, stage_num)

        # Add STAGE node
        add_node(
            node_id=stage_node_id,
            node_type="STAGE",
            label=stage_title,
            metadata={
                "stage_id": stage_id,
                "stage_number": stage_num,
                "stage_key": stage_key,
                "display_name": stage.get("display_name", stage_title),
                "title": stage_title,
                "explanation": stage.get("explanation", ""),
                "first_seen": stage.get("first_seen", ""),
                "last_seen": stage.get("last_seen", ""),
                "duration_seconds": stage.get("duration_seconds", 0.0),
                "sources": stage_sources,
                "event_count": stage.get("event_count", len(stage.get("event_ids", []))),
                "confidence": stage.get("confidence", "UNKNOWN"),
                "reason": stage.get("reason", "")
            }
        )

        # Add Edge: CAMPAIGN_CONTAINS_STAGE
        add_edge(
            source_id=camp_node_id,
            target_id=stage_node_id,
            relationship="CAMPAIGN_CONTAINS_STAGE",
            metadata={"stage_number": stage_num}
        )

        # 3. Process MITRE Technique Node & Edge
        tech_id = stage.get("mitre_technique")
        if tech_id and str(tech_id).strip().upper() not in ("UNKNOWN", "NONE", ""):
            clean_tech_id = str(tech_id).strip().upper()
            all_techniques.add(clean_tech_id)
            tech_node_id = make_technique_node_id(clean_tech_id)
            tech_name = MITRE_TECHNIQUE_NAMES.get(clean_tech_id, "Security Technique")

            add_node(
                node_id=tech_node_id,
                node_type="TECHNIQUE",
                label=f"{clean_tech_id} - {tech_name}",
                metadata={
                    "technique_id": clean_tech_id,
                    "technique_name": tech_name,
                    "mitre_url": f"https://attack.mitre.org/techniques/{clean_tech_id.replace('.', '/')}/"
                }
            )

            # Add Edge: STAGE_USES_TECHNIQUE
            add_edge(
                source_id=stage_node_id,
                target_id=tech_node_id,
                relationship="STAGE_USES_TECHNIQUE",
                metadata={"technique_id": clean_tech_id}
            )

        # 4. Process Evidence Event Nodes & Edges
        raw_event_ids = stage.get("event_ids") or []
        evidence_refs = stage.get("evidence_references") or []

        # Build map of event details from evidence references if available
        ref_meta_map: Dict[Any, Dict[str, Any]] = {}
        for ref in evidence_refs:
            if isinstance(ref, dict):
                eid = ref.get("event_id")
                if eid is not None:
                    ref_meta_map[eid] = ref

        # Process each event associated with this stage
        events_to_process = []
        if raw_event_ids:
            events_to_process = list(raw_event_ids)
        elif evidence_refs:
            events_to_process = [ref.get("event_id") if isinstance(ref, dict) else ref for ref in evidence_refs]
        else:
            # Fallback to deriving stable deterministic events from stage event_count
            ev_count = stage.get("event_count", 0)
            if ev_count > 0:
                events_to_process = [None] * ev_count

        for ev_idx, eid in enumerate(events_to_process, start=1):
            ev_node_id = make_event_node_id(eid, stage_num, ev_idx)
            all_events_represented.add(ev_node_id)

            ref_info = ref_meta_map.get(eid, {})
            ev_source = ref_info.get("source_ip") or (stage_sources[0] if stage_sources else "unknown")

            if eid is not None:
                ev_label = f"Evidence Event #{eid}"
            else:
                ev_label = f"Event Evidence ({ev_source} #{ev_idx})"

            add_node(
                node_id=ev_node_id,
                node_type="EVENT",
                label=ev_label,
                metadata={
                    "event_id": eid,
                    "stage_number": stage_num,
                    "stage_key": stage_key,
                    "source_ip": ev_source,
                    "first_seen": stage.get("first_seen", ""),
                    "evidence_reference": str(eid) if eid is not None else f"stage_{stage_num}_ev_{ev_idx}"
                }
            )

            # Add Edge: STAGE_SUPPORTED_BY_EVENT
            add_edge(
                source_id=stage_node_id,
                target_id=ev_node_id,
                relationship="STAGE_SUPPORTED_BY_EVENT",
                metadata={"event_id": eid, "stage_number": stage_num}
            )

    # 5. Compile Structural Summary
    stage_count = len(sorted_stages)
    technique_count = len(all_techniques)
    unique_sources = sorted(list(all_stage_sources))
    unique_techniques = sorted(list(all_techniques))
    evidence_count = len(all_events_represented)

    graph_reason = (
        f"Deterministic Evidence Graph for campaign '{campaign_id}': "
        f"{stage_count} attack stages supported by {evidence_count} evidence events "
        f"and mapped across {technique_count} MITRE ATT&CK techniques ({', '.join(unique_techniques) or 'None'})."
    )

    return {
        "campaign": {
            "campaign_id": campaign_id,
            "title": campaign_title,
            "sources": unique_sources,
            "event_count": camp_event_count,
            "stage_count": stage_count,
            "first_timestamp": story.get("first_timestamp", ""),
            "last_timestamp": story.get("last_timestamp", ""),
            "confidence": story.get("confidence", "UNKNOWN"),
        },
        "nodes": nodes,
        "edges": edges,
        "summary": {
            "campaign_id": campaign_id,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "stage_count": stage_count,
            "event_count": camp_event_count,
            "technique_count": technique_count,
            "source_ips": unique_sources,
            "techniques": unique_techniques,
            "evidence_count": evidence_count,
            "graph_reason": graph_reason
        }
    }


def build_evidence_graph_from_campaign(campaign: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convenience helper executing:
    Phase 1B Correlated Campaign -> Phase 1C Attack Story -> Phase 1D Evidence Graph.
    """
    story = build_attack_story(campaign)
    return build_evidence_graph(story)


def build_evidence_graph_from_events(
    events: Sequence[Dict[str, Any]],
    time_window_minutes: float = 30.0,
    campaign_id_prefix: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Convenience helper executing complete Phase 1 pipeline:
    Phase 1A Synthetic Events -> Phase 1B Correlation -> Phase 1C Attack Story -> Phase 1D Evidence Graph.
    """
    story = build_attack_story_from_events(
        events=events,
        time_window_minutes=time_window_minutes,
        campaign_id_prefix=campaign_id_prefix
    )
    if not story:
        return None
    return build_evidence_graph(story)
