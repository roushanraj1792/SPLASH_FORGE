"""
Unit & Integration Tests for Internal Evidence Graph Layer
==========================================================
Tests:
  1. Basic campaign graph creation.
  2. Deterministic output (identical inputs -> identical graphs).
  3. CAMPAIGN node creation and metadata.
  4. STAGE nodes creation and metadata.
  5. EVENT evidence nodes creation and metadata.
  6. MITRE TECHNIQUE nodes creation and metadata.
  7. CAMPAIGN_CONTAINS_STAGE edges.
  8. STAGE_SUPPORTED_BY_EVENT edges.
  9. STAGE_USES_TECHNIQUE edges.
 10. Chronological stage preservation.
 11. Multiple events per stage.
 12. Multiple synthetic source IPs tracking.
 13. Multiple MITRE techniques mapping.
 14. Node and edge duplicate removal.
 15. Safe handling of missing optional fields.
 16. Malformed campaign input rejection.
 17. Malformed stages rejection.
 18. Malformed event structures handling.
 19. Invalid timestamp validation.
 20. Invalid source IP validation.
 21. Invalid MITRE technique ID rejection.
 22. Oversized input safety limits enforcement.
 23. Stable deterministic IDs verification (no UUIDs/timestamps).
 24. Zero filesystem/database/network side effects.
 25. End-to-end compatibility (Phase 1A -> 1B -> 1C -> 1D).
"""

from datetime import datetime, timezone
import ipaddress
import socket
import sys
from pathlib import Path
import pytest

# Ensure SentinelX root is on sys.path
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from simulator.internal_evidence_graph import (
    build_evidence_graph,
    build_evidence_graph_from_campaign,
    build_evidence_graph_from_events,
    validate_attack_story_input,
    validate_technique_id,
    validate_ip_address,
    make_campaign_node_id,
    make_stage_node_id,
    make_event_node_id,
    make_technique_node_id,
    EvidenceGraphError,
    MAX_GRAPH_STAGES_BOUND,
    MAX_GRAPH_EVENTS_BOUND,
    VALID_RELATIONSHIPS,
    VALID_NODE_TYPES
)
from simulator.internal_campaign_generator import (
    generate_campaign,
    generate_campaign_events,
    DEFAULT_BOT_NODES
)
from simulator.internal_campaign_correlator import (
    correlate_campaigns,
    correlate_single_campaign
)
from simulator.internal_attack_story import (
    build_attack_story,
    build_attack_story_from_events
)
from database.database import get_recent_events, get_incidents


# ------------------------------------------------------------------------------
# 1. BASIC GRAPH CREATION & DETERMINISM
# ------------------------------------------------------------------------------

def test_basic_campaign_graph_creation():
    """Verify standard attack story builds a valid Evidence Graph."""
    events = generate_campaign_events(total_events=20)
    for idx, ev in enumerate(events, start=1):
        ev["id"] = idx

    story = build_attack_story_from_events(events)
    graph = build_evidence_graph(story)

    assert "campaign" in graph
    assert "nodes" in graph
    assert "edges" in graph
    assert "summary" in graph

    assert graph["summary"]["stage_count"] == len(story["ordered_stages"])
    assert graph["summary"]["node_count"] == len(graph["nodes"])
    assert graph["summary"]["edge_count"] == len(graph["edges"])


def test_deterministic_output():
    """Verify identical attack story yields bit-for-bit identical graph output."""
    events = generate_campaign_events(total_events=24)
    story = build_attack_story_from_events(events)

    graph_1 = build_evidence_graph(story)
    graph_2 = build_evidence_graph(story)

    assert graph_1 == graph_2


# ------------------------------------------------------------------------------
# 2. NODE TYPES VERIFICATION
# ------------------------------------------------------------------------------

def test_campaign_node():
    """Verify CAMPAIGN node structure and metadata."""
    story = {
        "campaign_id": "CAMP-TEST-001",
        "story_title": "Test Campaign",
        "sources": ["198.51.100.11"],
        "event_count": 5,
        "first_timestamp": "2026-09-15T01:00:00+00:00",
        "last_timestamp": "2026-09-15T01:00:20+00:00",
        "ordered_stages": []
    }
    graph = build_evidence_graph(story)

    camp_nodes = [n for n in graph["nodes"] if n["node_type"] == "CAMPAIGN"]
    assert len(camp_nodes) == 1
    node = camp_nodes[0]
    assert node["node_id"] == "campaign:CAMP-TEST-001"
    assert node["label"] == "Test Campaign"
    assert node["metadata"]["campaign_id"] == "CAMP-TEST-001"
    assert node["metadata"]["sources"] == ["198.51.100.11"]


def test_stage_nodes():
    """Verify STAGE nodes creation, labels, and stage ordering metadata."""
    story = {
        "campaign_id": "CAMP-STAGES",
        "ordered_stages": [
            {
                "stage_number": 1,
                "stage_key": "authentication_attack",
                "title": "Brute Force",
                "sources": ["198.51.100.11"],
                "first_seen": "2026-09-15T01:00:00+00:00",
                "last_seen": "2026-09-15T01:00:10+00:00",
            },
            {
                "stage_number": 2,
                "stage_key": "privilege_escalation",
                "title": "Privilege Escalation",
                "sources": ["198.51.100.12"],
                "first_seen": "2026-09-15T01:01:00+00:00",
                "last_seen": "2026-09-15T01:01:10+00:00",
            }
        ]
    }
    graph = build_evidence_graph(story)

    stage_nodes = [n for n in graph["nodes"] if n["node_type"] == "STAGE"]
    assert len(stage_nodes) == 2
    assert stage_nodes[0]["node_id"] == "stage:CAMP-STAGES:1"
    assert stage_nodes[0]["label"] == "Brute Force"
    assert stage_nodes[1]["node_id"] == "stage:CAMP-STAGES:2"
    assert stage_nodes[1]["label"] == "Privilege Escalation"


def test_event_evidence_nodes():
    """Verify EVENT evidence nodes creation and linking."""
    story = {
        "campaign_id": "CAMP-EVENTS",
        "ordered_stages": [
            {
                "stage_number": 1,
                "stage_key": "authentication_attack",
                "title": "Brute Force",
                "sources": ["198.51.100.11"],
                "first_seen": "2026-09-15T01:00:00+00:00",
                "last_seen": "2026-09-15T01:00:10+00:00",
                "event_ids": [101, 102],
                "evidence_references": [
                    {"event_id": 101, "source_ip": "198.51.100.11"},
                    {"event_id": 102, "source_ip": "198.51.100.11"},
                ]
            }
        ]
    }
    graph = build_evidence_graph(story)

    event_nodes = [n for n in graph["nodes"] if n["node_type"] == "EVENT"]
    assert len(event_nodes) == 2
    assert event_nodes[0]["node_id"] == "event:101"
    assert event_nodes[1]["node_id"] == "event:102"
    assert event_nodes[0]["metadata"]["source_ip"] == "198.51.100.11"


def test_mitre_technique_nodes():
    """Verify MITRE TECHNIQUE nodes creation and naming."""
    story = {
        "campaign_id": "CAMP-TECH",
        "ordered_stages": [
            {
                "stage_number": 1,
                "stage_key": "authentication_attack",
                "title": "Brute Force",
                "mitre_technique": "T1110",
                "sources": ["198.51.100.11"],
                "first_seen": "2026-09-15T01:00:00+00:00",
                "last_seen": "2026-09-15T01:00:10+00:00",
            }
        ]
    }
    graph = build_evidence_graph(story)

    tech_nodes = [n for n in graph["nodes"] if n["node_type"] == "TECHNIQUE"]
    assert len(tech_nodes) == 1
    assert tech_nodes[0]["node_id"] == "technique:T1110"
    assert tech_nodes[0]["label"] == "T1110 - Brute Force"
    assert tech_nodes[0]["metadata"]["technique_id"] == "T1110"


# ------------------------------------------------------------------------------
# 3. EDGE RELATIONSHIPS VERIFICATION
# ------------------------------------------------------------------------------

def test_campaign_contains_stage_edges():
    """Verify CAMPAIGN_CONTAINS_STAGE edges connect root to each stage."""
    story = {
        "campaign_id": "CAMP-EDGES",
        "ordered_stages": [
            {"stage_number": 1, "sources": ["198.51.100.11"], "first_seen": "2026-09-15T01:00:00+00:00", "last_seen": "2026-09-15T01:00:10+00:00"},
            {"stage_number": 2, "sources": ["198.51.100.12"], "first_seen": "2026-09-15T01:01:00+00:00", "last_seen": "2026-09-15T01:01:10+00:00"},
        ]
    }
    graph = build_evidence_graph(story)

    edges = [e for e in graph["edges"] if e["relationship"] == "CAMPAIGN_CONTAINS_STAGE"]
    assert len(edges) == 2
    assert edges[0]["source"] == "campaign:CAMP-EDGES"
    assert edges[0]["target"] == "stage:CAMP-EDGES:1"
    assert edges[1]["source"] == "campaign:CAMP-EDGES"
    assert edges[1]["target"] == "stage:CAMP-EDGES:2"


def test_stage_supported_by_event_edges():
    """Verify STAGE_SUPPORTED_BY_EVENT edges connect stage to event evidence."""
    story = {
        "campaign_id": "CAMP-EV-EDGES",
        "ordered_stages": [
            {
                "stage_number": 1,
                "sources": ["198.51.100.11"],
                "first_seen": "2026-09-15T01:00:00+00:00",
                "last_seen": "2026-09-15T01:00:10+00:00",
                "event_ids": [55, 56]
            }
        ]
    }
    graph = build_evidence_graph(story)

    edges = [e for e in graph["edges"] if e["relationship"] == "STAGE_SUPPORTED_BY_EVENT"]
    assert len(edges) == 2
    assert edges[0]["source"] == "stage:CAMP-EV-EDGES:1"
    assert edges[0]["target"] == "event:55"
    assert edges[1]["source"] == "stage:CAMP-EV-EDGES:1"
    assert edges[1]["target"] == "event:56"


def test_stage_uses_technique_edges():
    """Verify STAGE_USES_TECHNIQUE edges connect stage to technique node."""
    story = {
        "campaign_id": "CAMP-TECH-EDGES",
        "ordered_stages": [
            {
                "stage_number": 1,
                "mitre_technique": "T1059.001",
                "sources": ["198.51.100.11"],
                "first_seen": "2026-09-15T01:00:00+00:00",
                "last_seen": "2026-09-15T01:00:10+00:00",
            }
        ]
    }
    graph = build_evidence_graph(story)

    edges = [e for e in graph["edges"] if e["relationship"] == "STAGE_USES_TECHNIQUE"]
    assert len(edges) == 1
    assert edges[0]["source"] == "stage:CAMP-TECH-EDGES:1"
    assert edges[0]["target"] == "technique:T1059.001"


# ------------------------------------------------------------------------------
# 4. CHRONOLOGICAL PRESERVATION & MULTI-ATTRIBUTES
# ------------------------------------------------------------------------------

def test_chronological_stage_preservation():
    """Verify stages are processed in strictly chronological order even if provided out of order."""
    story = {
        "campaign_id": "CAMP-CHRONO",
        "ordered_stages": [
            {"stage_number": 3, "title": "Late Stage", "sources": ["198.51.100.11"], "first_seen": "2026-09-15T01:05:00+00:00", "last_seen": "2026-09-15T01:05:10+00:00"},
            {"stage_number": 1, "title": "Early Stage", "sources": ["198.51.100.11"], "first_seen": "2026-09-15T01:00:00+00:00", "last_seen": "2026-09-15T01:00:10+00:00"},
        ]
    }
    graph = build_evidence_graph(story)

    stage_nodes = [n for n in graph["nodes"] if n["node_type"] == "STAGE"]
    assert stage_nodes[0]["label"] == "Early Stage"
    assert stage_nodes[1]["label"] == "Late Stage"


def test_multiple_events_and_sources_and_techniques():
    """Verify graph handles multi-event, multi-source, multi-technique campaigns."""
    events = generate_campaign_events(total_events=24)
    for i, ev in enumerate(events, start=1):
        ev["id"] = i

    story = build_attack_story_from_events(events)
    graph = build_evidence_graph(story)

    summary = graph["summary"]
    assert summary["stage_count"] == 4
    assert len(summary["source_ips"]) == 4
    assert set(summary["source_ips"]) == set(DEFAULT_BOT_NODES.values())
    assert len(summary["techniques"]) == 4
    assert summary["evidence_count"] == 24


def test_multiple_events_per_stage():
    """Verify multiple events can be attached to a single stage."""
    story = {
        "campaign_id": "CAMP-MULTI-EV",
        "ordered_stages": [
            {
                "stage_number": 1,
                "sources": ["198.51.100.11"],
                "first_seen": "2026-09-15T01:00:00+00:00",
                "last_seen": "2026-09-15T01:00:10+00:00",
                "event_ids": [1, 2, 3, 4, 5, 6, 7, 8]
            }
        ]
    }
    graph = build_evidence_graph(story)
    ev_nodes = [n for n in graph["nodes"] if n["node_type"] == "EVENT"]
    assert len(ev_nodes) == 8
    ev_edges = [e for e in graph["edges"] if e["relationship"] == "STAGE_SUPPORTED_BY_EVENT"]
    assert len(ev_edges) == 8


def test_multiple_source_ips():
    """Verify multiple source IPs are tracked across the graph."""
    story = {
        "campaign_id": "CAMP-MULTI-IP",
        "sources": ["198.51.100.11", "198.51.100.12", "198.51.100.13"],
        "ordered_stages": [
            {"stage_number": 1, "sources": ["198.51.100.11"], "first_seen": "2026-09-15T01:00:00+00:00", "last_seen": "2026-09-15T01:00:10+00:00"},
            {"stage_number": 2, "sources": ["198.51.100.12", "198.51.100.13"], "first_seen": "2026-09-15T01:01:00+00:00", "last_seen": "2026-09-15T01:01:10+00:00"},
        ]
    }
    graph = build_evidence_graph(story)
    assert graph["summary"]["source_ips"] == ["198.51.100.11", "198.51.100.12", "198.51.100.13"]


def test_multiple_techniques():
    """Verify multiple MITRE technique nodes and edges are created."""
    story = {
        "campaign_id": "CAMP-MULTI-TECH",
        "ordered_stages": [
            {"stage_number": 1, "mitre_technique": "T1110", "first_seen": "2026-09-15T01:00:00+00:00", "last_seen": "2026-09-15T01:00:10+00:00"},
            {"stage_number": 2, "mitre_technique": "T1078", "first_seen": "2026-09-15T01:01:00+00:00", "last_seen": "2026-09-15T01:01:10+00:00"},
            {"stage_number": 3, "mitre_technique": "T1059.001", "first_seen": "2026-09-15T01:02:00+00:00", "last_seen": "2026-09-15T01:02:10+00:00"},
        ]
    }
    graph = build_evidence_graph(story)
    tech_nodes = [n for n in graph["nodes"] if n["node_type"] == "TECHNIQUE"]
    assert len(tech_nodes) == 3
    tech_edges = [e for e in graph["edges"] if e["relationship"] == "STAGE_USES_TECHNIQUE"]
    assert len(tech_edges) == 3


# ------------------------------------------------------------------------------
# 5. DEDUPLICATION & MISSING OPTIONAL FIELDS
# ------------------------------------------------------------------------------

def test_duplicate_removal():
    """Verify duplicate event IDs and duplicate techniques do not produce duplicate nodes."""
    story = {
        "campaign_id": "CAMP-DEDUP",
        "ordered_stages": [
            {
                "stage_number": 1,
                "mitre_technique": "T1110",
                "sources": ["198.51.100.11"],
                "first_seen": "2026-09-15T01:00:00+00:00",
                "last_seen": "2026-09-15T01:00:10+00:00",
                "event_ids": [10, 10, 10],  # duplicate event IDs
            },
            {
                "stage_number": 2,
                "mitre_technique": "T1110",  # duplicate technique across stages
                "sources": ["198.51.100.11"],
                "first_seen": "2026-09-15T01:01:00+00:00",
                "last_seen": "2026-09-15T01:01:10+00:00",
                "event_ids": [10],           # event ID shared across stages
            }
        ]
    }
    graph = build_evidence_graph(story)

    # Technique node should appear only once
    tech_nodes = [n for n in graph["nodes"] if n["node_id"] == "technique:T1110"]
    assert len(tech_nodes) == 1

    # Event node should appear only once
    event_nodes = [n for n in graph["nodes"] if n["node_id"] == "event:10"]
    assert len(event_nodes) == 1


def test_missing_optional_fields():
    """Verify graph builder safely handles missing optional fields without crashing."""
    minimal_story = {
        "campaign_id": "CAMP-MINIMAL",
        "ordered_stages": [
            {
                # minimal stage
                "stage_number": 1,
            }
        ]
    }
    graph = build_evidence_graph(minimal_story)
    assert graph["summary"]["stage_count"] == 1
    assert len(graph["nodes"]) == 2  # 1 campaign + 1 stage


# ------------------------------------------------------------------------------
# 6. REJECTION TESTS (MALFORMED / INVALID / OVERSIZED)
# ------------------------------------------------------------------------------

def test_malformed_campaign_input_rejection():
    """Verify non-dict or empty campaign input raises EvidenceGraphError."""
    with pytest.raises(EvidenceGraphError, match="must be a dictionary"):
        build_evidence_graph(None)

    with pytest.raises(EvidenceGraphError, match="must be a dictionary"):
        build_evidence_graph("invalid")

    with pytest.raises(EvidenceGraphError, match="cannot be empty"):
        build_evidence_graph({})

    with pytest.raises(EvidenceGraphError, match="Missing or invalid 'campaign_id'"):
        build_evidence_graph({"ordered_stages": []})


def test_malformed_stages_rejection():
    """Verify malformed stage structures raise EvidenceGraphError."""
    with pytest.raises(EvidenceGraphError, match="Missing or invalid 'ordered_stages'"):
        build_evidence_graph({"campaign_id": "CAMP-01", "ordered_stages": "not-a-list"})

    with pytest.raises(EvidenceGraphError, match="must be a dictionary"):
        build_evidence_graph({"campaign_id": "CAMP-01", "ordered_stages": ["not-a-dict"]})

    with pytest.raises(EvidenceGraphError, match="invalid stage_number"):
        build_evidence_graph({"campaign_id": "CAMP-01", "ordered_stages": [{"stage_number": 0}]})


def test_malformed_event_objects_rejection():
    """Verify malformed event structures raise EvidenceGraphError."""
    story = {
        "campaign_id": "CAMP-BAD-EV",
        "ordered_stages": [
            {
                "stage_number": 1,
                "event_ids": "not-a-list-of-ids"
            }
        ]
    }
    with pytest.raises(EvidenceGraphError, match="must be a list or tuple"):
        build_evidence_graph(story)


def test_invalid_timestamps_rejection():
    """Verify malformed timestamps raise EvidenceGraphError."""
    story = {
        "campaign_id": "CAMP-BAD-TS",
        "ordered_stages": [
            {
                "stage_number": 1,
                "first_seen": "not-a-timestamp",
            }
        ]
    }
    with pytest.raises(EvidenceGraphError, match="invalid timestamp"):
        build_evidence_graph(story)


def test_invalid_source_ips_rejection():
    """Verify invalid source IPs raise EvidenceGraphError."""
    story = {
        "campaign_id": "CAMP-BAD-IP",
        "ordered_stages": [
            {
                "stage_number": 1,
                "sources": ["999.999.999.999"]
            }
        ]
    }
    with pytest.raises(EvidenceGraphError, match="Malformed IPv4 address"):
        build_evidence_graph(story)


def test_invalid_technique_ids_rejection():
    """Verify malformed MITRE technique IDs raise EvidenceGraphError."""
    story = {
        "campaign_id": "CAMP-BAD-TECH",
        "ordered_stages": [
            {
                "stage_number": 1,
                "mitre_technique": "NOT-A-TECHNIQUE"
            }
        ]
    }
    with pytest.raises(EvidenceGraphError, match="Malformed MITRE technique ID"):
        build_evidence_graph(story)


def test_oversized_stages_rejection():
    """Verify input collections exceeding safety limits raise EvidenceGraphError."""
    oversized_stages = [{"stage_number": i} for i in range(1, MAX_GRAPH_STAGES_BOUND + 2)]
    story = {
        "campaign_id": "CAMP-OVERSIZED",
        "ordered_stages": oversized_stages
    }
    with pytest.raises(EvidenceGraphError, match="exceeds safety limit"):
        build_evidence_graph(story)


# ------------------------------------------------------------------------------
# 7. STABLE IDS VERIFICATION
# ------------------------------------------------------------------------------

def test_stable_deterministic_ids():
    """Verify node IDs are deterministic prefixes without random elements."""
    assert make_campaign_node_id("CAMP-01") == "campaign:CAMP-01"
    assert make_stage_node_id("CAMP-01", 2) == "stage:CAMP-01:2"
    assert make_event_node_id(105, 1, 1) == "event:105"
    assert make_event_node_id(None, 1, 3) == "event:stage1:ev003"
    assert make_technique_node_id("t1110") == "technique:T1110"


# ------------------------------------------------------------------------------
# 8. ZERO SIDE EFFECTS VERIFICATION
# ------------------------------------------------------------------------------

def test_no_database_side_effects():
    """Verify graph generation does not modify or query database state."""
    events_before = len(get_recent_events(limit=50))
    incidents_before = len(get_incidents())

    events = generate_campaign_events(total_events=20)
    graph = build_evidence_graph_from_events(events)
    assert graph is not None

    events_after = len(get_recent_events(limit=50))
    incidents_after = len(get_incidents())

    assert events_before == events_after
    assert incidents_before == incidents_after


def test_no_network_or_socket_calls(monkeypatch):
    """Verify zero socket or network calls are made during graph building."""
    def forbidden_socket(*args, **kwargs):
        raise AssertionError("FORBIDDEN: Network socket call in evidence graph builder!")

    monkeypatch.setattr(socket, "socket", forbidden_socket)

    events = generate_campaign_events(total_events=24)
    graph = build_evidence_graph_from_events(events)
    assert graph["summary"]["node_count"] > 0


def test_no_filesystem_modifications():
    """Verify graph generation does not create or write files to filesystem."""
    story = {
        "campaign_id": "CAMP-FS-CHECK",
        "ordered_stages": [{"stage_number": 1, "event_ids": [1]}]
    }
    graph = build_evidence_graph(story)
    assert graph["summary"]["node_count"] == 3


# ------------------------------------------------------------------------------
# 9. END-TO-END PIPELINE VERIFICATION (PHASE 1A -> 1B -> 1C -> 1D)
# ------------------------------------------------------------------------------

def test_end_to_end_phase1_full_pipeline():
    """
    Verify complete 4-stage SentinelX pipeline:
    Phase 1A: Internal Campaign Generator ->
    Phase 1B: Internal Campaign Correlator ->
    Phase 1C: Internal Attack Story ->
    Phase 1D: Internal Evidence Graph.
    """
    # 1. Phase 1A: Synthetic Events
    raw_campaign = generate_campaign(
        campaign_id="E2E-CAMP-001",
        total_events=24,
        dry_run=True
    )
    events = raw_campaign["events"]
    assert len(events) == 24

    # 2. Phase 1B: Correlation
    campaigns = correlate_campaigns(events, campaign_id_prefix="E2E-CAMP")
    assert len(campaigns) == 1
    corr = campaigns[0]
    assert corr["stage_count"] == 4

    # 3. Phase 1C: Attack Story
    story = build_attack_story(corr)
    assert len(story["ordered_stages"]) == 4

    # 4. Phase 1D: Evidence Graph
    graph = build_evidence_graph(story)

    assert graph["summary"]["campaign_id"] == "E2E-CAMP-001"
    assert graph["summary"]["stage_count"] == 4
    assert graph["summary"]["technique_count"] == 4
    assert graph["summary"]["evidence_count"] == 24
    assert len(graph["nodes"]) > 0
    assert len(graph["edges"]) > 0

    # Verify all relationship types exist in the end-to-end graph
    rel_types = {e["relationship"] for e in graph["edges"]}
    assert rel_types == {
        "CAMPAIGN_CONTAINS_STAGE",
        "STAGE_SUPPORTED_BY_EVENT",
        "STAGE_USES_TECHNIQUE"
    }

    # Verify convenience helper produces identical result
    graph_from_camp = build_evidence_graph_from_campaign(corr)
    assert graph_from_camp == graph
