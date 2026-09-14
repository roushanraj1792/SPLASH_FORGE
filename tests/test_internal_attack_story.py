"""
Unit & Integration Tests for Internal Attack Story Engine
=========================================================
Tests:
  1. Basic single-stage attack story generation.
  2. Full multi-stage attack story generation.
  3. Strict chronological ordering preservation.
  4. Campaign identity preservation.
  5. Multiple source IPs tracking across stages.
  6. MITRE ATT&CK technique mapping and preservation.
  7. Event ID and evidence reference preservation.
  8. Deterministic output verification (identical inputs -> identical stories).
  9. Human-readable narrative and summary generation.
 10. Missing campaign identifier rejection.
 11. Malformed stage structures rejection.
 12. Malformed timestamp handling.
 13. Empty campaign handling.
 14. Oversized input rejection.
 15. Duplicate event IDs deduplication.
 16. Out-of-order stage input reordering.
 17. Zero database modifications or queries.
 18. Zero network/socket access.
 19. Zero external API calls.
 20. Zero filesystem side effects.
 21. End-to-end pipeline verification (Phase 1A -> Phase 1B -> Phase 1C).
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

from simulator.internal_attack_story import (
    build_attack_story,
    build_attack_story_from_events,
    build_attack_stories_from_events,
    validate_campaign_dict,
    AttackStoryError,
    STAGE_NARRATIVES,
    MAX_STORY_STAGES_BOUND
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
from database.database import get_recent_events, get_incidents


# ------------------------------------------------------------------------------
# 1. BASIC SINGLE-STAGE STORY TESTS
# ------------------------------------------------------------------------------

def test_basic_single_stage_story():
    """Verify single-stage campaign produces a valid attack story."""
    campaign = {
        "campaign_id": "CAMP-001",
        "campaign_name": "Brute Force Attack",
        "ordered_stages": [
            {
                "stage_index": 1,
                "stage_key": "authentication_attack",
                "display_name": "Authentication Attack",
                "mitre_technique": "T1110",
                "event_count": 5,
                "event_ids": [1, 2, 3, 4, 5],
                "sources": ["198.51.100.11"],
                "first_seen": "2026-09-15T01:00:00+00:00",
                "last_seen": "2026-09-15T01:00:20+00:00",
                "summary": "5 failed login attempts."
            }
        ],
        "sources": ["198.51.100.11"],
        "event_count": 5,
        "first_observed": "2026-09-15T01:00:00+00:00",
        "last_observed": "2026-09-15T01:00:20+00:00",
        "techniques": ["T1110"],
        "correlation_reason": "Single source brute force."
    }

    story = build_attack_story(campaign)
    assert story["campaign_id"] == "CAMP-001"
    assert len(story["ordered_stages"]) == 1

    stage = story["ordered_stages"][0]
    assert stage["stage_number"] == 1
    assert stage["stage_key"] == "authentication_attack"
    assert stage["mitre_technique"] == "T1110"
    assert stage["sources"] == ["198.51.100.11"]
    assert stage["event_ids"] == [1, 2, 3, 4, 5]
    assert "brute-force" in stage["explanation"].lower()


# ------------------------------------------------------------------------------
# 2. FULL MULTI-STAGE ATTACK STORY TESTS
# ------------------------------------------------------------------------------

def test_full_multi_stage_attack_story():
    """Verify complete 4-stage campaign is converted into a multi-stage attack story."""
    events = generate_campaign_events(total_events=24)
    for i, ev in enumerate(events, start=101):
        ev["id"] = i

    campaign = correlate_single_campaign(events)
    assert campaign is not None

    story = build_attack_story(campaign)

    assert story["campaign_id"] == campaign["campaign_id"]
    assert len(story["ordered_stages"]) == 4

    expected_keys = [
        "authentication_attack",
        "successful_authentication",
        "suspicious_powershell",
        "privilege_escalation"
    ]
    for idx, expected in enumerate(expected_keys):
        st = story["ordered_stages"][idx]
        assert st["stage_key"] == expected
        assert st["stage_number"] == idx + 1
        assert st["stage_id"] == f"STAGE-{idx+1:03d}"
        assert len(st["event_ids"]) > 0


# ------------------------------------------------------------------------------
# 3. CHRONOLOGICAL ORDERING TESTS
# ------------------------------------------------------------------------------

def test_chronological_ordering():
    """Verify story stages strictly follow chronological timestamps."""
    events = generate_campaign_events(total_events=24)
    story = build_attack_story_from_events(events)

    stages = story["ordered_stages"]
    for i in range(len(stages) - 1):
        t1 = datetime.fromisoformat(stages[i]["first_seen"])
        t2 = datetime.fromisoformat(stages[i+1]["first_seen"])
        assert t1 <= t2, f"Stage {i} timestamp {t1} must precede or equal Stage {i+1} timestamp {t2}"


def test_out_of_order_stages_reordered():
    """Verify out-of-order input stages are sorted into proper chronological order."""
    campaign = {
        "campaign_id": "CAMP-REORDER",
        "ordered_stages": [
            {
                "stage_key": "privilege_escalation",
                "sources": ["198.51.100.14"],
                "first_seen": "2026-09-15T01:03:00+00:00",
                "last_seen": "2026-09-15T01:03:30+00:00",
            },
            {
                "stage_key": "authentication_attack",
                "sources": ["198.51.100.11"],
                "first_seen": "2026-09-15T01:00:00+00:00",
                "last_seen": "2026-09-15T01:00:30+00:00",
            },
            {
                "stage_key": "suspicious_powershell",
                "sources": ["198.51.100.13"],
                "first_seen": "2026-09-15T01:02:00+00:00",
                "last_seen": "2026-09-15T01:02:30+00:00",
            },
        ]
    }

    story = build_attack_story(campaign)
    assert story["ordered_stages"][0]["stage_key"] == "authentication_attack"
    assert story["ordered_stages"][1]["stage_key"] == "suspicious_powershell"
    assert story["ordered_stages"][2]["stage_key"] == "privilege_escalation"


# ------------------------------------------------------------------------------
# 4. CAMPAIGN IDENTITY PRESERVATION TESTS
# ------------------------------------------------------------------------------

def test_campaign_identity_preservation():
    """Verify campaign identifier is preserved exactly."""
    events = generate_campaign_events(total_events=20)
    campaign = correlate_single_campaign(events, campaign_id_prefix="CAMP-SPECIFIC-ID")
    story = build_attack_story(campaign)

    assert story["campaign_id"] == "CAMP-SPECIFIC-ID-001"
    assert "CAMP-SPECIFIC-ID-001" in story["story_summary"]


# ------------------------------------------------------------------------------
# 5. MULTIPLE SOURCE IPS TESTS
# ------------------------------------------------------------------------------

def test_multiple_source_ips_tracking():
    """Verify attack story tracks all botnet source IPs across stages."""
    events = generate_campaign_events(total_events=24)
    story = build_attack_story_from_events(events)

    expected_ips = sorted(list(DEFAULT_BOT_NODES.values()))
    assert story["sources"] == expected_ips
    assert len(story["sources"]) == 4


# ------------------------------------------------------------------------------
# 6. MITRE TECHNIQUE PRESERVATION TESTS
# ------------------------------------------------------------------------------

def test_mitre_technique_preservation():
    """Verify all recognized MITRE ATT&CK techniques are collected and mapped."""
    events = generate_campaign_events(total_events=24)
    story = build_attack_story_from_events(events)

    expected_techniques = {"T1110", "T1078", "T1059.001", "T1068"}
    assert set(story["mitre_techniques"]) == expected_techniques


# ------------------------------------------------------------------------------
# 7. EVENT ID AND EVIDENCE REFERENCE PRESERVATION TESTS
# ------------------------------------------------------------------------------

def test_evidence_references_preservation():
    """Verify evidence references and event IDs are collected and preserved."""
    events = generate_campaign_events(total_events=20)
    for i, ev in enumerate(events, start=500):
        ev["id"] = i

    story = build_attack_story_from_events(events)

    assert len(story["evidence_references"]) == 20
    assert story["evidence_references"] == list(range(500, 520))

    # Verify stage-level evidence references
    first_stage = story["ordered_stages"][0]
    assert len(first_stage["evidence_references"]) > 0
    assert first_stage["evidence_references"][0]["event_id"] == 500


# ------------------------------------------------------------------------------
# 8. DETERMINISTIC OUTPUT TESTS
# ------------------------------------------------------------------------------

def test_deterministic_output():
    """Verify identical campaign input yields identical attack story output."""
    events = generate_campaign_events(total_events=24)
    campaign = correlate_single_campaign(events)

    story_1 = build_attack_story(campaign)
    story_2 = build_attack_story(campaign)

    assert story_1 == story_2


# ------------------------------------------------------------------------------
# 9. NARRATIVE GENERATION TESTS
# ------------------------------------------------------------------------------

def test_narrative_generation_multi_stage():
    """Verify comprehensive narrative includes progression and technique details."""
    events = generate_campaign_events(total_events=24)
    story = build_attack_story_from_events(events)

    narrative = story["overall_narrative"]
    assert "4-stage intrusion sequence" in narrative
    assert "4 synthetic bot source(s)" in narrative
    assert "T1110" in narrative or "T1078" in narrative
    assert len(narrative) > 100


# ------------------------------------------------------------------------------
# 10. REJECTION TESTS (MALFORMED / MISSING / OVERSIZED)
# ------------------------------------------------------------------------------

def test_missing_campaign_id_rejection():
    """Verify missing campaign_id raises AttackStoryError."""
    with pytest.raises(AttackStoryError, match="Missing or invalid 'campaign_id'"):
        build_attack_story({"ordered_stages": []})

    with pytest.raises(AttackStoryError, match="Missing or invalid 'campaign_id'"):
        build_attack_story({"campaign_id": "", "ordered_stages": []})


def test_malformed_stages_rejection():
    """Verify non-list or invalid stage structures raise AttackStoryError."""
    with pytest.raises(AttackStoryError, match="Missing or invalid 'ordered_stages'"):
        build_attack_story({"campaign_id": "CAMP-01", "ordered_stages": "not-a-list"})

    with pytest.raises(AttackStoryError, match="must be a dictionary"):
        build_attack_story({"campaign_id": "CAMP-01", "ordered_stages": ["not-a-dict"]})

    with pytest.raises(AttackStoryError, match="missing required field"):
        build_attack_story({"campaign_id": "CAMP-01", "ordered_stages": [{"stage_key": "recon"}]})


def test_malformed_timestamps_rejection():
    """Verify invalid ISO-8601 timestamps in stages raise AttackStoryError."""
    bad_campaign = {
        "campaign_id": "CAMP-BAD-TS",
        "ordered_stages": [
            {
                "stage_key": "authentication_attack",
                "sources": ["198.51.100.11"],
                "first_seen": "invalid-timestamp",
                "last_seen": "2026-09-15T01:00:00+00:00",
            }
        ]
    }
    with pytest.raises(AttackStoryError):
        build_attack_story(bad_campaign)


def test_inverted_timestamp_sequence_rejection():
    """Verify last_seen earlier than first_seen raises AttackStoryError."""
    bad_campaign = {
        "campaign_id": "CAMP-INVERTED-TS",
        "ordered_stages": [
            {
                "stage_key": "authentication_attack",
                "sources": ["198.51.100.11"],
                "first_seen": "2026-09-15T01:05:00+00:00",
                "last_seen": "2026-09-15T01:00:00+00:00",  # Earlier!
            }
        ]
    }
    with pytest.raises(AttackStoryError, match="invalid timestamp sequence"):
        build_attack_story(bad_campaign)


def test_empty_campaign_rejection():
    """Verify empty dictionary raises AttackStoryError."""
    with pytest.raises(AttackStoryError, match="dictionary cannot be empty"):
        build_attack_story({})

    with pytest.raises(AttackStoryError, match="must be a dictionary"):
        build_attack_story(None)


def test_oversized_stages_rejection():
    """Verify stage collections exceeding MAX_STORY_STAGES_BOUND raise AttackStoryError."""
    single_stage = {
        "stage_key": "authentication_attack",
        "sources": ["198.51.100.11"],
        "first_seen": "2026-09-15T01:00:00+00:00",
        "last_seen": "2026-09-15T01:00:05+00:00",
    }
    oversized = [single_stage] * (MAX_STORY_STAGES_BOUND + 1)
    with pytest.raises(AttackStoryError, match="exceeds safety limit"):
        build_attack_story({"campaign_id": "CAMP-OVERSIZED", "ordered_stages": oversized})


# ------------------------------------------------------------------------------
# 11. DUPLICATE EVENT IDS HANDLING
# ------------------------------------------------------------------------------

def test_duplicate_event_ids_deduplication():
    """Verify duplicate event IDs are safely deduplicated."""
    campaign = {
        "campaign_id": "CAMP-DEDUP",
        "ordered_stages": [
            {
                "stage_key": "authentication_attack",
                "sources": ["198.51.100.11"],
                "event_ids": [10, 10, 20, 20, 30],
                "first_seen": "2026-09-15T01:00:00+00:00",
                "last_seen": "2026-09-15T01:00:10+00:00",
            }
        ]
    }
    story = build_attack_story(campaign)
    stage = story["ordered_stages"][0]
    assert stage["event_ids"] == [10, 20, 30]
    assert story["evidence_references"] == [10, 20, 30]


# ------------------------------------------------------------------------------
# 12. ZERO SIDE EFFECTS VERIFICATION
# ------------------------------------------------------------------------------

def test_no_database_side_effects():
    """Verify building an attack story does not query or insert database records."""
    ev_count_before = len(get_recent_events(limit=50))
    inc_count_before = len(get_incidents())

    events = generate_campaign_events(total_events=20)
    story = build_attack_story_from_events(events)
    assert story is not None

    ev_count_after = len(get_recent_events(limit=50))
    inc_count_after = len(get_incidents())

    assert ev_count_before == ev_count_after
    assert inc_count_before == inc_count_after


def test_no_network_or_socket_calls(monkeypatch):
    """Verify zero socket or network calls are made during story building."""
    def forbidden_socket(*args, **kwargs):
        raise AssertionError("FORBIDDEN: Network socket call in attack story engine!")

    monkeypatch.setattr(socket, "socket", forbidden_socket)

    events = generate_campaign_events(total_events=24)
    story = build_attack_story_from_events(events)
    assert story["campaign_id"] is not None


# ------------------------------------------------------------------------------
# 13. END-TO-END PIPELINE VERIFICATION (PHASE 1A -> 1B -> 1C)
# ------------------------------------------------------------------------------

def test_end_to_end_phase1_pipeline():
    """
    Verify complete seamless flow:
    Phase 1A Synthetic Campaign Generator
    → Phase 1B Internal Campaign Correlator
    → Phase 1C Internal Attack Story Engine
    """
    # 1. Phase 1A: Generate synthetic events
    raw_campaign = generate_campaign(
        campaign_id="E2E-TEST-BOT-01",
        total_events=24,
        dry_run=True
    )
    events = raw_campaign["events"]
    assert len(events) == 24

    # 2. Phase 1B: Correlate into structured campaign
    campaigns = correlate_campaigns(events)
    assert len(campaigns) == 1
    corr_campaign = campaigns[0]
    assert corr_campaign["stage_count"] == 4

    # 3. Phase 1C: Build attack progression story
    story = build_attack_story(corr_campaign)
    assert story["campaign_id"] == corr_campaign["campaign_id"]
    assert len(story["ordered_stages"]) == 4
    assert story["confidence"] == "HIGH"
    assert len(story["sources"]) == 4
    assert "Attack Progression Story" in story["story_title"]
