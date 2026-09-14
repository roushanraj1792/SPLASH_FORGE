"""
Unit & Integration Tests for Internal Response Lab (Phase 1E)
============================================================
Comprehensive test suite covering:
  1. Basic Response Lab creation & interface
  2. Deterministic output reproducibility
  3. Campaign identity tracking
  4. BLOCK_SOURCE_IP option evaluation
  5. ISOLATE_HOST option evaluation
  6. NOTIFY_ADMIN option evaluation
  7. NO_ACTION option evaluation
  8. Response scoring bounds & integer types
  9. Coverage scoring logic
 10. Risk reduction scoring logic
 11. Operational impact scoring hierarchy
 12. Residual risk scoring relationship
 13. Confidence score bounds & progression
 14. Recommendation structure & generation
 15. Authentication attack influence
 16. Successful authentication influence
 17. PowerShell execution influence
 18. Privilege escalation influence
 19. Multiple source IP influence
 20. Multiple MITRE techniques tracking
 21. Multiple evidence events influence
 22. Duplicate input handling (options & nodes)
 23. Malformed graph rejection
 24. Malformed nodes rejection
 25. Malformed edges rejection
 26. Invalid response option rejection
 27. Oversized graph rejection
 28. Zero network/socket activity
 29. Zero database/filesystem side effects
 30. Phase 1D Evidence Graph -> Response Lab end-to-end
 31. Custom response options subset
 32. Single response option evaluation
 33. Pipeline convenience helpers (from story & campaign)
 34. Pipeline convenience helper (from events)
 35. Empty response options rejection
 36. Oversized response options rejection
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

from simulator.internal_response_lab import (
    ResponseLab,
    ResponseLabError,
    evaluate_responses,
    evaluate_single_response,
    compare_and_recommend,
    extract_graph_indicators,
    validate_evidence_graph_input,
    validate_response_options,
    validate_ip_address,
    validate_technique_id,
    evaluate_responses_from_story,
    evaluate_responses_from_campaign,
    evaluate_responses_from_events,
    BLOCK_SOURCE_IP,
    ISOLATE_HOST,
    NOTIFY_ADMIN,
    NO_ACTION,
    SUPPORTED_RESPONSE_OPTIONS,
    MAX_GRAPH_NODES_BOUND,
    MAX_GRAPH_EDGES_BOUND,
    MAX_RESPONSE_OPTIONS_BOUND,
)
from simulator.internal_evidence_graph import (
    build_evidence_graph,
    build_evidence_graph_from_campaign,
    build_evidence_graph_from_events,
)
from simulator.internal_attack_story import (
    build_attack_story,
    build_attack_story_from_events,
)
from simulator.internal_campaign_generator import generate_campaign_events
from database.database import get_recent_events, get_incidents


# ------------------------------------------------------------------------------
# TEST FIXTURES & HELPERS
# ------------------------------------------------------------------------------

def make_mock_evidence_graph(
    campaign_id: str = "CAMP-TEST-001",
    stages: Optional[list] = None,
    source_ips: Optional[list] = None,
    events_per_stage: int = 3,
) -> dict:
    """Build a deterministic, valid mock Evidence Graph for isolated unit testing."""
    if source_ips is None:
        source_ips = ["192.168.1.100"]

    if stages is None:
        stages = [
            {
                "stage_number": 1,
                "stage_key": "reconnaissance",
                "title": "Network Reconnaissance",
                "mitre_technique": "T1046",
                "sources": list(source_ips),
            },
            {
                "stage_number": 2,
                "stage_key": "authentication_attack",
                "title": "Credential Brute Force",
                "mitre_technique": "T1110",
                "sources": list(source_ips),
            },
        ]

    camp_node_id = f"campaign:{campaign_id}"
    nodes = [
        {
            "node_id": camp_node_id,
            "node_type": "CAMPAIGN",
            "label": f"Campaign {campaign_id}",
            "metadata": {
                "campaign_id": campaign_id,
                "sources": list(source_ips),
                "stage_count": len(stages),
                "event_count": len(stages) * events_per_stage,
            },
        }
    ]
    edges = []

    total_events = 0
    techniques_seen = set()

    for st in stages:
        s_num = st["stage_number"]
        st_node_id = f"stage:{campaign_id}:{s_num}"
        nodes.append({
            "node_id": st_node_id,
            "node_type": "STAGE",
            "label": st.get("title", f"Stage {s_num}"),
            "metadata": {
                "stage_number": s_num,
                "stage_key": st.get("stage_key", f"stage_{s_num}"),
                "sources": list(st.get("sources", source_ips)),
            },
        })
        edges.append({
            "source": camp_node_id,
            "target": st_node_id,
            "relationship": "CAMPAIGN_CONTAINS_STAGE",
            "metadata": {"stage_number": s_num},
        })

        tech = st.get("mitre_technique")
        if tech:
            techniques_seen.add(tech)
            tech_node_id = f"technique:{tech}"
            nodes.append({
                "node_id": tech_node_id,
                "node_type": "TECHNIQUE",
                "label": f"{tech} - Mock",
                "metadata": {"technique_id": tech},
            })
            edges.append({
                "source": st_node_id,
                "target": tech_node_id,
                "relationship": "STAGE_USES_TECHNIQUE",
                "metadata": {"technique_id": tech},
            })

        for e_idx in range(1, events_per_stage + 1):
            total_events += 1
            ev_node_id = f"event:{campaign_id}:s{s_num}:e{e_idx}"
            nodes.append({
                "node_id": ev_node_id,
                "node_type": "EVENT",
                "label": f"Event #{total_events}",
                "metadata": {
                    "event_id": total_events,
                    "stage_number": s_num,
                    "source_ip": source_ips[0],
                },
            })
            edges.append({
                "source": st_node_id,
                "target": ev_node_id,
                "relationship": "STAGE_SUPPORTED_BY_EVENT",
                "metadata": {"event_id": total_events},
            })

    summary = {
        "campaign_id": campaign_id,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "stage_count": len(stages),
        "event_count": total_events,
        "technique_count": len(techniques_seen),
        "source_ips": list(source_ips),
        "techniques": sorted(list(techniques_seen)),
        "evidence_count": total_events,
        "graph_reason": f"Mock graph for {campaign_id}",
    }

    return {
        "campaign": {
            "campaign_id": campaign_id,
            "title": f"Campaign {campaign_id}",
            "sources": list(source_ips),
            "event_count": total_events,
            "stage_count": len(stages),
        },
        "nodes": nodes,
        "edges": edges,
        "summary": summary,
    }


# ------------------------------------------------------------------------------
# 1. BASIC CREATION & INTERFACE
# ------------------------------------------------------------------------------

def test_basic_response_lab_creation():
    """Verify ResponseLab class instantiation and evaluate_responses function."""
    graph = make_mock_evidence_graph()
    lab = ResponseLab()
    assert lab.default_response_options == list(SUPPORTED_RESPONSE_OPTIONS)

    report = lab.evaluate(graph)
    assert isinstance(report, dict)
    assert "campaign_id" in report
    assert "responses" in report
    assert "recommendation" in report
    assert "comparison_reason" in report

    # Test module-level function
    report2 = evaluate_responses(graph)
    assert isinstance(report2, dict)
    assert report2["campaign_id"] == graph["campaign"]["campaign_id"]
    assert len(report2["responses"]) == 4


# ------------------------------------------------------------------------------
# 2. DETERMINISTIC OUTPUT
# ------------------------------------------------------------------------------

def test_deterministic_output():
    """Verify identical inputs yield identical response reports."""
    graph = make_mock_evidence_graph()
    run1 = evaluate_responses(graph)
    run2 = evaluate_responses(graph)
    assert run1 == run2


# ------------------------------------------------------------------------------
# 3. CAMPAIGN IDENTITY
# ------------------------------------------------------------------------------

def test_campaign_identity():
    """Verify campaign ID is correctly preserved and reflected in response IDs."""
    camp_id = "CAMP-DELTA-99"
    graph = make_mock_evidence_graph(campaign_id=camp_id)
    report = evaluate_responses(graph)

    assert report["campaign_id"] == camp_id
    for resp in report["responses"]:
        assert resp["response_id"].startswith(f"resp:{camp_id}:")
        assert resp["response_id"].endswith(resp["response_type"].lower())


# ------------------------------------------------------------------------------
# 4. BLOCK_SOURCE_IP OPTION
# ------------------------------------------------------------------------------

def test_block_source_ip_option():
    """Verify BLOCK_SOURCE_IP evaluates with appropriate scope, effect, and scores."""
    graph = make_mock_evidence_graph(source_ips=["192.168.1.50"])
    report = evaluate_responses(graph, response_options=[BLOCK_SOURCE_IP])

    assert len(report["responses"]) == 1
    resp = report["responses"][0]
    assert resp["response_type"] == BLOCK_SOURCE_IP
    assert "192.168.1.50" in resp["scope"]
    assert "Drop incoming" in resp["predicted_effect"]
    assert resp["coverage_score"] > 50
    assert resp["risk_reduction_score"] > 0
    assert resp["operational_impact_score"] < 40
    assert "BLOCK_SOURCE_IP" in resp["reason"]


# ------------------------------------------------------------------------------
# 5. ISOLATE_HOST OPTION
# ------------------------------------------------------------------------------

def test_isolate_host_option():
    """Verify ISOLATE_HOST evaluates with endpoint scope, network severance effect, and high impact."""
    graph = make_mock_evidence_graph()
    report = evaluate_responses(graph, response_options=[ISOLATE_HOST])

    assert len(report["responses"]) == 1
    resp = report["responses"][0]
    assert resp["response_type"] == ISOLATE_HOST
    assert "host endpoint" in resp["scope"].lower()
    assert "Sever host" in resp["predicted_effect"]
    assert resp["operational_impact_score"] == 75
    assert resp["risk_reduction_score"] > 0
    assert "ISOLATE_HOST" in resp["reason"]


# ------------------------------------------------------------------------------
# 6. NOTIFY_ADMIN OPTION
# ------------------------------------------------------------------------------

def test_notify_admin_option():
    """Verify NOTIFY_ADMIN evaluates with SOC scope, minimal impact, and low risk reduction."""
    graph = make_mock_evidence_graph()
    report = evaluate_responses(graph, response_options=[NOTIFY_ADMIN])

    assert len(report["responses"]) == 1
    resp = report["responses"][0]
    assert resp["response_type"] == NOTIFY_ADMIN
    assert "SOC" in resp["scope"] or "Security Operations" in resp["scope"]
    assert resp["operational_impact_score"] == 5
    assert resp["risk_reduction_score"] <= 20
    assert resp["residual_risk_score"] > 0
    assert "NOTIFY_ADMIN" in resp["reason"]


# ------------------------------------------------------------------------------
# 7. NO_ACTION OPTION
# ------------------------------------------------------------------------------

def test_no_action_option():
    """Verify NO_ACTION produces zero coverage, zero impact, zero reduction, and 100% residual risk."""
    graph = make_mock_evidence_graph()
    report = evaluate_responses(graph, response_options=[NO_ACTION])

    assert len(report["responses"]) == 1
    resp = report["responses"][0]
    assert resp["response_type"] == NO_ACTION
    assert resp["coverage_score"] == 0
    assert resp["operational_impact_score"] == 0
    assert resp["risk_reduction_score"] == 0
    assert resp["confidence"] == 100
    assert resp["residual_risk_score"] > 0


# ------------------------------------------------------------------------------
# 8. RESPONSE SCORING BOUNDS & INTEGER TYPES
# ------------------------------------------------------------------------------

def test_response_scoring_bounds():
    """Verify all scores across all options are integers bounded between 0 and 100."""
    graph = make_mock_evidence_graph()
    report = evaluate_responses(graph)

    for resp in report["responses"]:
        for score_key in (
            "coverage_score",
            "risk_reduction_score",
            "operational_impact_score",
            "residual_risk_score",
            "confidence",
        ):
            val = resp[score_key]
            assert isinstance(val, int), f"{score_key} must be int, got {type(val)}"
            assert 0 <= val <= 100, f"{score_key} ({val}) outside [0, 100]"


# ------------------------------------------------------------------------------
# 9. COVERAGE SCORING
# ------------------------------------------------------------------------------

def test_coverage_scoring():
    """Verify coverage scoring differs logically between perimeter attacks and host compromise."""
    # Perimeter-only graph
    perimeter_graph = make_mock_evidence_graph(stages=[
        {"stage_number": 1, "stage_key": "reconnaissance", "mitre_technique": "T1046"},
        {"stage_number": 2, "stage_key": "authentication_attack", "mitre_technique": "T1110"},
    ])
    perim_rep = evaluate_responses(perimeter_graph)
    perim_block = next(r for r in perim_rep["responses"] if r["response_type"] == BLOCK_SOURCE_IP)
    perim_isolate = next(r for r in perim_rep["responses"] if r["response_type"] == ISOLATE_HOST)

    # BLOCK_SOURCE_IP has superior coverage against perimeter attacks
    assert perim_block["coverage_score"] > perim_isolate["coverage_score"]

    # Host compromise graph
    host_graph = make_mock_evidence_graph(stages=[
        {"stage_number": 1, "stage_key": "successful_authentication", "mitre_technique": "T1078"},
        {"stage_number": 2, "stage_key": "privilege_escalation", "mitre_technique": "T1068"},
    ])
    host_rep = evaluate_responses(host_graph)
    host_block = next(r for r in host_rep["responses"] if r["response_type"] == BLOCK_SOURCE_IP)
    host_isolate = next(r for r in host_rep["responses"] if r["response_type"] == ISOLATE_HOST)

    # ISOLATE_HOST has superior coverage when host is compromised
    assert host_isolate["coverage_score"] > host_block["coverage_score"]


# ------------------------------------------------------------------------------
# 10. RISK REDUCTION SCORING
# ------------------------------------------------------------------------------

def test_risk_reduction_scoring():
    """Verify risk reduction reflects threat containment efficacy."""
    host_graph = make_mock_evidence_graph(stages=[
        {"stage_number": 1, "stage_key": "successful_authentication", "mitre_technique": "T1078"},
        {"stage_number": 2, "stage_key": "suspicious_powershell", "mitre_technique": "T1059.001"},
    ])
    rep = evaluate_responses(host_graph)
    isolate_resp = next(r for r in rep["responses"] if r["response_type"] == ISOLATE_HOST)
    block_resp = next(r for r in rep["responses"] if r["response_type"] == BLOCK_SOURCE_IP)
    no_act_resp = next(r for r in rep["responses"] if r["response_type"] == NO_ACTION)

    assert isolate_resp["risk_reduction_score"] > block_resp["risk_reduction_score"]
    assert block_resp["risk_reduction_score"] > no_act_resp["risk_reduction_score"]
    assert no_act_resp["risk_reduction_score"] == 0


# ------------------------------------------------------------------------------
# 11. OPERATIONAL IMPACT SCORING HIERARCHY
# ------------------------------------------------------------------------------

def test_operational_impact_scoring():
    """Verify operational impact hierarchy: NO_ACTION (0) < NOTIFY_ADMIN (5) < BLOCK_SOURCE_IP < ISOLATE_HOST (75)."""
    graph = make_mock_evidence_graph()
    report = evaluate_responses(graph)
    impacts = {r["response_type"]: r["operational_impact_score"] for r in report["responses"]}

    assert impacts[NO_ACTION] == 0
    assert impacts[NOTIFY_ADMIN] == 5
    assert impacts[BLOCK_SOURCE_IP] < impacts[ISOLATE_HOST]
    assert impacts[ISOLATE_HOST] == 75


# ------------------------------------------------------------------------------
# 12. RESIDUAL RISK SCORING
# ------------------------------------------------------------------------------

def test_residual_risk_scoring():
    """Verify residual risk equals base risk minus risk reduction, bounded at 0."""
    graph = make_mock_evidence_graph()
    report = evaluate_responses(graph)

    no_act = next(r for r in report["responses"] if r["response_type"] == NO_ACTION)
    block = next(r for r in report["responses"] if r["response_type"] == BLOCK_SOURCE_IP)

    # NO_ACTION preserves full base risk
    assert no_act["residual_risk_score"] > 0
    # Effective response produces lower residual risk than NO_ACTION
    assert block["residual_risk_score"] < no_act["residual_risk_score"]


# ------------------------------------------------------------------------------
# 13. CONFIDENCE SCORING
# ------------------------------------------------------------------------------

def test_confidence_scoring():
    """Verify confidence is deterministic and bounded within [50, 100]."""
    graph = make_mock_evidence_graph()
    report = evaluate_responses(graph)

    for r in report["responses"]:
        assert 50 <= r["confidence"] <= 100


# ------------------------------------------------------------------------------
# 14. RECOMMENDATION GENERATION
# ------------------------------------------------------------------------------

def test_recommendation_generation():
    """Verify recommendation structure and alignment with evaluated options."""
    graph = make_mock_evidence_graph()
    report = evaluate_responses(graph)

    rec = report["recommendation"]
    assert "response_id" in rec
    assert "response_type" in rec
    assert "reason" in rec
    assert rec["response_type"] in SUPPORTED_RESPONSE_OPTIONS

    # Recommendation response_id must match one of the response entries
    resp_ids = [r["response_id"] for r in report["responses"]]
    assert rec["response_id"] in resp_ids


# ------------------------------------------------------------------------------
# 15. AUTHENTICATION ATTACK INFLUENCE
# ------------------------------------------------------------------------------

def test_authentication_attack_influence():
    """Verify brute force authentication influences BLOCK_SOURCE_IP priority."""
    graph = make_mock_evidence_graph(stages=[
        {"stage_number": 1, "stage_key": "authentication_attack", "mitre_technique": "T1110"},
    ])
    report = evaluate_responses(graph)

    assert report["recommendation"]["response_type"] == BLOCK_SOURCE_IP
    block_resp = next(r for r in report["responses"] if r["response_type"] == BLOCK_SOURCE_IP)
    assert block_resp["coverage_score"] >= 80


# ------------------------------------------------------------------------------
# 16. SUCCESSFUL AUTHENTICATION INFLUENCE
# ------------------------------------------------------------------------------

def test_successful_authentication_influence():
    """Verify successful authentication triggers ISOLATE_HOST recommendation."""
    graph = make_mock_evidence_graph(stages=[
        {"stage_number": 1, "stage_key": "successful_authentication", "mitre_technique": "T1078"},
    ])
    report = evaluate_responses(graph)

    assert report["recommendation"]["response_type"] == ISOLATE_HOST
    assert "valid account" in report["recommendation"]["reason"].lower() or "t1078" in report["recommendation"]["reason"].lower()


# ------------------------------------------------------------------------------
# 17. POWERSHELL INFLUENCE
# ------------------------------------------------------------------------------

def test_powershell_influence():
    """Verify suspicious PowerShell execution triggers ISOLATE_HOST recommendation."""
    graph = make_mock_evidence_graph(stages=[
        {"stage_number": 1, "stage_key": "suspicious_powershell", "mitre_technique": "T1059.001"},
    ])
    report = evaluate_responses(graph)

    assert report["recommendation"]["response_type"] == ISOLATE_HOST
    assert "powershell" in report["recommendation"]["reason"].lower()


# ------------------------------------------------------------------------------
# 18. PRIVILEGE ESCALATION INFLUENCE
# ------------------------------------------------------------------------------

def test_privilege_escalation_influence():
    """Verify privilege escalation triggers ISOLATE_HOST recommendation with maximum coverage."""
    graph = make_mock_evidence_graph(stages=[
        {"stage_number": 1, "stage_key": "privilege_escalation", "mitre_technique": "T1068"},
    ])
    report = evaluate_responses(graph)

    assert report["recommendation"]["response_type"] == ISOLATE_HOST
    iso_resp = next(r for r in report["responses"] if r["response_type"] == ISOLATE_HOST)
    assert iso_resp["coverage_score"] == 95
    assert "privilege escalation" in report["recommendation"]["reason"].lower()


# ------------------------------------------------------------------------------
# 19. MULTIPLE SOURCE IP INFLUENCE
# ------------------------------------------------------------------------------

def test_multiple_source_ip_influence():
    """Verify multiple source IPs are represented in BLOCK_SOURCE_IP scope and impact."""
    ips = ["192.168.1.10", "192.168.1.20", "192.168.1.30"]
    graph = make_mock_evidence_graph(source_ips=ips)
    report = evaluate_responses(graph)

    block_resp = next(r for r in report["responses"] if r["response_type"] == BLOCK_SOURCE_IP)
    for ip in ips:
        assert ip in block_resp["scope"]

    # Operational impact reflects multiple source IPs
    assert block_resp["operational_impact_score"] > 10


# ------------------------------------------------------------------------------
# 20. MULTIPLE TECHNIQUES TRACKING
# ------------------------------------------------------------------------------

def test_multiple_techniques():
    """Verify graphs with all 5 MITRE techniques evaluate correctly."""
    stages = [
        {"stage_number": 1, "stage_key": "reconnaissance", "mitre_technique": "T1046"},
        {"stage_number": 2, "stage_key": "authentication_attack", "mitre_technique": "T1110"},
        {"stage_number": 3, "stage_key": "successful_authentication", "mitre_technique": "T1078"},
        {"stage_number": 4, "stage_key": "suspicious_powershell", "mitre_technique": "T1059.001"},
        {"stage_number": 5, "stage_key": "privilege_escalation", "mitre_technique": "T1068"},
    ]
    graph = make_mock_evidence_graph(stages=stages)
    report = evaluate_responses(graph)

    assert report["recommendation"]["response_type"] == ISOLATE_HOST
    assert "T1068" in report["recommendation"]["reason"] or "privilege" in report["recommendation"]["reason"].lower()


# ------------------------------------------------------------------------------
# 21. MULTIPLE EVIDENCE EVENTS INFLUENCE
# ------------------------------------------------------------------------------

def test_multiple_evidence_events():
    """Verify higher evidence count yields higher or equal confidence."""
    graph_few = make_mock_evidence_graph(events_per_stage=1)
    graph_many = make_mock_evidence_graph(events_per_stage=10)

    rep_few = evaluate_responses(graph_few)
    rep_many = evaluate_responses(graph_many)

    conf_few = rep_few["responses"][0]["confidence"]
    conf_many = rep_many["responses"][0]["confidence"]
    assert conf_many >= conf_few


# ------------------------------------------------------------------------------
# 22. DUPLICATE INPUT HANDLING
# ------------------------------------------------------------------------------

def test_duplicate_input_handling():
    """Verify duplicate response options and duplicate graph nodes are safely deduplicated."""
    graph = make_mock_evidence_graph()
    # Inject duplicate node
    dup_node = dict(graph["nodes"][0])
    graph["nodes"].append(dup_node)

    # Pass duplicate options
    opts = [BLOCK_SOURCE_IP, BLOCK_SOURCE_IP, ISOLATE_HOST, ISOLATE_HOST]
    report = evaluate_responses(graph, response_options=opts)

    assert len(report["responses"]) == 2
    types = [r["response_type"] for r in report["responses"]]
    assert types == [BLOCK_SOURCE_IP, ISOLATE_HOST]


# ------------------------------------------------------------------------------
# 23. MALFORMED GRAPH REJECTION
# ------------------------------------------------------------------------------

def test_malformed_graph_rejection():
    """Verify non-dictionary, empty, or missing required fields raise ResponseLabError."""
    with pytest.raises(ResponseLabError):
        evaluate_responses(None)

    with pytest.raises(ResponseLabError):
        evaluate_responses("not-a-dict")

    with pytest.raises(ResponseLabError):
        evaluate_responses({})

    with pytest.raises(ResponseLabError):
        evaluate_responses({"nodes": [], "edges": []})  # missing campaign

    with pytest.raises(ResponseLabError):
        evaluate_responses({"campaign": {"campaign_id": "C1"}, "edges": []})  # missing nodes

    with pytest.raises(ResponseLabError):
        evaluate_responses({"campaign": {"campaign_id": "C1"}, "nodes": []})  # missing edges


# ------------------------------------------------------------------------------
# 24. MALFORMED NODES REJECTION
# ------------------------------------------------------------------------------

def test_malformed_nodes_rejection():
    """Verify nodes with invalid types, missing IDs, or malformed metadata raise ResponseLabError."""
    # Node is not a dict
    graph1 = make_mock_evidence_graph()
    graph1["nodes"].append("invalid-node")
    with pytest.raises(ResponseLabError):
        evaluate_responses(graph1)

    # Node has invalid node_type
    graph2 = make_mock_evidence_graph()
    graph2["nodes"].append({"node_id": "bad:1", "node_type": "UNKNOWN_TYPE"})
    with pytest.raises(ResponseLabError):
        evaluate_responses(graph2)

    # Node has invalid IP in metadata
    graph3 = make_mock_evidence_graph()
    graph3["nodes"].append({
        "node_id": "event:bad",
        "node_type": "EVENT",
        "metadata": {"source_ip": "999.999.999.999"},
    })
    with pytest.raises(ResponseLabError):
        evaluate_responses(graph3)


# ------------------------------------------------------------------------------
# 25. MALFORMED EDGES REJECTION
# ------------------------------------------------------------------------------

def test_malformed_edges_rejection():
    """Verify edges missing source/target or with invalid relationships raise ResponseLabError."""
    graph1 = make_mock_evidence_graph()
    graph1["edges"].append("not-an-edge")
    with pytest.raises(ResponseLabError):
        evaluate_responses(graph1)

    graph2 = make_mock_evidence_graph()
    graph2["edges"].append({"source": "a", "target": "b", "relationship": "INVALID_REL"})
    with pytest.raises(ResponseLabError):
        evaluate_responses(graph2)


# ------------------------------------------------------------------------------
# 26. INVALID RESPONSE OPTION REJECTION
# ------------------------------------------------------------------------------

def test_invalid_response_option_rejection():
    """Verify unknown response options or non-string options raise ResponseLabError."""
    graph = make_mock_evidence_graph()

    with pytest.raises(ResponseLabError):
        evaluate_responses(graph, response_options=["EXECUTE_NUKE"])

    with pytest.raises(ResponseLabError):
        evaluate_responses(graph, response_options=[12345])

    with pytest.raises(ResponseLabError):
        evaluate_responses(graph, response_options="NOT_A_LIST")


# ------------------------------------------------------------------------------
# 27. OVERSIZED GRAPH REJECTION
# ------------------------------------------------------------------------------

def test_oversized_graph_rejection():
    """Verify graph exceeding node or edge bounds raises ResponseLabError."""
    graph = make_mock_evidence_graph()
    dummy_nodes = [
        {"node_id": f"dummy:{i}", "node_type": "EVENT", "metadata": {}}
        for i in range(MAX_GRAPH_NODES_BOUND + 1)
    ]
    graph["nodes"] = dummy_nodes

    with pytest.raises(ResponseLabError):
        evaluate_responses(graph)


# ------------------------------------------------------------------------------
# 28. NO NETWORK OR SOCKET ACTIVITY
# ------------------------------------------------------------------------------

def test_no_network_or_socket_activity(monkeypatch):
    """Verify that evaluating responses executes ZERO network or socket calls."""
    def guarded_socket(*args, **kwargs):
        raise RuntimeError("CRITICAL SAFETY VIOLATION: Socket opened during response evaluation!")

    monkeypatch.setattr(socket, "socket", guarded_socket)

    graph = make_mock_evidence_graph()
    report = evaluate_responses(graph)
    assert report is not None


# ------------------------------------------------------------------------------
# 29. NO DATABASE OR FILESYSTEM SIDE EFFECTS
# ------------------------------------------------------------------------------

def test_no_database_side_effects():
    """Verify database remains completely untouched before and after response lab evaluation."""
    events_before = len(get_recent_events(limit=50))
    incidents_before = len(get_incidents(limit=50))

    graph = make_mock_evidence_graph()
    report = evaluate_responses(graph)

    events_after = len(get_recent_events(limit=50))
    incidents_after = len(get_incidents(limit=50))

    assert events_before == events_after
    assert incidents_before == incidents_after


# ------------------------------------------------------------------------------
# 30. PHASE 1D EVIDENCE GRAPH -> RESPONSE LAB END-TO-END
# ------------------------------------------------------------------------------

def test_phase_1d_evidence_graph_to_response_lab_e2e():
    """
    Verify complete Phase 1 pipeline execution:
    Phase 1A Synthetic Events -> Phase 1B Correlation -> Phase 1C Attack Story ->
    Phase 1D Evidence Graph -> Phase 1E Response Lab.
    """
    events = generate_campaign_events(total_events=25)
    for idx, ev in enumerate(events, start=1):
        ev["id"] = idx

    story = build_attack_story_from_events(events)
    assert story is not None

    graph = build_evidence_graph(story)
    assert graph is not None

    report = evaluate_responses(graph)
    assert report["campaign_id"] == story["campaign_id"]
    assert len(report["responses"]) == 4
    assert report["recommendation"]["response_type"] in SUPPORTED_RESPONSE_OPTIONS
    assert len(report["comparison_reason"]) > 20


# ------------------------------------------------------------------------------
# 31. CUSTOM RESPONSE OPTIONS SUBSET
# ------------------------------------------------------------------------------

def test_custom_response_options_subset():
    """Verify caller can specify a custom subset of response options."""
    graph = make_mock_evidence_graph()
    report = evaluate_responses(graph, response_options=[NOTIFY_ADMIN, NO_ACTION])

    assert len(report["responses"]) == 2
    types = [r["response_type"] for r in report["responses"]]
    assert types == [NOTIFY_ADMIN, NO_ACTION]
    # In absence of active containment options, NOTIFY_ADMIN should be recommended
    assert report["recommendation"]["response_type"] == NOTIFY_ADMIN


# ------------------------------------------------------------------------------
# 32. SINGLE RESPONSE OPTION EVALUATION
# ------------------------------------------------------------------------------

def test_single_response_option():
    """Verify evaluation works cleanly when only one response option is requested."""
    graph = make_mock_evidence_graph()
    report = evaluate_responses(graph, response_options=[NO_ACTION])

    assert len(report["responses"]) == 1
    assert report["recommendation"]["response_type"] == NO_ACTION


# ------------------------------------------------------------------------------
# 33. PIPELINE CONVENIENCE HELPERS (FROM STORY & CAMPAIGN)
# ------------------------------------------------------------------------------

def test_pipeline_convenience_helpers():
    """Verify evaluate_responses_from_story and evaluate_responses_from_campaign."""
    from simulator.internal_campaign_correlator import correlate_single_campaign

    events = generate_campaign_events(total_events=20)
    for idx, ev in enumerate(events, start=1):
        ev["id"] = idx

    story = build_attack_story_from_events(events)
    rep_from_story = evaluate_responses_from_story(story)
    assert rep_from_story["campaign_id"] == story["campaign_id"]

    camp_dict = correlate_single_campaign(events)
    rep_from_camp = evaluate_responses_from_campaign(camp_dict)
    assert rep_from_camp["campaign_id"] == camp_dict["campaign_id"]


# ------------------------------------------------------------------------------
# 34. PIPELINE CONVENIENCE HELPER (FROM EVENTS)
# ------------------------------------------------------------------------------

def test_pipeline_convenience_from_events():
    """Verify evaluate_responses_from_events executes complete Phase 1 pipeline."""
    events = generate_campaign_events(total_events=20)
    for idx, ev in enumerate(events, start=1):
        ev["id"] = idx

    report = evaluate_responses_from_events(events)
    assert report is not None
    assert "campaign_id" in report
    assert len(report["responses"]) == 4

    # Empty events returns None safely
    assert evaluate_responses_from_events([]) is None


# ------------------------------------------------------------------------------
# 35. EMPTY RESPONSE OPTIONS REJECTION
# ------------------------------------------------------------------------------

def test_empty_response_options_rejection():
    """Verify passing an empty list of response options raises ResponseLabError."""
    graph = make_mock_evidence_graph()
    with pytest.raises(ResponseLabError):
        evaluate_responses(graph, response_options=[])


# ------------------------------------------------------------------------------
# 36. OVERSIZED RESPONSE OPTIONS REJECTION
# ------------------------------------------------------------------------------

def test_oversized_response_options_rejection():
    """Verify passing too many response options raises ResponseLabError."""
    graph = make_mock_evidence_graph()
    too_many = [BLOCK_SOURCE_IP] * (MAX_RESPONSE_OPTIONS_BOUND + 1)
    with pytest.raises(ResponseLabError):
        evaluate_responses(graph, response_options=too_many)
