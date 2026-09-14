"""
Unit & Integration Tests for Internal Deterministic Policy Engine (Phase 1G)
===========================================================================
Comprehensive test suite covering:
  1. Basic policy engine creation & interface
  2. Deterministic output reproducibility
  3. Campaign identity consistency across Phase 1D, 1E, 1F, 1G
  4. BLOCK_SOURCE_IP recommendation & RECOMMEND decision state
  5. ISOLATE_HOST recommendation & RECOMMEND decision state
  6. NOTIFY_ADMIN recommendation & REVIEW decision state
  7. NO_ACTION handling & NO_ACTION decision state
  8. Policy scoring bounds & types
  9. Confidence bounds & progression
 10. Residual risk tracking in policy factors
 11. Containment effectiveness in policy factors
 12. Service impact in policy factors
 13. Blast radius in policy factors
 14. Successful authentication influence (T1078)
 15. PowerShell execution influence (T1059.001)
 16. Privilege escalation influence (T1068)
 17. Authentication attack influence (T1110)
 18. Reconnaissance influence (T1046)
 19. Multiple source IP influence
 20. Multiple techniques tracking
 21. Multiple stages influence on evidence strength
 22. Multiple evidence events influence
 23. Phase 1E score influence
 24. Phase 1F Cyber Twin score influence
 25. Malformed graph rejection
 26. Malformed Response Lab result rejection
 27. Malformed Cyber Twin result rejection
 28. Malformed nodes rejection
 29. Malformed edges rejection
 30. Invalid response rejection
 31. Duplicate handling (nodes, responses, simulations)
 32. Oversized input rejection
 33. Bounded processing enforcement [0, 100]
 34. Deterministic repeated evaluation
 35. Complete Phase 1D -> 1E -> 1F -> 1G End-to-End pipeline
 36. Zero network/socket activity
 37. Zero database/filesystem side effects
 38. Pipeline convenience helpers (graph, story, campaign, events)
 39. Alternatives matrix structure and ordering
 40. Decision state semantics (RECOMMEND, REVIEW, NO_ACTION)
"""

import ipaddress
import socket
import sys
from pathlib import Path
import pytest

# Ensure SentinelX root is on sys.path
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from policy.internal_policy_engine import (
    PolicyEngine,
    PolicyEngineError,
    evaluate_policy,
    evaluate_policy_from_graph,
    evaluate_policy_from_story,
    evaluate_policy_from_campaign,
    evaluate_policy_from_events,
    DECISION_RECOMMEND,
    DECISION_REVIEW,
    DECISION_NO_ACTION,
    VALID_DECISION_STATES,
    MAX_GRAPH_NODES_BOUND,
    MAX_GRAPH_EDGES_BOUND,
    MAX_RESPONSES_BOUND,
)
from simulator.internal_response_lab import (
    evaluate_responses,
    BLOCK_SOURCE_IP,
    ISOLATE_HOST,
    NOTIFY_ADMIN,
    NO_ACTION,
    SUPPORTED_RESPONSE_OPTIONS,
)
from simulator.internal_cyber_twin import (
    simulate_all_responses,
    simulate_response_impact,
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
from simulator.internal_campaign_correlator import correlate_single_campaign
from database.database import get_recent_events, get_incidents


# ------------------------------------------------------------------------------
# TEST FIXTURES & HELPERS
# ------------------------------------------------------------------------------

def make_test_pipeline_data(
    campaign_id: str = "CAMP-POL-001",
    stages: Optional[list] = None,
    source_ips: Optional[list] = None,
    events_per_stage: int = 3,
) -> tuple:
    """Build valid Phase 1D Graph, Phase 1E Lab Result, and Phase 1F Twin Result."""
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

    graph = {
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

    lab_result = evaluate_responses(graph)
    twin_result = simulate_all_responses(graph, lab_result)
    return graph, lab_result, twin_result


# ------------------------------------------------------------------------------
# 1. BASIC CREATION & INTERFACE
# ------------------------------------------------------------------------------

def test_basic_policy_engine_creation():
    """Verify PolicyEngine class instantiation, evaluate method, and evaluate_policy function."""
    graph, lab, twin = make_test_pipeline_data()
    engine = PolicyEngine()
    result = engine.evaluate(graph, lab, twin)

    assert isinstance(result, dict)
    assert "campaign_id" in result
    assert "decision" in result
    assert "alternatives" in result
    assert "policy_factors" in result
    assert "reason" in result
    assert "comparison_reason" in result

    # Check function-level API
    result2 = evaluate_policy(graph, lab, twin)
    assert result2 == result


# ------------------------------------------------------------------------------
# 2. DETERMINISTIC OUTPUT
# ------------------------------------------------------------------------------

def test_deterministic_output():
    """Verify identical inputs yield identical policy evaluation outputs."""
    graph, lab, twin = make_test_pipeline_data()
    res1 = evaluate_policy(graph, lab, twin)
    res2 = evaluate_policy(graph, lab, twin)
    assert res1 == res2


# ------------------------------------------------------------------------------
# 3. CAMPAIGN IDENTITY
# ------------------------------------------------------------------------------

def test_campaign_identity():
    """Verify campaign identity is strictly preserved in policy output."""
    camp_id = "CAMP-POL-XYZ-88"
    graph, lab, twin = make_test_pipeline_data(campaign_id=camp_id)
    res = evaluate_policy(graph, lab, twin)
    assert res["campaign_id"] == camp_id


# ------------------------------------------------------------------------------
# 4. BLOCK_SOURCE_IP RECOMMENDATION
# ------------------------------------------------------------------------------

def test_block_source_ip_recommendation():
    """Verify perimeter recon/brute-force results in BLOCK_SOURCE_IP RECOMMEND decision."""
    graph, lab, twin = make_test_pipeline_data(stages=[
        {"stage_number": 1, "stage_key": "reconnaissance", "mitre_technique": "T1046"},
        {"stage_number": 2, "stage_key": "authentication_attack", "mitre_technique": "T1110"},
    ])
    res = evaluate_policy(graph, lab, twin)

    assert res["decision"]["recommended_response"] == BLOCK_SOURCE_IP
    assert res["decision"]["decision"] == DECISION_RECOMMEND
    assert res["decision"]["policy_score"] >= 80
    assert "BLOCK_SOURCE_IP" in res["reason"]


# ------------------------------------------------------------------------------
# 5. ISOLATE_HOST RECOMMENDATION
# ------------------------------------------------------------------------------

def test_isolate_host_recommendation():
    """Verify host compromise indicators trigger ISOLATE_HOST RECOMMEND decision."""
    graph, lab, twin = make_test_pipeline_data(stages=[
        {"stage_number": 1, "stage_key": "successful_authentication", "mitre_technique": "T1078"},
        {"stage_number": 2, "stage_key": "suspicious_powershell", "mitre_technique": "T1059.001"},
        {"stage_number": 3, "stage_key": "privilege_escalation", "mitre_technique": "T1068"},
    ])
    res = evaluate_policy(graph, lab, twin)

    assert res["decision"]["recommended_response"] == ISOLATE_HOST
    assert res["decision"]["decision"] == DECISION_RECOMMEND
    assert res["decision"]["policy_score"] >= 85
    assert "ISOLATE_HOST" in res["reason"]


# ------------------------------------------------------------------------------
# 6. NOTIFY_ADMIN RECOMMENDATION
# ------------------------------------------------------------------------------

def test_notify_admin_recommendation():
    """Verify NOTIFY_ADMIN produces REVIEW decision state."""
    graph, lab, twin = make_test_pipeline_data()
    # Filter lab and twin to only contain NOTIFY_ADMIN and NO_ACTION
    lab_filtered = dict(lab)
    lab_filtered["responses"] = [r for r in lab["responses"] if r["response_type"] in (NOTIFY_ADMIN, NO_ACTION)]
    twin_filtered = dict(twin)
    twin_filtered["simulations"] = [s for s in twin["simulations"] if s["response_type"] in (NOTIFY_ADMIN, NO_ACTION)]
    twin_filtered["simulations_by_type"] = {
        k: v for k, v in twin["simulations_by_type"].items() if k in (NOTIFY_ADMIN, NO_ACTION)
    }

    res = evaluate_policy(graph, lab_filtered, twin_filtered)
    assert res["decision"]["recommended_response"] == NOTIFY_ADMIN
    assert res["decision"]["decision"] == DECISION_REVIEW


# ------------------------------------------------------------------------------
# 7. NO_ACTION HANDLING
# ------------------------------------------------------------------------------

def test_no_action_handling():
    """Verify NO_ACTION produces NO_ACTION decision state when evaluated alone."""
    graph, lab, twin = make_test_pipeline_data()
    lab_filtered = dict(lab)
    lab_filtered["responses"] = [r for r in lab["responses"] if r["response_type"] == NO_ACTION]
    twin_filtered = dict(twin)
    twin_filtered["simulations"] = [s for s in twin["simulations"] if s["response_type"] == NO_ACTION]
    twin_filtered["simulations_by_type"] = {
        k: v for k, v in twin["simulations_by_type"].items() if k == NO_ACTION
    }

    res = evaluate_policy(graph, lab_filtered, twin_filtered)
    assert res["decision"]["recommended_response"] == NO_ACTION
    assert res["decision"]["decision"] == DECISION_NO_ACTION
    assert res["decision"]["policy_score"] == 10


# ------------------------------------------------------------------------------
# 8. POLICY SCORING BOUNDS
# ------------------------------------------------------------------------------

def test_policy_scoring_bounds():
    """Verify all policy scores across decision and alternatives are integers in [0, 100]."""
    graph, lab, twin = make_test_pipeline_data()
    res = evaluate_policy(graph, lab, twin)

    rec_score = res["decision"]["policy_score"]
    assert isinstance(rec_score, int)
    assert 0 <= rec_score <= 100

    for alt in res["alternatives"]:
        ascore = alt["policy_score"]
        assert isinstance(ascore, int)
        assert 0 <= ascore <= 100


# ------------------------------------------------------------------------------
# 9. CONFIDENCE
# ------------------------------------------------------------------------------

def test_confidence_bounds():
    """Verify confidence in decision and policy_factors is bounded [50, 100]."""
    graph, lab, twin = make_test_pipeline_data()
    res = evaluate_policy(graph, lab, twin)

    assert 50 <= res["decision"]["confidence"] <= 100
    assert 50 <= res["policy_factors"]["confidence"] <= 100


# ------------------------------------------------------------------------------
# 10. RESIDUAL RISK
# ------------------------------------------------------------------------------

def test_residual_risk_in_policy_factors():
    """Verify residual risk is tracked in policy_factors and bounded [0, 100]."""
    graph, lab, twin = make_test_pipeline_data()
    res = evaluate_policy(graph, lab, twin)

    res_risk = res["policy_factors"]["residual_risk"]
    assert isinstance(res_risk, int)
    assert 0 <= res_risk <= 100


# ------------------------------------------------------------------------------
# 11. CONTAINMENT EFFECTIVENESS
# ------------------------------------------------------------------------------

def test_containment_effectiveness_in_policy_factors():
    """Verify containment effectiveness is tracked in policy_factors."""
    graph, lab, twin = make_test_pipeline_data()
    res = evaluate_policy(graph, lab, twin)

    eff = res["policy_factors"]["containment_effectiveness"]
    assert isinstance(eff, int)
    assert eff > 50


# ------------------------------------------------------------------------------
# 12. SERVICE IMPACT
# ------------------------------------------------------------------------------

def test_service_impact_in_policy_factors():
    """Verify service impact in policy_factors matches recommended response."""
    # Perimeter graph: BLOCK_SOURCE_IP recommended -> low service impact
    graph, lab, twin = make_test_pipeline_data()
    res = evaluate_policy(graph, lab, twin)
    assert res["policy_factors"]["service_impact"] <= 30


# ------------------------------------------------------------------------------
# 13. BLAST RADIUS
# ------------------------------------------------------------------------------

def test_blast_radius_in_policy_factors():
    """Verify blast radius in policy_factors matches recommended response."""
    graph, lab, twin = make_test_pipeline_data()
    res = evaluate_policy(graph, lab, twin)
    assert res["policy_factors"]["blast_radius"] <= 30


# ------------------------------------------------------------------------------
# 14. SUCCESSFUL AUTHENTICATION INFLUENCE
# ------------------------------------------------------------------------------

def test_successful_authentication_influence():
    """Verify T1078 valid accounts flips policy preference from BLOCK to ISOLATE."""
    graph, lab, twin = make_test_pipeline_data(stages=[
        {"stage_number": 1, "stage_key": "successful_authentication", "mitre_technique": "T1078"},
    ])
    res = evaluate_policy(graph, lab, twin)
    assert res["decision"]["recommended_response"] == ISOLATE_HOST


# ------------------------------------------------------------------------------
# 15. POWERSHELL INFLUENCE
# ------------------------------------------------------------------------------

def test_powershell_influence():
    """Verify T1059.001 PowerShell execution triggers ISOLATE_HOST policy recommendation."""
    graph, lab, twin = make_test_pipeline_data(stages=[
        {"stage_number": 1, "stage_key": "suspicious_powershell", "mitre_technique": "T1059.001"},
    ])
    res = evaluate_policy(graph, lab, twin)
    assert res["decision"]["recommended_response"] == ISOLATE_HOST


# ------------------------------------------------------------------------------
# 16. PRIVILEGE ESCALATION INFLUENCE
# ------------------------------------------------------------------------------

def test_privilege_escalation_influence():
    """Verify T1068 privilege escalation maximizes ISOLATE_HOST policy score."""
    graph, lab, twin = make_test_pipeline_data(stages=[
        {"stage_number": 1, "stage_key": "privilege_escalation", "mitre_technique": "T1068"},
    ])
    res = evaluate_policy(graph, lab, twin)
    assert res["decision"]["recommended_response"] == ISOLATE_HOST
    assert res["decision"]["policy_score"] >= 90


# ------------------------------------------------------------------------------
# 17. AUTHENTICATION ATTACK INFLUENCE
# ------------------------------------------------------------------------------

def test_authentication_attack_influence():
    """Verify T1110 brute force favors BLOCK_SOURCE_IP."""
    graph, lab, twin = make_test_pipeline_data(stages=[
        {"stage_number": 1, "stage_key": "authentication_attack", "mitre_technique": "T1110"},
    ])
    res = evaluate_policy(graph, lab, twin)
    assert res["decision"]["recommended_response"] == BLOCK_SOURCE_IP


# ------------------------------------------------------------------------------
# 18. RECONNAISSANCE INFLUENCE
# ------------------------------------------------------------------------------

def test_reconnaissance_influence():
    """Verify T1046 recon is factored into perimeter containment policy."""
    graph, lab, twin = make_test_pipeline_data(stages=[
        {"stage_number": 1, "stage_key": "reconnaissance", "mitre_technique": "T1046"},
    ])
    res = evaluate_policy(graph, lab, twin)
    assert res["decision"]["recommended_response"] == BLOCK_SOURCE_IP


# ------------------------------------------------------------------------------
# 19. MULTIPLE SOURCE IP INFLUENCE
# ------------------------------------------------------------------------------

def test_multiple_source_ip_influence():
    """Verify multiple adversary source IPs are noted in policy reason."""
    ips = ["192.168.1.10", "192.168.1.20", "192.168.1.30"]
    graph, lab, twin = make_test_pipeline_data(source_ips=ips)
    res = evaluate_policy(graph, lab, twin)

    assert "3 external IP" in res["reason"]


# ------------------------------------------------------------------------------
# 20. MULTIPLE TECHNIQUES INFLUENCE
# ------------------------------------------------------------------------------

def test_multiple_techniques_influence():
    """Verify 5-technique full attack story is evaluated with comprehensive policy factors."""
    stages = [
        {"stage_number": 1, "stage_key": "reconnaissance", "mitre_technique": "T1046"},
        {"stage_number": 2, "stage_key": "authentication_attack", "mitre_technique": "T1110"},
        {"stage_number": 3, "stage_key": "successful_authentication", "mitre_technique": "T1078"},
        {"stage_number": 4, "stage_key": "suspicious_powershell", "mitre_technique": "T1059.001"},
        {"stage_number": 5, "stage_key": "privilege_escalation", "mitre_technique": "T1068"},
    ]
    graph, lab, twin = make_test_pipeline_data(stages=stages)
    res = evaluate_policy(graph, lab, twin)

    assert res["decision"]["recommended_response"] == ISOLATE_HOST
    assert res["policy_factors"]["evidence_strength"] >= 75


# ------------------------------------------------------------------------------
# 21. MULTIPLE STAGES INFLUENCE
# ------------------------------------------------------------------------------

def test_multiple_stages_influence():
    """Verify more stages increase evidence strength factor."""
    graph_few, lab_few, twin_few = make_test_pipeline_data(stages=[
        {"stage_number": 1, "stage_key": "reconnaissance", "mitre_technique": "T1046"}
    ])
    graph_many, lab_many, twin_many = make_test_pipeline_data(stages=[
        {"stage_number": 1, "stage_key": "reconnaissance", "mitre_technique": "T1046"},
        {"stage_number": 2, "stage_key": "authentication_attack", "mitre_technique": "T1110"},
        {"stage_number": 3, "stage_key": "successful_authentication", "mitre_technique": "T1078"},
    ])

    res_few = evaluate_policy(graph_few, lab_few, twin_few)
    res_many = evaluate_policy(graph_many, lab_many, twin_many)

    assert res_many["policy_factors"]["evidence_strength"] >= res_few["policy_factors"]["evidence_strength"]


# ------------------------------------------------------------------------------
# 22. MULTIPLE EVIDENCE EVENTS INFLUENCE
# ------------------------------------------------------------------------------

def test_multiple_evidence_events_influence():
    """Verify higher evidence event count increases or maintains evidence strength."""
    g1, l1, t1 = make_test_pipeline_data(events_per_stage=1)
    g2, l2, t2 = make_test_pipeline_data(events_per_stage=10)

    res1 = evaluate_policy(g1, l1, t1)
    res2 = evaluate_policy(g2, l2, t2)

    assert res2["policy_factors"]["evidence_strength"] >= res1["policy_factors"]["evidence_strength"]


# ------------------------------------------------------------------------------
# 23. PHASE 1E INFLUENCE
# ------------------------------------------------------------------------------

def test_phase_1e_influence():
    """Verify Phase 1E response metrics influence policy evaluation."""
    graph, lab, twin = make_test_pipeline_data()
    res = evaluate_policy(graph, lab, twin)
    assert len(res["alternatives"]) == len(lab["responses"]) - 1


# ------------------------------------------------------------------------------
# 24. PHASE 1F INFLUENCE
# ------------------------------------------------------------------------------

def test_phase_1f_influence():
    """Verify Phase 1F Cyber Twin blast radius and impact flow into policy factors."""
    graph, lab, twin = make_test_pipeline_data()
    res = evaluate_policy(graph, lab, twin)

    rec_sim = twin["simulations_by_type"][res["decision"]["recommended_response"]]["simulation"]
    assert res["policy_factors"]["blast_radius"] == rec_sim["blast_radius_score"]
    assert res["policy_factors"]["service_impact"] == rec_sim["service_impact_score"]


# ------------------------------------------------------------------------------
# 25. MALFORMED GRAPH REJECTION
# ------------------------------------------------------------------------------

def test_malformed_graph_rejection():
    """Verify invalid Evidence Graph structures safely raise PolicyEngineError."""
    _, lab, twin = make_test_pipeline_data()

    with pytest.raises(PolicyEngineError):
        evaluate_policy(None, lab, twin)

    with pytest.raises(PolicyEngineError):
        evaluate_policy("not-a-dict", lab, twin)

    with pytest.raises(PolicyEngineError):
        evaluate_policy({}, lab, twin)

    with pytest.raises(PolicyEngineError):
        evaluate_policy({"campaign": {"campaign_id": "C1"}}, lab, twin)


# ------------------------------------------------------------------------------
# 26. MALFORMED RESPONSE LAB REJECTION
# ------------------------------------------------------------------------------

def test_malformed_response_lab_rejection():
    """Verify invalid Response Lab results safely raise PolicyEngineError."""
    graph, _, twin = make_test_pipeline_data()

    with pytest.raises(PolicyEngineError):
        evaluate_policy(graph, None, twin)

    with pytest.raises(PolicyEngineError):
        evaluate_policy(graph, {}, twin)

    # Campaign ID mismatch
    with pytest.raises(PolicyEngineError):
        evaluate_policy(graph, {"campaign_id": "WRONG_ID", "responses": []}, twin)


# ------------------------------------------------------------------------------
# 27. MALFORMED CYBER TWIN REJECTION
# ------------------------------------------------------------------------------

def test_malformed_cyber_twin_rejection():
    """Verify invalid Cyber Twin results safely raise PolicyEngineError."""
    graph, lab, _ = make_test_pipeline_data()

    with pytest.raises(PolicyEngineError):
        evaluate_policy(graph, lab, None)

    with pytest.raises(PolicyEngineError):
        evaluate_policy(graph, lab, {})

    # Campaign ID mismatch
    with pytest.raises(PolicyEngineError):
        evaluate_policy(graph, lab, {"campaign_id": "WRONG_ID", "simulations": []})


# ------------------------------------------------------------------------------
# 28. MALFORMED NODES REJECTION
# ------------------------------------------------------------------------------

def test_malformed_nodes_rejection():
    """Verify invalid nodes in graph raise PolicyEngineError."""
    graph, lab, twin = make_test_pipeline_data()
    graph["nodes"].append("not-a-node-dict")

    with pytest.raises(PolicyEngineError):
        evaluate_policy(graph, lab, twin)


# ------------------------------------------------------------------------------
# 29. MALFORMED EDGES REJECTION
# ------------------------------------------------------------------------------

def test_malformed_edges_rejection():
    """Verify invalid edges in graph raise PolicyEngineError."""
    graph, lab, twin = make_test_pipeline_data()
    graph["edges"].append({"source": "a", "target": "b", "relationship": "INVALID_REL"})

    with pytest.raises(PolicyEngineError):
        evaluate_policy(graph, lab, twin)


# ------------------------------------------------------------------------------
# 30. INVALID RESPONSE REJECTION
# ------------------------------------------------------------------------------

def test_invalid_response_rejection():
    """Verify unsupported response types in lab result raise PolicyEngineError."""
    graph, lab, twin = make_test_pipeline_data()
    bad_lab = dict(lab)
    bad_lab["responses"] = [{"response_type": "UNSUPPORTED_ACTION", "coverage_score": 50}]

    with pytest.raises(PolicyEngineError):
        evaluate_policy(graph, bad_lab, twin)


# ------------------------------------------------------------------------------
# 31. DUPLICATE HANDLING
# ------------------------------------------------------------------------------

def test_duplicate_handling():
    """Verify duplicate nodes and responses are deduplicated safely without crashing."""
    graph, lab, twin = make_test_pipeline_data()
    # Duplicate node
    graph["nodes"].append(dict(graph["nodes"][0]))
    # Duplicate response
    lab["responses"].append(dict(lab["responses"][0]))

    res = evaluate_policy(graph, lab, twin)
    assert res is not None


# ------------------------------------------------------------------------------
# 32. OVERSIZED INPUT REJECTION
# ------------------------------------------------------------------------------

def test_oversized_input_rejection():
    """Verify oversized inputs raise PolicyEngineError."""
    graph, lab, twin = make_test_pipeline_data()
    dummy_nodes = [
        {"node_id": f"dummy:{i}", "node_type": "EVENT", "metadata": {}}
        for i in range(MAX_GRAPH_NODES_BOUND + 1)
    ]
    graph["nodes"] = dummy_nodes

    with pytest.raises(PolicyEngineError):
        evaluate_policy(graph, lab, twin)


# ------------------------------------------------------------------------------
# 33. BOUNDED PROCESSING ENFORCEMENT
# ------------------------------------------------------------------------------

def test_bounded_processing_enforcement():
    """Verify all scores across policy result are bounded in [0, 100]."""
    graph, lab, twin = make_test_pipeline_data()
    res = evaluate_policy(graph, lab, twin)

    assert 0 <= res["decision"]["policy_score"] <= 100
    assert 0 <= res["decision"]["confidence"] <= 100

    for k, v in res["policy_factors"].items():
        assert isinstance(v, int)
        assert 0 <= v <= 100, f"Factor {k} ({v}) outside [0, 100]"

    for alt in res["alternatives"]:
        assert 0 <= alt["policy_score"] <= 100


# ------------------------------------------------------------------------------
# 34. DETERMINISTIC REPEATED EVALUATION
# ------------------------------------------------------------------------------

def test_deterministic_repeated_evaluation():
    """Verify 5 consecutive evaluations produce identical policy decisions."""
    graph, lab, twin = make_test_pipeline_data()
    first = evaluate_policy(graph, lab, twin)
    for _ in range(4):
        subsequent = evaluate_policy(graph, lab, twin)
        assert first == subsequent


# ------------------------------------------------------------------------------
# 35. PHASE 1D -> 1E -> 1F -> 1G END-TO-END
# ------------------------------------------------------------------------------

def test_phase_1d_to_1e_to_1f_to_1g_e2e():
    """
    Verify complete Phase 1 pipeline execution:
    1A Events -> 1B Campaign -> 1C Story -> 1D Graph -> 1E Lab -> 1F Twin -> 1G Policy.
    """
    events = generate_campaign_events(total_events=25)
    for idx, ev in enumerate(events, start=1):
        ev["id"] = idx

    story = build_attack_story_from_events(events)
    assert story is not None

    graph = build_evidence_graph(story)
    assert graph is not None

    lab_result = evaluate_responses(graph)
    assert lab_result is not None

    twin_result = simulate_all_responses(graph, lab_result)
    assert twin_result is not None

    policy_result = evaluate_policy(graph, lab_result, twin_result)
    assert policy_result["campaign_id"] == story["campaign_id"]
    assert policy_result["decision"]["decision"] in VALID_DECISION_STATES
    assert len(policy_result["alternatives"]) >= 1
    assert len(policy_result["comparison_reason"]) > 20


# ------------------------------------------------------------------------------
# 36. ZERO NETWORK OR SOCKET ACTIVITY
# ------------------------------------------------------------------------------

def test_no_network_or_socket_activity(monkeypatch):
    """Verify that Policy Engine executes ZERO network or socket operations."""
    def guarded_socket(*args, **kwargs):
        raise RuntimeError("CRITICAL SAFETY VIOLATION: Socket call attempted in Policy Engine!")

    monkeypatch.setattr(socket, "socket", guarded_socket)

    graph, lab, twin = make_test_pipeline_data()
    res = evaluate_policy(graph, lab, twin)
    assert res is not None


# ------------------------------------------------------------------------------
# 37. ZERO DATABASE OR FILESYSTEM SIDE EFFECTS
# ------------------------------------------------------------------------------

def test_no_database_side_effects():
    """Verify database remains completely untouched before and after Policy Engine evaluation."""
    events_before = len(get_recent_events(limit=50))
    incidents_before = len(get_incidents(limit=50))

    graph, lab, twin = make_test_pipeline_data()
    evaluate_policy(graph, lab, twin)

    events_after = len(get_recent_events(limit=50))
    incidents_after = len(get_incidents(limit=50))

    assert events_before == events_after
    assert incidents_before == incidents_after


# ------------------------------------------------------------------------------
# 38. PIPELINE CONVENIENCE HELPERS
# ------------------------------------------------------------------------------

def test_pipeline_convenience_helpers():
    """Verify convenience helpers evaluate policy from graph, story, campaign, and events."""
    events = generate_campaign_events(total_events=20)
    for idx, ev in enumerate(events, start=1):
        ev["id"] = idx

    # From events
    pol_from_events = evaluate_policy_from_events(events)
    assert pol_from_events is not None
    assert "decision" in pol_from_events

    # Empty events
    assert evaluate_policy_from_events([]) is None

    # From campaign
    camp_dict = correlate_single_campaign(events)
    pol_from_camp = evaluate_policy_from_campaign(camp_dict)
    assert pol_from_camp["campaign_id"] == camp_dict["campaign_id"]

    # From story
    story = build_attack_story_from_events(events)
    pol_from_story = evaluate_policy_from_story(story)
    assert pol_from_story["campaign_id"] == story["campaign_id"]

    # From graph
    graph = build_evidence_graph(story)
    pol_from_graph = evaluate_policy_from_graph(graph)
    assert pol_from_graph["campaign_id"] == graph["campaign"]["campaign_id"]


# ------------------------------------------------------------------------------
# 39. ALTERNATIVES MATRIX STRUCTURE & ORDERING
# ------------------------------------------------------------------------------

def test_alternatives_structure_and_ordering():
    """Verify alternatives matrix excludes recommended response and is sorted by score."""
    graph, lab, twin = make_test_pipeline_data()
    res = evaluate_policy(graph, lab, twin)

    rec_type = res["decision"]["recommended_response"]
    alt_types = [a["response_type"] for a in res["alternatives"]]
    assert rec_type not in alt_types

    # Verify descending score ordering
    scores = [a["policy_score"] for a in res["alternatives"]]
    assert scores == sorted(scores, reverse=True)


# ------------------------------------------------------------------------------
# 40. DECISION STATE SEMANTICS
# ------------------------------------------------------------------------------

def test_decision_state_semantics():
    """Verify RECOMMEND, REVIEW, and NO_ACTION states are properly assigned."""
    # RECOMMEND
    graph, lab, twin = make_test_pipeline_data()
    res_rec = evaluate_policy(graph, lab, twin)
    assert res_rec["decision"]["decision"] == DECISION_RECOMMEND

    # REVIEW
    lab_rev = dict(lab)
    lab_rev["responses"] = [r for r in lab["responses"] if r["response_type"] == NOTIFY_ADMIN]
    twin_rev = dict(twin)
    twin_rev["simulations"] = [s for s in twin["simulations"] if s["response_type"] == NOTIFY_ADMIN]
    twin_rev["simulations_by_type"] = {NOTIFY_ADMIN: twin["simulations_by_type"][NOTIFY_ADMIN]}
    res_rev = evaluate_policy(graph, lab_rev, twin_rev)
    assert res_rev["decision"]["decision"] == DECISION_REVIEW

    # NO_ACTION
    lab_no = dict(lab)
    lab_no["responses"] = [r for r in lab["responses"] if r["response_type"] == NO_ACTION]
    twin_no = dict(twin)
    twin_no["simulations"] = [s for s in twin["simulations"] if s["response_type"] == NO_ACTION]
    twin_no["simulations_by_type"] = {NO_ACTION: twin["simulations_by_type"][NO_ACTION]}
    res_no = evaluate_policy(graph, lab_no, twin_no)
    assert res_no["decision"]["decision"] == DECISION_NO_ACTION
