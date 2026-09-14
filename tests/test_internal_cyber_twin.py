"""
Unit & Integration Tests for Internal Cyber Twin Impact Simulation (Phase 1F)
============================================================================
Comprehensive test suite covering:
  1. Basic Cyber Twin creation & interface
  2. Deterministic output reproducibility
  3. Campaign identity consistency
  4. BLOCK_SOURCE_IP simulation
  5. ISOLATE_HOST simulation
  6. NOTIFY_ADMIN simulation
  7. NO_ACTION simulation
  8. Blast radius scoring hierarchy
  9. Service impact scoring hierarchy
 10. Containment effectiveness scoring logic
 11. Residual risk and risk change calculations
 12. Confidence scoring bounds
 13. Authentication attack influence
 14. Successful authentication influence
 15. PowerShell execution influence
 16. Privilege escalation influence
 17. Reconnaissance influence
 18. Multiple source IP influence
 19. Multiple techniques tracking
 20. Multiple evidence events handling
 21. Stage count influence
 22. Phase 1E score influence on containment
 23. Malformed graph rejection
 24. Malformed response lab result rejection
 25. Malformed nodes rejection
 26. Malformed edges rejection
 27. Invalid response option rejection
 28. Oversized input bounds enforcement
 29. Zero network/socket activity
 30. Zero database/filesystem side effects
 31. Deterministic repeated simulations
 32. Phase 1D -> Phase 1E -> Phase 1F end-to-end
 33. Duplicate handling (nodes & responses)
 34. Bounded score processing
 35. simulate_all_responses structure & comparison
 36. Pipeline convenience helpers (graph, story, campaign, events)
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

from simulator.internal_cyber_twin import (
    CyberTwin,
    CyberTwinError,
    simulate_response_impact,
    simulate_all_responses,
    extract_cyber_twin_features,
    validate_cyber_twin_inputs,
    simulate_response_from_graph,
    simulate_impact_from_story,
    simulate_impact_from_campaign,
    simulate_impact_from_events,
    BLOCK_SOURCE_IP,
    ISOLATE_HOST,
    NOTIFY_ADMIN,
    NO_ACTION,
    SUPPORTED_RESPONSE_OPTIONS,
    MAX_GRAPH_NODES_BOUND,
    MAX_GRAPH_EDGES_BOUND,
    MAX_RESPONSES_BOUND,
)
from simulator.internal_response_lab import (
    ResponseLab,
    evaluate_responses,
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

def make_test_graph_and_lab(
    campaign_id: str = "CAMP-TWIN-001",
    stages: Optional[list] = None,
    source_ips: Optional[list] = None,
    events_per_stage: int = 3,
) -> tuple:
    """Build a valid Evidence Graph and evaluate it with Phase 1E Response Lab."""
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
    return graph, lab_result


# ------------------------------------------------------------------------------
# 1. BASIC CREATION & INTERFACE
# ------------------------------------------------------------------------------

def test_basic_cyber_twin_creation():
    """Verify CyberTwin class instantiation and interface methods."""
    graph, lab_result = make_test_graph_and_lab()
    twin = CyberTwin()

    single_sim = twin.simulate_response(graph, lab_result, BLOCK_SOURCE_IP)
    assert isinstance(single_sim, dict)
    assert single_sim["campaign_id"] == graph["campaign"]["campaign_id"]
    assert single_sim["response_type"] == BLOCK_SOURCE_IP
    assert "simulation" in single_sim
    assert "comparison" in single_sim

    all_sim = twin.simulate_all(graph, lab_result)
    assert isinstance(all_sim, dict)
    assert "simulations" in all_sim
    assert len(all_sim["simulations"]) == 4


# ------------------------------------------------------------------------------
# 2. DETERMINISTIC OUTPUT
# ------------------------------------------------------------------------------

def test_deterministic_output():
    """Verify identical inputs yield bit-for-bit identical simulation results."""
    graph, lab_result = make_test_graph_and_lab()
    sim1 = simulate_response_impact(graph, lab_result, BLOCK_SOURCE_IP)
    sim2 = simulate_response_impact(graph, lab_result, BLOCK_SOURCE_IP)
    assert sim1 == sim2


# ------------------------------------------------------------------------------
# 3. CAMPAIGN IDENTITY
# ------------------------------------------------------------------------------

def test_campaign_identity():
    """Verify campaign identity is strictly preserved and validated across components."""
    camp_id = "CAMP-IDENT-777"
    graph, lab_result = make_test_graph_and_lab(campaign_id=camp_id)

    sim = simulate_response_impact(graph, lab_result, ISOLATE_HOST)
    assert sim["campaign_id"] == camp_id


# ------------------------------------------------------------------------------
# 4. BLOCK_SOURCE_IP SIMULATION
# ------------------------------------------------------------------------------

def test_block_source_ip_simulation():
    """Verify BLOCK_SOURCE_IP simulation captures affected sources and perimeter blast radius."""
    graph, lab_result = make_test_graph_and_lab(source_ips=["192.168.1.55"])
    sim = simulate_response_impact(graph, lab_result, BLOCK_SOURCE_IP)

    sim_data = sim["simulation"]
    assert "192.168.1.55" in sim_data["affected_sources"]
    assert sim_data["blast_radius_score"] <= 30
    assert sim_data["service_impact_score"] <= 30
    assert sim_data["containment_effectiveness_score"] > 60
    assert "Firewall drops ingress" in sim_data["predicted_outcome"]


# ------------------------------------------------------------------------------
# 5. ISOLATE_HOST SIMULATION
# ------------------------------------------------------------------------------

def test_isolate_host_simulation():
    """Verify ISOLATE_HOST simulation models high blast radius and high service disruption."""
    graph, lab_result = make_test_graph_and_lab()
    sim = simulate_response_impact(graph, lab_result, ISOLATE_HOST)

    sim_data = sim["simulation"]
    assert sim_data["blast_radius_score"] == 80
    assert sim_data["service_impact_score"] == 80
    assert "severed" in sim_data["predicted_outcome"].lower()


# ------------------------------------------------------------------------------
# 6. NOTIFY_ADMIN SIMULATION
# ------------------------------------------------------------------------------

def test_notify_admin_simulation():
    """Verify NOTIFY_ADMIN produces negligible blast radius and low containment effectiveness."""
    graph, lab_result = make_test_graph_and_lab()
    sim = simulate_response_impact(graph, lab_result, NOTIFY_ADMIN)

    sim_data = sim["simulation"]
    assert sim_data["affected_sources"] == []
    assert sim_data["blast_radius_score"] == 5
    assert sim_data["service_impact_score"] == 5
    assert sim_data["containment_effectiveness_score"] == 15
    assert sim_data["residual_risk_score"] > 0


# ------------------------------------------------------------------------------
# 7. NO_ACTION SIMULATION
# ------------------------------------------------------------------------------

def test_no_action_simulation():
    """Verify NO_ACTION produces zero blast radius, zero service disruption, and zero containment."""
    graph, lab_result = make_test_graph_and_lab()
    sim = simulate_response_impact(graph, lab_result, NO_ACTION)

    sim_data = sim["simulation"]
    assert sim_data["blast_radius_score"] == 0
    assert sim_data["service_impact_score"] == 0
    assert sim_data["containment_effectiveness_score"] == 0
    assert sim_data["confidence"] == 100
    assert sim["comparison"]["risk_change"] == 0


# ------------------------------------------------------------------------------
# 8. BLAST RADIUS SCORING
# ------------------------------------------------------------------------------

def test_blast_radius_scoring():
    """Verify blast radius hierarchy: NO_ACTION < NOTIFY_ADMIN < BLOCK_SOURCE_IP < ISOLATE_HOST."""
    graph, lab_result = make_test_graph_and_lab()
    all_sims = simulate_all_responses(graph, lab_result)["simulations_by_type"]

    no_act_blast = all_sims[NO_ACTION]["simulation"]["blast_radius_score"]
    notify_blast = all_sims[NOTIFY_ADMIN]["simulation"]["blast_radius_score"]
    block_blast = all_sims[BLOCK_SOURCE_IP]["simulation"]["blast_radius_score"]
    isolate_blast = all_sims[ISOLATE_HOST]["simulation"]["blast_radius_score"]

    assert no_act_blast < notify_blast < block_blast < isolate_blast
    assert isolate_blast == 80


# ------------------------------------------------------------------------------
# 9. SERVICE IMPACT SCORING
# ------------------------------------------------------------------------------

def test_service_impact_scoring():
    """Verify service impact hierarchy: NO_ACTION < NOTIFY_ADMIN < BLOCK_SOURCE_IP < ISOLATE_HOST."""
    graph, lab_result = make_test_graph_and_lab()
    all_sims = simulate_all_responses(graph, lab_result)["simulations_by_type"]

    no_act_impact = all_sims[NO_ACTION]["simulation"]["service_impact_score"]
    notify_impact = all_sims[NOTIFY_ADMIN]["simulation"]["service_impact_score"]
    block_impact = all_sims[BLOCK_SOURCE_IP]["simulation"]["service_impact_score"]
    isolate_impact = all_sims[ISOLATE_HOST]["simulation"]["service_impact_score"]

    assert no_act_impact < notify_impact < block_impact < isolate_impact
    assert isolate_impact == 80


# ------------------------------------------------------------------------------
# 10. CONTAINMENT EFFECTIVENESS
# ------------------------------------------------------------------------------

def test_containment_effectiveness():
    """Verify containment effectiveness accurately reflects attack surface mitigation."""
    # Perimeter graph
    perim_graph, perim_lab = make_test_graph_and_lab(stages=[
        {"stage_number": 1, "stage_key": "reconnaissance", "mitre_technique": "T1046"},
        {"stage_number": 2, "stage_key": "authentication_attack", "mitre_technique": "T1110"},
    ])
    perim_sims = simulate_all_responses(perim_graph, perim_lab)["simulations_by_type"]
    assert (
        perim_sims[BLOCK_SOURCE_IP]["simulation"]["containment_effectiveness_score"]
        > perim_sims[ISOLATE_HOST]["simulation"]["containment_effectiveness_score"]
    )

    # Host compromise graph
    host_graph, host_lab = make_test_graph_and_lab(stages=[
        {"stage_number": 1, "stage_key": "successful_authentication", "mitre_technique": "T1078"},
        {"stage_number": 2, "stage_key": "privilege_escalation", "mitre_technique": "T1068"},
    ])
    host_sims = simulate_all_responses(host_graph, host_lab)["simulations_by_type"]
    assert (
        host_sims[ISOLATE_HOST]["simulation"]["containment_effectiveness_score"]
        > host_sims[BLOCK_SOURCE_IP]["simulation"]["containment_effectiveness_score"]
    )


# ------------------------------------------------------------------------------
# 11. RESIDUAL RISK
# ------------------------------------------------------------------------------

def test_residual_risk():
    """Verify residual risk equals base risk minus containment, bounded properly."""
    graph, lab_result = make_test_graph_and_lab()
    sim = simulate_response_impact(graph, lab_result, BLOCK_SOURCE_IP)

    res_risk = sim["simulation"]["residual_risk_score"]
    risk_change = sim["comparison"]["risk_change"]
    assert res_risk >= 0
    assert risk_change > 0


# ------------------------------------------------------------------------------
# 12. CONFIDENCE
# ------------------------------------------------------------------------------

def test_confidence():
    """Verify confidence score is bounded [50, 100] across all simulated responses."""
    graph, lab_result = make_test_graph_and_lab()
    for opt in SUPPORTED_RESPONSE_OPTIONS:
        sim = simulate_response_impact(graph, lab_result, opt)
        assert 50 <= sim["simulation"]["confidence"] <= 100


# ------------------------------------------------------------------------------
# 13. AUTHENTICATION ATTACK INFLUENCE
# ------------------------------------------------------------------------------

def test_authentication_attack_influence():
    """Verify credential brute-force is mapped to affected_techniques for BLOCK_SOURCE_IP."""
    graph, lab_result = make_test_graph_and_lab(stages=[
        {"stage_number": 1, "stage_key": "authentication_attack", "mitre_technique": "T1110"},
    ])
    sim = simulate_response_impact(graph, lab_result, BLOCK_SOURCE_IP)

    assert "T1110" in sim["simulation"]["affected_techniques"]
    assert sim["simulation"]["containment_effectiveness_score"] >= 70


# ------------------------------------------------------------------------------
# 14. SUCCESSFUL AUTHENTICATION INFLUENCE
# ------------------------------------------------------------------------------

def test_successful_authentication_influence():
    """Verify successful authentication flags host compromise in simulation."""
    graph, lab_result = make_test_graph_and_lab(stages=[
        {"stage_number": 1, "stage_key": "successful_authentication", "mitre_technique": "T1078"},
    ])
    sim_block = simulate_response_impact(graph, lab_result, BLOCK_SOURCE_IP)
    sim_isolate = simulate_response_impact(graph, lab_result, ISOLATE_HOST)

    # BLOCK_SOURCE_IP leaves host risk active
    assert "remains active and unmitigated on the endpoint" in sim_block["simulation"]["predicted_outcome"].lower()
    assert sim_block["simulation"]["residual_risk_score"] > 30
    # ISOLATE_HOST achieves high containment
    assert sim_isolate["simulation"]["containment_effectiveness_score"] >= 85


# ------------------------------------------------------------------------------
# 15. POWERSHELL INFLUENCE
# ------------------------------------------------------------------------------

def test_powershell_influence():
    """Verify suspicious PowerShell execution is captured in ISOLATE_HOST simulation."""
    graph, lab_result = make_test_graph_and_lab(stages=[
        {"stage_number": 1, "stage_key": "suspicious_powershell", "mitre_technique": "T1059.001"},
    ])
    sim = simulate_response_impact(graph, lab_result, ISOLATE_HOST)

    assert "T1059.001" in sim["simulation"]["affected_techniques"]
    assert "powershell" in sim["simulation"]["predicted_outcome"].lower()


# ------------------------------------------------------------------------------
# 16. PRIVILEGE ESCALATION INFLUENCE
# ------------------------------------------------------------------------------

def test_privilege_escalation_influence():
    """Verify privilege escalation triggers maximum containment effectiveness for ISOLATE_HOST."""
    graph, lab_result = make_test_graph_and_lab(stages=[
        {"stage_number": 1, "stage_key": "privilege_escalation", "mitre_technique": "T1068"},
    ])
    sim = simulate_response_impact(graph, lab_result, ISOLATE_HOST)

    assert "T1068" in sim["simulation"]["affected_techniques"]
    assert sim["simulation"]["containment_effectiveness_score"] >= 90


# ------------------------------------------------------------------------------
# 17. RECONNAISSANCE INFLUENCE
# ------------------------------------------------------------------------------

def test_reconnaissance_influence():
    """Verify network service discovery (T1046) is tracked in BLOCK_SOURCE_IP simulation."""
    graph, lab_result = make_test_graph_and_lab(stages=[
        {"stage_number": 1, "stage_key": "reconnaissance", "mitre_technique": "T1046"},
    ])
    sim = simulate_response_impact(graph, lab_result, BLOCK_SOURCE_IP)

    assert "T1046" in sim["simulation"]["affected_techniques"]


# ------------------------------------------------------------------------------
# 18. MULTIPLE SOURCE IP INFLUENCE
# ------------------------------------------------------------------------------

def test_multiple_source_ip_influence():
    """Verify multiple adversary source IPs are tracked in affected_sources and impact scores."""
    ips = ["192.168.1.10", "192.168.1.20", "192.168.1.30"]
    graph, lab_result = make_test_graph_and_lab(source_ips=ips)
    sim = simulate_response_impact(graph, lab_result, BLOCK_SOURCE_IP)

    sim_data = sim["simulation"]
    for ip in ips:
        assert ip in sim_data["affected_sources"]
    assert sim_data["blast_radius_score"] > 10


# ------------------------------------------------------------------------------
# 19. MULTIPLE TECHNIQUES INFLUENCE
# ------------------------------------------------------------------------------

def test_multiple_techniques_influence():
    """Verify simulation handles 5-stage attack mapping techniques to respective response scopes."""
    stages = [
        {"stage_number": 1, "stage_key": "reconnaissance", "mitre_technique": "T1046"},
        {"stage_number": 2, "stage_key": "authentication_attack", "mitre_technique": "T1110"},
        {"stage_number": 3, "stage_key": "successful_authentication", "mitre_technique": "T1078"},
        {"stage_number": 4, "stage_key": "suspicious_powershell", "mitre_technique": "T1059.001"},
        {"stage_number": 5, "stage_key": "privilege_escalation", "mitre_technique": "T1068"},
    ]
    graph, lab_result = make_test_graph_and_lab(stages=stages)
    all_sims = simulate_all_responses(graph, lab_result)["simulations_by_type"]

    assert "T1046" in all_sims[BLOCK_SOURCE_IP]["simulation"]["affected_techniques"]
    assert "T1068" in all_sims[ISOLATE_HOST]["simulation"]["affected_techniques"]


# ------------------------------------------------------------------------------
# 20. MULTIPLE EVIDENCE EVENTS
# ------------------------------------------------------------------------------

def test_multiple_evidence_events():
    """Verify evidence events are collected into affected_events for containment."""
    graph, lab_result = make_test_graph_and_lab(events_per_stage=5)
    sim = simulate_response_impact(graph, lab_result, ISOLATE_HOST)

    assert len(sim["simulation"]["affected_events"]) >= 5


# ------------------------------------------------------------------------------
# 21. STAGE COUNT INFLUENCE
# ------------------------------------------------------------------------------

def test_stage_count_influence():
    """Verify stage keys are mapped to affected_stages for targeted responses."""
    graph, lab_result = make_test_graph_and_lab()
    sim_block = simulate_response_impact(graph, lab_result, BLOCK_SOURCE_IP)

    assert len(sim_block["simulation"]["affected_stages"]) > 0


# ------------------------------------------------------------------------------
# 22. PHASE 1E SCORE INFLUENCE
# ------------------------------------------------------------------------------

def test_phase_1e_score_influence():
    """Verify Cyber Twin incorporates Phase 1E risk reduction and coverage into simulation."""
    graph, lab_result = make_test_graph_and_lab()
    lab_block = next(r for r in lab_result["responses"] if r["response_type"] == BLOCK_SOURCE_IP)

    sim = simulate_response_impact(graph, lab_result, BLOCK_SOURCE_IP)
    # The containment score correlates with Phase 1E coverage score
    assert abs(sim["simulation"]["containment_effectiveness_score"] - lab_block["coverage_score"]) < 20


# ------------------------------------------------------------------------------
# 23. MALFORMED GRAPH REJECTION
# ------------------------------------------------------------------------------

def test_malformed_graph_rejection():
    """Verify invalid Evidence Graph structures safely raise CyberTwinError."""
    _, lab_result = make_test_graph_and_lab()

    with pytest.raises(CyberTwinError):
        simulate_response_impact(None, lab_result, BLOCK_SOURCE_IP)

    with pytest.raises(CyberTwinError):
        simulate_response_impact("not-a-dict", lab_result, BLOCK_SOURCE_IP)

    with pytest.raises(CyberTwinError):
        simulate_response_impact({}, lab_result, BLOCK_SOURCE_IP)

    with pytest.raises(CyberTwinError):
        simulate_response_impact({"campaign": {"campaign_id": "C1"}}, lab_result, BLOCK_SOURCE_IP)


# ------------------------------------------------------------------------------
# 24. MALFORMED RESPONSE RESULT REJECTION
# ------------------------------------------------------------------------------

def test_malformed_response_result_rejection():
    """Verify invalid Response Lab results safely raise CyberTwinError."""
    graph, _ = make_test_graph_and_lab()

    with pytest.raises(CyberTwinError):
        simulate_response_impact(graph, None, BLOCK_SOURCE_IP)

    with pytest.raises(CyberTwinError):
        simulate_response_impact(graph, {}, BLOCK_SOURCE_IP)

    # Campaign ID mismatch
    with pytest.raises(CyberTwinError):
        bad_lab = {"campaign_id": "MISMATCHED-CAMP", "responses": []}
        simulate_response_impact(graph, bad_lab, BLOCK_SOURCE_IP)

    # Empty responses
    with pytest.raises(CyberTwinError):
        bad_lab2 = {"campaign_id": graph["campaign"]["campaign_id"], "responses": []}
        simulate_response_impact(graph, bad_lab2, BLOCK_SOURCE_IP)


# ------------------------------------------------------------------------------
# 25. MALFORMED NODES REJECTION
# ------------------------------------------------------------------------------

def test_malformed_nodes_rejection():
    """Verify invalid nodes inside Evidence Graph raise CyberTwinError."""
    graph, lab_result = make_test_graph_and_lab()
    graph["nodes"].append("not-a-node-dict")

    with pytest.raises(CyberTwinError):
        simulate_response_impact(graph, lab_result, BLOCK_SOURCE_IP)


# ------------------------------------------------------------------------------
# 26. MALFORMED EDGES REJECTION
# ------------------------------------------------------------------------------

def test_malformed_edges_rejection():
    """Verify invalid edges inside Evidence Graph raise CyberTwinError."""
    graph, lab_result = make_test_graph_and_lab()
    graph["edges"].append({"source": "a", "target": "b", "relationship": "UNKNOWN_REL"})

    with pytest.raises(CyberTwinError):
        simulate_response_impact(graph, lab_result, BLOCK_SOURCE_IP)


# ------------------------------------------------------------------------------
# 27. INVALID RESPONSE OPTION REJECTION
# ------------------------------------------------------------------------------

def test_invalid_response_option_rejection():
    """Verify passing an unsupported response option to simulate_response_impact raises CyberTwinError."""
    graph, lab_result = make_test_graph_and_lab()

    with pytest.raises(CyberTwinError):
        simulate_response_impact(graph, lab_result, "CUSTOM_ACTION")

    with pytest.raises(CyberTwinError):
        simulate_response_impact(graph, lab_result, 99999)


# ------------------------------------------------------------------------------
# 28. OVERSIZED INPUT REJECTION
# ------------------------------------------------------------------------------

def test_oversized_input_rejection():
    """Verify oversized graphs or response lists safely raise CyberTwinError."""
    graph, lab_result = make_test_graph_and_lab()

    # Oversized nodes
    dummy_nodes = [
        {"node_id": f"dummy:{i}", "node_type": "EVENT", "metadata": {}}
        for i in range(MAX_GRAPH_NODES_BOUND + 1)
    ]
    graph["nodes"] = dummy_nodes
    with pytest.raises(CyberTwinError):
        simulate_response_impact(graph, lab_result, BLOCK_SOURCE_IP)


# ------------------------------------------------------------------------------
# 29. NO NETWORK OR SOCKET ACTIVITY
# ------------------------------------------------------------------------------

def test_no_network_or_socket_activity(monkeypatch):
    """Verify that Cyber Twin executes ZERO network or socket calls."""
    def guarded_socket(*args, **kwargs):
        raise RuntimeError("CRITICAL SAFETY VIOLATION: Socket call attempted in Cyber Twin!")

    monkeypatch.setattr(socket, "socket", guarded_socket)

    graph, lab_result = make_test_graph_and_lab()
    result = simulate_all_responses(graph, lab_result)
    assert result is not None


# ------------------------------------------------------------------------------
# 30. NO DATABASE OR FILESYSTEM SIDE EFFECTS
# ------------------------------------------------------------------------------

def test_no_database_side_effects():
    """Verify database remains completely untouched before and after Cyber Twin execution."""
    events_before = len(get_recent_events(limit=50))
    incidents_before = len(get_incidents(limit=50))

    graph, lab_result = make_test_graph_and_lab()
    simulate_all_responses(graph, lab_result)

    events_after = len(get_recent_events(limit=50))
    incidents_after = len(get_incidents(limit=50))

    assert events_before == events_after
    assert incidents_before == incidents_after


# ------------------------------------------------------------------------------
# 31. DETERMINISTIC REPEATED SIMULATION
# ------------------------------------------------------------------------------

def test_deterministic_repeated_simulation():
    """Verify 5 consecutive simulations produce identical results."""
    graph, lab_result = make_test_graph_and_lab()
    first = simulate_all_responses(graph, lab_result)
    for _ in range(4):
        subsequent = simulate_all_responses(graph, lab_result)
        assert first == subsequent


# ------------------------------------------------------------------------------
# 32. PHASE 1D -> PHASE 1E -> PHASE 1F END-TO-END
# ------------------------------------------------------------------------------

def test_phase_1d_to_1e_to_1f_e2e():
    """
    Verify complete Phase 1 pipeline execution:
    Synthetic Telemetry (1A) -> Correlation (1B) -> Attack Story (1C) ->
    Evidence Graph (1D) -> Response Lab (1E) -> Cyber Twin (1F).
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
    assert twin_result["campaign_id"] == story["campaign_id"]
    assert len(twin_result["simulations"]) == 4
    assert twin_result["optimal_simulation"] is not None


# ------------------------------------------------------------------------------
# 33. DUPLICATE HANDLING
# ------------------------------------------------------------------------------

def test_duplicate_handling():
    """Verify duplicate nodes in graph and duplicate responses in lab result are handled cleanly."""
    graph, lab_result = make_test_graph_and_lab()

    # Inject duplicate node
    dup_node = dict(graph["nodes"][0])
    graph["nodes"].append(dup_node)

    # Inject duplicate response
    dup_resp = dict(lab_result["responses"][0])
    lab_result["responses"].append(dup_resp)

    all_sims = simulate_all_responses(graph, lab_result)
    assert len(all_sims["simulations"]) == 4  # Deduplicated cleanly


# ------------------------------------------------------------------------------
# 34. BOUNDED SCORE PROCESSING
# ------------------------------------------------------------------------------

def test_bounded_score_processing():
    """Verify all simulation scores stay strictly within [0, 100]."""
    graph, lab_result = make_test_graph_and_lab()
    all_sims = simulate_all_responses(graph, lab_result)

    for sim in all_sims["simulations"]:
        sim_data = sim["simulation"]
        for score_key in (
            "blast_radius_score",
            "service_impact_score",
            "containment_effectiveness_score",
            "residual_risk_score",
            "confidence",
        ):
            val = sim_data[score_key]
            assert isinstance(val, int)
            assert 0 <= val <= 100


# ------------------------------------------------------------------------------
# 35. SIMULATE_ALL_RESPONSES STRUCTURE & COMPARISON
# ------------------------------------------------------------------------------

def test_simulate_all_responses_structure():
    """Verify simulate_all_responses output schema and overall comparison metrics."""
    graph, lab_result = make_test_graph_and_lab()
    result = simulate_all_responses(graph, lab_result)

    assert "campaign_id" in result
    assert "simulations" in result
    assert "simulations_by_type" in result
    assert "optimal_simulation" in result
    assert "overall_comparison" in result

    comparison = result["overall_comparison"]
    assert "summary" in comparison
    assert "recommended_response" in comparison
    assert "trade_off_analysis" in comparison


# ------------------------------------------------------------------------------
# 36. PIPELINE CONVENIENCE HELPERS
# ------------------------------------------------------------------------------

def test_pipeline_convenience_helpers():
    """Verify convenience functions chaining graph, story, campaign, and events to Cyber Twin."""
    events = generate_campaign_events(total_events=20)
    for idx, ev in enumerate(events, start=1):
        ev["id"] = idx

    # From events
    twin_from_events = simulate_impact_from_events(events)
    assert twin_from_events is not None
    assert "simulations" in twin_from_events

    # Empty events
    assert simulate_impact_from_events([]) is None

    # From campaign
    camp_dict = correlate_single_campaign(events)
    twin_from_camp = simulate_impact_from_campaign(camp_dict, response_type=BLOCK_SOURCE_IP)
    assert twin_from_camp["response_type"] == BLOCK_SOURCE_IP

    # From story
    story = build_attack_story_from_events(events)
    twin_from_story = simulate_impact_from_story(story)
    assert len(twin_from_story["simulations"]) == 4

    # From graph
    graph = build_evidence_graph(story)
    twin_from_graph = simulate_response_from_graph(graph, response_type=ISOLATE_HOST)
    assert twin_from_graph["response_type"] == ISOLATE_HOST
