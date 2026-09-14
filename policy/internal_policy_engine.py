"""
Internal Policy Engine — Deterministic Decision & Policy Evaluation Layer
=========================================================================
Part of the SentinelX Detection & Incident Response Platform (Phase 1G).

Role:
  Consumes:
    1. Phase 1D — Evidence Knowledge Graph
    2. Phase 1E — Response Lab evaluation
    3. Phase 1F — Cyber Twin impact simulation
  and applies deterministic, explainable policy rules to select and justify
  a recommended response decision without executing any real response.

Pipeline Context:
  Synthetic Telemetry (1A)
           ↓
  Correlated Campaign (1B)
           ↓
  Structured Attack Story (1C)
           ↓
  Evidence Knowledge Graph (1D)
           ↓
  Internal Response Lab (1E)
           ↓
  Cyber Twin Impact Simulation (1F)
           ↓
  Deterministic Policy & Decision Engine (1G)
           ↓
  Recommended Decision:
    - Recommended Response: BLOCK_SOURCE_IP | ISOLATE_HOST | NOTIFY_ADMIN | NO_ACTION
    - Decision State: RECOMMEND | REVIEW | NO_ACTION
    - Policy Score & Confidence
    - Alternatives Matrix & Policy Factors
    - Explainable Decision Reason & Comparison

Policy Decision Semantics:
  - RECOMMEND: Confirmed threat evidence and sufficient confidence justify
    automated policy recommendation for containment.
  - REVIEW: Evidence is ambiguous, confidence is lower, or operational impact
    warrants manual security analyst review (e.g. NOTIFY_ADMIN).
  - NO_ACTION: Passive telemetry monitoring baseline with zero intervention.

Safety & Boundary Rules:
  - POLICY EVALUATION ONLY: Never executes real containment or system actions.
  - ZERO network traffic: No sockets, no HTTP, no external connections.
  - ZERO database modifications: Purely in-memory evaluation.
  - ZERO containment layer invocation: Does NOT import services.containment.
  - ZERO external service calls: No Telegram, no Gemini, no third-party APIs.
  - Strictly deterministic: Identical inputs yield identical policy decisions.
  - No randomness, no datetime.now(), no UUIDs.
"""

import ipaddress
import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

# Optional pipeline helpers
try:
    from simulator.internal_evidence_graph import (
        build_evidence_graph,
        build_evidence_graph_from_campaign,
        build_evidence_graph_from_events,
    )
except ImportError:
    build_evidence_graph = None  # type: ignore
    build_evidence_graph_from_campaign = None  # type: ignore
    build_evidence_graph_from_events = None  # type: ignore

try:
    from simulator.internal_response_lab import (
        evaluate_responses,
        BLOCK_SOURCE_IP,
        ISOLATE_HOST,
        NOTIFY_ADMIN,
        NO_ACTION,
        SUPPORTED_RESPONSE_OPTIONS,
    )
except ImportError:
    BLOCK_SOURCE_IP = "BLOCK_SOURCE_IP"
    ISOLATE_HOST = "ISOLATE_HOST"
    NOTIFY_ADMIN = "NOTIFY_ADMIN"
    NO_ACTION = "NO_ACTION"
    SUPPORTED_RESPONSE_OPTIONS = (
        BLOCK_SOURCE_IP,
        ISOLATE_HOST,
        NOTIFY_ADMIN,
        NO_ACTION,
    )
    evaluate_responses = None  # type: ignore

try:
    from simulator.internal_cyber_twin import (
        simulate_all_responses,
        simulate_response_impact,
    )
except ImportError:
    simulate_all_responses = None  # type: ignore
    simulate_response_impact = None  # type: ignore


# ------------------------------------------------------------------------------
# CONSTANTS & CONSTRAINTS
# ------------------------------------------------------------------------------

DECISION_RECOMMEND = "RECOMMEND"
DECISION_REVIEW = "REVIEW"
DECISION_NO_ACTION = "NO_ACTION"

VALID_DECISION_STATES = {
    DECISION_RECOMMEND,
    DECISION_REVIEW,
    DECISION_NO_ACTION,
}

VALID_RESPONSE_TYPES = set(SUPPORTED_RESPONSE_OPTIONS)

MAX_GRAPH_NODES_BOUND = 5000
MAX_GRAPH_EDGES_BOUND = 10000
MAX_RESPONSES_BOUND = 20
MAX_SOURCE_IPS_BOUND = 200

VALID_NODE_TYPES = {
    "CAMPAIGN",
    "STAGE",
    "EVENT",
    "TECHNIQUE",
}

VALID_RELATIONSHIPS = {
    "CAMPAIGN_CONTAINS_STAGE",
    "STAGE_SUPPORTED_BY_EVENT",
    "STAGE_USES_TECHNIQUE",
}


# ------------------------------------------------------------------------------
# EXCEPTIONS
# ------------------------------------------------------------------------------

class PolicyEngineError(ValueError):
    """Raised when policy engine input is malformed, invalid, or violates safety bounds."""
    pass


# ------------------------------------------------------------------------------
# VALIDATION UTILITIES
# ------------------------------------------------------------------------------

def validate_ip_address(ip_str: Any) -> str:
    """Validate that source IP is a syntactically valid IPv4 address."""
    if not isinstance(ip_str, str) or not ip_str.strip():
        raise PolicyEngineError(f"Invalid source IP: {repr(ip_str)}")
    cleaned = ip_str.strip()
    try:
        addr = ipaddress.ip_address(cleaned)
        if not isinstance(addr, ipaddress.IPv4Address):
            raise PolicyEngineError(f"Only IPv4 addresses supported: '{ip_str}'")
        return cleaned
    except ValueError as exc:
        raise PolicyEngineError(f"Malformed IPv4 address '{ip_str}': {exc}") from exc


def validate_technique_id(tech_id: Any) -> str:
    """Validate MITRE technique ID format (e.g. 'T1110' or 'T1059.001')."""
    if not isinstance(tech_id, str) or not tech_id.strip():
        raise PolicyEngineError(f"Invalid MITRE technique ID: {repr(tech_id)}")
    cleaned = tech_id.strip().upper()
    if not re.match(r"^T\d{4}(\.\d{3})?$", cleaned):
        raise PolicyEngineError(f"Malformed MITRE technique ID format: '{tech_id}'")
    return cleaned


def validate_policy_inputs(
    graph: Any,
    lab_result: Any,
    twin_result: Any
) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    """
    Strictly validate Phase 1D Evidence Graph, Phase 1E Response Lab, and
    Phase 1F Cyber Twin structures.
    """
    # 1. Validate Evidence Graph
    if graph is None:
        raise PolicyEngineError("Evidence graph cannot be None.")
    if not isinstance(graph, dict):
        raise PolicyEngineError(f"Evidence graph must be a dictionary, got: {type(graph).__name__}")
    if not graph:
        raise PolicyEngineError("Evidence graph dictionary cannot be empty.")

    campaign = graph.get("campaign")
    if not isinstance(campaign, dict) or not campaign:
        raise PolicyEngineError("Missing or invalid 'campaign' in evidence graph.")

    campaign_id = campaign.get("campaign_id")
    if not isinstance(campaign_id, str) or not campaign_id.strip():
        raise PolicyEngineError(f"Missing or invalid 'campaign_id' in campaign: {repr(campaign_id)}")
    camp_id_clean = campaign_id.strip()

    raw_nodes = graph.get("nodes")
    if raw_nodes is None or not isinstance(raw_nodes, (list, tuple)):
        raise PolicyEngineError(f"Missing or invalid 'nodes' in evidence graph: {repr(raw_nodes)}")
    if len(raw_nodes) > MAX_GRAPH_NODES_BOUND:
        raise PolicyEngineError(f"Graph node count ({len(raw_nodes)}) exceeds safety limit ({MAX_GRAPH_NODES_BOUND}).")

    seen_node_ids = set()
    deduped_nodes: List[Dict[str, Any]] = []
    for idx, node in enumerate(raw_nodes):
        if not isinstance(node, dict):
            raise PolicyEngineError(f"Node at index {idx} must be a dictionary.")
        nid = node.get("node_id")
        if not isinstance(nid, str) or not nid.strip():
            raise PolicyEngineError(f"Node at index {idx} has invalid 'node_id': {repr(nid)}")
        ntype = node.get("node_type")
        if not isinstance(ntype, str) or ntype not in VALID_NODE_TYPES:
            raise PolicyEngineError(f"Node '{nid}' has invalid 'node_type': {repr(ntype)}")

        meta = node.get("metadata")
        if meta is not None and not isinstance(meta, dict):
            raise PolicyEngineError(f"Node '{nid}' metadata must be a dictionary.")

        if meta:
            if ntype == "TECHNIQUE":
                t_id = meta.get("technique_id")
                if t_id is not None:
                    validate_technique_id(t_id)
            elif ntype == "EVENT":
                s_ip = meta.get("source_ip")
                if s_ip is not None and str(s_ip).strip().lower() not in ("unknown", ""):
                    validate_ip_address(s_ip)
            elif ntype == "STAGE":
                for s in meta.get("sources", []):
                    validate_ip_address(s)

        if nid not in seen_node_ids:
            seen_node_ids.add(nid)
            deduped_nodes.append(node)

    raw_edges = graph.get("edges")
    if raw_edges is None or not isinstance(raw_edges, (list, tuple)):
        raise PolicyEngineError(f"Missing or invalid 'edges' in evidence graph: {repr(raw_edges)}")
    if len(raw_edges) > MAX_GRAPH_EDGES_BOUND:
        raise PolicyEngineError(f"Graph edge count ({len(raw_edges)}) exceeds safety limit ({MAX_GRAPH_EDGES_BOUND}).")

    for idx, edge in enumerate(raw_edges):
        if not isinstance(edge, dict):
            raise PolicyEngineError(f"Edge at index {idx} must be a dictionary.")
        src = edge.get("source")
        tgt = edge.get("target")
        rel = edge.get("relationship")
        if not isinstance(src, str) or not src.strip():
            raise PolicyEngineError(f"Edge at index {idx} has invalid 'source': {repr(src)}")
        if not isinstance(tgt, str) or not tgt.strip():
            raise PolicyEngineError(f"Edge at index {idx} has invalid 'target': {repr(tgt)}")
        if not isinstance(rel, str) or rel not in VALID_RELATIONSHIPS:
            raise PolicyEngineError(f"Edge at index {idx} has invalid 'relationship': {repr(rel)}")

    clean_graph = {
        "campaign": campaign,
        "nodes": deduped_nodes,
        "edges": list(raw_edges),
        "summary": graph.get("summary") or {},
    }

    # 2. Validate Response Lab Result
    if lab_result is None:
        raise PolicyEngineError("Response lab result cannot be None.")
    if not isinstance(lab_result, dict):
        raise PolicyEngineError(f"Response lab result must be a dictionary, got: {type(lab_result).__name__}")
    if not lab_result:
        raise PolicyEngineError("Response lab result dictionary cannot be empty.")

    lab_camp_id = lab_result.get("campaign_id")
    if not isinstance(lab_camp_id, str) or not lab_camp_id.strip():
        raise PolicyEngineError(f"Missing or invalid 'campaign_id' in response lab result: {repr(lab_camp_id)}")
    if lab_camp_id.strip() != camp_id_clean:
        raise PolicyEngineError(
            f"Campaign ID mismatch between graph ('{camp_id_clean}') and response lab ('{lab_camp_id.strip()}')."
        )

    raw_responses = lab_result.get("responses")
    if raw_responses is None or not isinstance(raw_responses, (list, tuple)):
        raise PolicyEngineError(f"Missing or invalid 'responses' in response lab result: {repr(raw_responses)}")
    if not raw_responses:
        raise PolicyEngineError("Response lab result 'responses' list cannot be empty.")
    if len(raw_responses) > MAX_RESPONSES_BOUND:
        raise PolicyEngineError(f"Response count ({len(raw_responses)}) exceeds limit ({MAX_RESPONSES_BOUND}).")

    seen_types = set()
    validated_responses: List[Dict[str, Any]] = []
    for idx, resp in enumerate(raw_responses):
        if not isinstance(resp, dict):
            raise PolicyEngineError(f"Response at index {idx} must be a dictionary.")
        rtype = resp.get("response_type")
        if not isinstance(rtype, str) or rtype.strip().upper() not in VALID_RESPONSE_TYPES:
            raise PolicyEngineError(f"Response at index {idx} has invalid 'response_type': {repr(rtype)}")
        norm_rtype = rtype.strip().upper()

        for score_field in (
            "coverage_score",
            "risk_reduction_score",
            "operational_impact_score",
            "residual_risk_score",
            "confidence",
        ):
            val = resp.get(score_field)
            if not isinstance(val, (int, float)):
                raise PolicyEngineError(f"Response '{norm_rtype}' field '{score_field}' must be numeric.")
            if not (0 <= val <= 100):
                raise PolicyEngineError(f"Response '{norm_rtype}' field '{score_field}' ({val}) outside [0, 100].")

        if norm_rtype not in seen_types:
            seen_types.add(norm_rtype)
            validated_responses.append(resp)

    clean_lab = {
        "campaign_id": camp_id_clean,
        "responses": validated_responses,
        "recommendation": lab_result.get("recommendation") or {},
        "comparison_reason": lab_result.get("comparison_reason", ""),
    }

    # 3. Validate Cyber Twin Result
    if twin_result is None:
        raise PolicyEngineError("Cyber twin result cannot be None.")
    if not isinstance(twin_result, dict):
        raise PolicyEngineError(f"Cyber twin result must be a dictionary, got: {type(twin_result).__name__}")
    if not twin_result:
        raise PolicyEngineError("Cyber twin result dictionary cannot be empty.")

    twin_camp_id = twin_result.get("campaign_id")
    if not isinstance(twin_camp_id, str) or not twin_camp_id.strip():
        raise PolicyEngineError(f"Missing or invalid 'campaign_id' in cyber twin result: {repr(twin_camp_id)}")
    if twin_camp_id.strip() != camp_id_clean:
        raise PolicyEngineError(
            f"Campaign ID mismatch between graph ('{camp_id_clean}') and cyber twin ('{twin_camp_id.strip()}')."
        )

    # Normalize simulations from twin_result
    raw_simulations = twin_result.get("simulations")
    sims_by_type: Dict[str, Dict[str, Any]] = {}

    if raw_simulations is not None:
        if not isinstance(raw_simulations, (list, tuple)):
            raise PolicyEngineError("Cyber twin 'simulations' must be a list or tuple.")
        if len(raw_simulations) > MAX_RESPONSES_BOUND:
            raise PolicyEngineError(f"Cyber twin simulation count exceeds limit ({MAX_RESPONSES_BOUND}).")

        for idx, sim in enumerate(raw_simulations):
            if not isinstance(sim, dict):
                raise PolicyEngineError(f"Simulation at index {idx} must be a dictionary.")
            srtype = sim.get("response_type")
            if not isinstance(srtype, str) or srtype.strip().upper() not in VALID_RESPONSE_TYPES:
                raise PolicyEngineError(f"Simulation at index {idx} has invalid 'response_type': {repr(srtype)}")
            norm_srtype = srtype.strip().upper()

            sim_inner = sim.get("simulation")
            if not isinstance(sim_inner, dict):
                raise PolicyEngineError(f"Simulation '{norm_srtype}' missing 'simulation' dictionary.")

            for sfield in (
                "blast_radius_score",
                "service_impact_score",
                "containment_effectiveness_score",
                "residual_risk_score",
                "confidence",
            ):
                sval = sim_inner.get(sfield)
                if not isinstance(sval, (int, float)):
                    raise PolicyEngineError(f"Simulation '{norm_srtype}' field '{sfield}' must be numeric.")
                if not (0 <= sval <= 100):
                    raise PolicyEngineError(f"Simulation '{norm_srtype}' field '{sfield}' ({sval}) outside [0, 100].")

            if norm_srtype not in sims_by_type:
                sims_by_type[norm_srtype] = sim

    elif "simulation" in twin_result and "response_type" in twin_result:
        # Single response simulation provided
        srtype = twin_result.get("response_type")
        if not isinstance(srtype, str) or srtype.strip().upper() not in VALID_RESPONSE_TYPES:
            raise PolicyEngineError(f"Single simulation has invalid 'response_type': {repr(srtype)}")
        norm_srtype = srtype.strip().upper()
        sim_inner = twin_result.get("simulation")
        if not isinstance(sim_inner, dict):
            raise PolicyEngineError("Single simulation missing 'simulation' dictionary.")
        sims_by_type[norm_srtype] = twin_result

    elif "simulations_by_type" in twin_result:
        raw_sbt = twin_result.get("simulations_by_type")
        if not isinstance(raw_sbt, dict):
            raise PolicyEngineError("Cyber twin 'simulations_by_type' must be a dictionary.")
        for k, v in raw_sbt.items():
            if isinstance(v, dict) and k in VALID_RESPONSE_TYPES:
                sims_by_type[k] = v

    if not sims_by_type:
        raise PolicyEngineError("Cyber twin result contains no valid simulations.")

    clean_twin = {
        "campaign_id": camp_id_clean,
        "simulations": list(sims_by_type.values()),
        "simulations_by_type": sims_by_type,
        "overall_comparison": twin_result.get("overall_comparison") or {},
    }

    return clean_graph, clean_lab, clean_twin


# ------------------------------------------------------------------------------
# POLICY FEATURE & FACTOR EXTRACTION
# ------------------------------------------------------------------------------

def extract_policy_factors(
    graph: Dict[str, Any],
    lab_result: Dict[str, Any],
    twin_result: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Extract deterministic policy factors combining Evidence Graph telemetry,
    Response Lab scores, and Cyber Twin simulated impact metrics.
    """
    campaign = graph["campaign"]
    campaign_id = campaign["campaign_id"].strip()
    nodes = graph["nodes"]
    summary = graph.get("summary", {})

    stage_nodes: List[Dict[str, Any]] = []
    technique_nodes: List[Dict[str, Any]] = []
    event_nodes: List[Dict[str, Any]] = []

    source_ips_set: Set[str] = set()
    techniques_set: Set[str] = set()

    for s in campaign.get("sources", []):
        if s:
            source_ips_set.add(s)

    for node in nodes:
        ntype = node.get("node_type")
        meta = node.get("metadata", {})

        if ntype == "STAGE":
            stage_nodes.append(node)
            for s in meta.get("sources", []):
                if s:
                    source_ips_set.add(s)

        elif ntype == "TECHNIQUE":
            technique_nodes.append(node)
            t_id = meta.get("technique_id")
            if t_id:
                techniques_set.add(t_id)

        elif ntype == "EVENT":
            event_nodes.append(node)
            src = meta.get("source_ip")
            if src and str(src).strip().lower() not in ("unknown", ""):
                source_ips_set.add(src)

    if summary:
        for t in summary.get("techniques", []):
            if t:
                techniques_set.add(t)
        for s in summary.get("source_ips", []):
            if s:
                source_ips_set.add(s)

    sorted_sources = sorted(list(source_ips_set))
    sorted_techniques = sorted(list(techniques_set))

    stage_count = len(stage_nodes) or campaign.get("stage_count", 0)
    event_count = len(event_nodes) or campaign.get("event_count", 0)

    # Attack Stage & Technique Semantics
    has_recon = "T1046" in sorted_techniques
    has_auth_attack = "T1110" in sorted_techniques
    has_successful_auth = "T1078" in sorted_techniques
    has_powershell = "T1059.001" in sorted_techniques
    has_privilege_escalation = "T1068" in sorted_techniques

    for stage in stage_nodes:
        meta = stage.get("metadata", {})
        s_key = str(meta.get("stage_key", "")).lower()
        s_label = str(stage.get("label", "")).lower()

        if "recon" in s_key or "recon" in s_label:
            has_recon = True
        if "auth" in s_key and "fail" in s_key or "brute" in s_key or "brute" in s_label or s_key == "authentication_attack":
            has_auth_attack = True
        if "success" in s_key or "valid account" in s_label or s_key == "successful_authentication":
            has_successful_auth = True
        if "powershell" in s_key or "powershell" in s_label or s_key == "suspicious_powershell":
            has_powershell = True
        if "priv" in s_key or "escalation" in s_key or "privilege" in s_label or s_key == "privilege_escalation":
            has_privilege_escalation = True

    has_host_compromise = has_successful_auth or has_powershell or has_privilege_escalation

    # Security Risk (Base Risk, 0-100)
    base_risk = 15
    if has_recon:
        base_risk += 10
    if has_auth_attack:
        base_risk += 15
    if has_successful_auth:
        base_risk += 20
    if has_powershell:
        base_risk += 20
    if has_privilege_escalation:
        base_risk += 25
    base_risk += min(15, stage_count * 3)
    if len(sorted_sources) > 1:
        base_risk += min(10, (len(sorted_sources) - 1) * 3)
    base_risk += min(10, event_count // 4)
    security_risk = min(100, max(15, int(base_risk)))

    # Evidence Strength (0-100)
    ev_strength = 30
    ev_strength += min(30, stage_count * 8)
    ev_strength += min(20, event_count * 2)
    ev_strength += min(20, len(sorted_techniques) * 6)
    evidence_strength = min(100, max(25, int(ev_strength)))

    # Confidence (0-100)
    conf = 55
    conf += min(20, stage_count * 5)
    conf += min(15, event_count // 2)
    if len(sorted_techniques) >= 2:
        conf += 10
    elif len(sorted_techniques) == 1:
        conf += 5
    confidence = min(95, max(50, int(conf)))

    # Mappings from Response Lab and Cyber Twin
    lab_responses_by_type = {r["response_type"]: r for r in lab_result.get("responses", [])}
    twin_sims_by_type = twin_result.get("simulations_by_type", {})

    return {
        "campaign_id": campaign_id,
        "security_risk": security_risk,
        "evidence_strength": evidence_strength,
        "confidence": confidence,
        "stage_count": stage_count,
        "event_count": event_count,
        "source_ips": sorted_sources,
        "source_ip_count": len(sorted_sources),
        "techniques": sorted_techniques,
        "technique_count": len(sorted_techniques),
        "has_recon": has_recon,
        "has_auth_attack": has_auth_attack,
        "has_successful_auth": has_successful_auth,
        "has_powershell": has_powershell,
        "has_privilege_escalation": has_privilege_escalation,
        "has_host_compromise": has_host_compromise,
        "lab_responses_by_type": lab_responses_by_type,
        "twin_sims_by_type": twin_sims_by_type,
    }


# ------------------------------------------------------------------------------
# DETERMINISTIC POLICY EVALUATION ENGINE
# ------------------------------------------------------------------------------

def evaluate_single_policy_option(
    response_type: str,
    factors: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Score a single hypothetical response option against deterministic policy rules.
    Computes a policy score (0-100), residual risk, blast radius, and rationale.
    """
    sec_risk = factors["security_risk"]
    ev_strength = factors["evidence_strength"]
    conf = factors["confidence"]
    has_host_comp = factors["has_host_compromise"]
    has_auth_attack = factors["has_auth_attack"]
    has_recon = factors["has_recon"]
    has_ps = factors["has_powershell"]
    has_priv = factors["has_privilege_escalation"]
    has_success_auth = factors["has_successful_auth"]
    source_count = factors["source_ip_count"]

    lab_resp = factors["lab_responses_by_type"].get(response_type, {})
    twin_sim = factors["twin_sims_by_type"].get(response_type, {})
    sim_data = twin_sim.get("simulation", {})

    # Extract metrics from Cyber Twin or fallback to Response Lab / heuristics
    containment_eff = int(sim_data.get("containment_effectiveness_score") or lab_resp.get("risk_reduction_score") or 0)
    service_impact = int(sim_data.get("service_impact_score") or lab_resp.get("operational_impact_score") or 0)
    blast_radius = int(sim_data.get("blast_radius_score") or 0)
    residual_risk = int(sim_data.get("residual_risk_score") or lab_resp.get("residual_risk_score") or sec_risk)
    resp_conf = int(sim_data.get("confidence") or lab_resp.get("confidence") or conf)

    # Deterministic Rule-Based Policy Scoring
    if response_type == BLOCK_SOURCE_IP:
        if not has_host_comp:
            # Optimal policy choice for pure perimeter/ingress attacks
            score = 86
            if has_auth_attack:
                score += 4
            if has_recon:
                score += 2
            if source_count > 2:
                score -= 4
            policy_score = min(98, max(75, score))
            rationale = (
                f"BLOCK_SOURCE_IP is strongly favored by policy: threat is perimeter/ingress-driven "
                f"({source_count} external IP(s)) without on-host compromise. Delivers high containment ({containment_eff}) "
                f"with negligible service impact ({service_impact})."
            )
        else:
            # Suboptimal when host is compromised because active processes/footholds remain active
            score = 42
            if has_priv:
                score -= 7
            if has_ps:
                score -= 5
            policy_score = min(55, max(30, score))
            rationale = (
                f"BLOCK_SOURCE_IP is disfavored: active host compromise indicators detected "
                f"(credentials/PowerShell/privilege escalation). Firewall ingress block leaves active on-host adversary "
                f"processes unmitigated (residual risk: {residual_risk})."
            )

    elif response_type == ISOLATE_HOST:
        if has_host_comp:
            # Decisive policy choice for confirmed host compromise
            score = 90
            if has_priv:
                score += 4
            if has_ps:
                score += 3
            if has_success_auth:
                score += 2
            policy_score = min(98, max(85, score))
            rationale = (
                f"ISOLATE_HOST is strongly favored by policy: confirmed on-host breach telemetry "
                f"(PowerShell/valid account/privilege escalation). Severe service impact ({service_impact}) and blast radius "
                f"({blast_radius}) are justified to halt lateral movement and active execution (containment: {containment_eff})."
            )
        else:
            # Overkill for external port scans or failed brute force
            policy_score = 48
            rationale = (
                f"ISOLATE_HOST is disfavored: high service impact ({service_impact}) and blast radius ({blast_radius}) "
                f"are disproportionate for an external probing attack without confirmed endpoint foothold."
            )

    elif response_type == NOTIFY_ADMIN:
        # Awareness / escalation fallback
        if ev_strength < 45 or conf < 65:
            # When evidence is borderline, human review is preferred
            policy_score = 78
            rationale = (
                f"NOTIFY_ADMIN is favored: telemetry evidence strength ({ev_strength}) or confidence ({conf}) is "
                f"insufficient for automated containment. Alerting SOC analysts provides human oversight without business disruption."
            )
        else:
            # When clear evidence exists, automated containment is preferred over passive notification
            policy_score = 52
            rationale = (
                f"NOTIFY_ADMIN provides zero automated containment (residual risk: {residual_risk}). In the presence of "
                f"actionable threat telemetry, automated containment options are preferred."
            )

    elif response_type == NO_ACTION:
        # Zero-containment baseline
        policy_score = 10
        rationale = (
            f"NO_ACTION maintains zero containment (effectiveness: 0) and retains maximum residual risk ({residual_risk}). "
            f"Adversary activity continues unhindered."
        )

    else:
        raise PolicyEngineError(f"Unsupported response type: {repr(response_type)}")

    return {
        "response_type": response_type,
        "policy_score": int(policy_score),
        "containment_effectiveness": int(containment_eff),
        "residual_risk": int(residual_risk),
        "service_impact": int(service_impact),
        "blast_radius": int(blast_radius),
        "confidence": int(resp_conf),
        "rationale": rationale,
    }


def evaluate_policy(
    graph: Dict[str, Any],
    lab_result: Dict[str, Any],
    twin_result: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Evaluate candidate response options against deterministic policy rules.

    Parameters:
      graph: Validated Phase 1D Evidence Graph dictionary.
      lab_result: Validated Phase 1E Response Lab evaluation dictionary.
      twin_result: Validated Phase 1F Cyber Twin simulation dictionary.

    Returns:
      Deterministic policy decision dictionary with:
        - campaign_id
        - decision: { recommended_response, decision, policy_score, confidence }
        - alternatives: [ { response_type, policy_score, rationale }, ... ]
        - policy_factors: { security_risk, containment_effectiveness, residual_risk, blast_radius, service_impact, confidence, evidence_strength }
        - reason: Explainable rationale for recommended decision.
        - comparison_reason: Comparative analysis across all evaluated options.
    """
    clean_graph, clean_lab, clean_twin = validate_policy_inputs(graph, lab_result, twin_result)
    factors = extract_policy_factors(clean_graph, clean_lab, clean_twin)
    camp_id = factors["campaign_id"]

    # Evaluate candidate response types present in lab/twin or standard options
    candidate_types = [r["response_type"] for r in clean_lab.get("responses", [])]
    if not candidate_types:
        candidate_types = list(SUPPORTED_RESPONSE_OPTIONS)

    scored_options: List[Dict[str, Any]] = []
    for rtype in candidate_types:
        scored = evaluate_single_policy_option(rtype, factors)
        scored_options.append(scored)

    # Sort scored options by policy score descending to determine recommendation
    sorted_options = sorted(scored_options, key=lambda x: x["policy_score"], reverse=True)
    winner = sorted_options[0]
    rec_type = winner["response_type"]
    rec_score = winner["policy_score"]

    # Determine Decision State: RECOMMEND, REVIEW, or NO_ACTION
    if rec_type in (BLOCK_SOURCE_IP, ISOLATE_HOST):
        if factors["confidence"] >= 60 and factors["evidence_strength"] >= 40:
            decision_state = DECISION_RECOMMEND
        else:
            decision_state = DECISION_REVIEW
    elif rec_type == NOTIFY_ADMIN:
        decision_state = DECISION_REVIEW
    elif rec_type == NO_ACTION:
        decision_state = DECISION_NO_ACTION
    else:
        decision_state = DECISION_REVIEW

    # Format Alternatives
    alternatives = [
        {
            "response_type": opt["response_type"],
            "policy_score": opt["policy_score"],
            "rationale": opt["rationale"],
        }
        for opt in sorted_options
        if opt["response_type"] != rec_type
    ]

    # Overall Policy Factors for the Recommended Action
    policy_factors = {
        "security_risk": factors["security_risk"],
        "containment_effectiveness": winner["containment_effectiveness"],
        "residual_risk": winner["residual_risk"],
        "blast_radius": winner["blast_radius"],
        "service_impact": winner["service_impact"],
        "confidence": winner["confidence"],
        "evidence_strength": factors["evidence_strength"],
    }

    # Generate Explainable Reasons
    if rec_type == ISOLATE_HOST:
        reason = (
            f"Policy selects ISOLATE_HOST ({decision_state}): evidence indicates confirmed on-host compromise "
            f"(PowerShell/credentials/privilege escalation). Decisive containment ({winner['containment_effectiveness']}) "
            f"outweighs endpoint operational disruption ({winner['service_impact']})."
        )
    elif rec_type == BLOCK_SOURCE_IP:
        reason = (
            f"Policy selects BLOCK_SOURCE_IP ({decision_state}): threat is perimeter-driven reconnaissance/brute-force "
            f"from {factors['source_ip_count']} external IP(s). High containment ({winner['containment_effectiveness']}) "
            f"achieved with minimal service disruption ({winner['service_impact']})."
        )
    elif rec_type == NOTIFY_ADMIN:
        reason = (
            f"Policy selects NOTIFY_ADMIN ({decision_state}): automated containment is deferred due to "
            f"borderline evidence strength ({factors['evidence_strength']}) or low confidence ({factors['confidence']})."
        )
    else:
        reason = (
            f"Policy selects NO_ACTION ({decision_state}): baseline monitoring maintained with zero intervention."
        )

    # Comparison Reason Across All Options
    comp_parts = []
    for opt in sorted_options:
        comp_parts.append(
            f"{opt['response_type']} (score: {opt['policy_score']}, containment: {opt['containment_effectiveness']}, impact: {opt['service_impact']})"
        )
    comparison_reason = (
        f"Deterministic Policy Comparison for campaign '{camp_id}': [{'; '.join(comp_parts)}]. "
        f"Decision '{decision_state}' prioritizes {rec_type} (score: {rec_score}) "
        f"based on {'host compromise indicators' if factors['has_host_compromise'] else 'perimeter-focused telemetry'}."
    )

    return {
        "campaign_id": camp_id,
        "decision": {
            "recommended_response": rec_type,
            "decision": decision_state,
            "policy_score": rec_score,
            "confidence": winner["confidence"],
        },
        "alternatives": alternatives,
        "policy_factors": policy_factors,
        "reason": reason,
        "comparison_reason": comparison_reason,
    }


class PolicyEngine:
    """
    Object-oriented wrapper for the Internal Deterministic Policy Engine.
    Provides reproducible, state-free policy evaluations.
    """

    def __init__(self) -> None:
        pass

    def evaluate(
        self,
        graph: Dict[str, Any],
        lab_result: Dict[str, Any],
        twin_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Evaluate candidate response options against deterministic policy rules."""
        return evaluate_policy(graph=graph, lab_result=lab_result, twin_result=twin_result)


# ------------------------------------------------------------------------------
# CONVENIENCE PIPELINE HELPERS
# ------------------------------------------------------------------------------

def evaluate_policy_from_graph(graph: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convenience helper executing:
    Phase 1D Evidence Graph -> Phase 1E Response Lab -> Phase 1F Cyber Twin -> Phase 1G Policy Engine.
    """
    if evaluate_responses is None or simulate_all_responses is None:
        raise PolicyEngineError("Phase 1E or Phase 1F dependencies not available.")
    lab_result = evaluate_responses(graph)
    twin_result = simulate_all_responses(graph, lab_result)
    return evaluate_policy(graph, lab_result, twin_result)


def evaluate_policy_from_story(story: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convenience helper executing:
    Phase 1C Story -> Phase 1D Graph -> Phase 1E Lab -> Phase 1F Twin -> Phase 1G Policy.
    """
    if build_evidence_graph is None:
        raise PolicyEngineError("Phase 1D build_evidence_graph is not available.")
    graph = build_evidence_graph(story)
    return evaluate_policy_from_graph(graph)


def evaluate_policy_from_campaign(campaign: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convenience helper executing:
    Phase 1B Campaign -> Phase 1C Story -> Phase 1D Graph -> Phase 1E Lab -> Phase 1F Twin -> Phase 1G Policy.
    """
    if build_evidence_graph_from_campaign is None:
        raise PolicyEngineError("Phase 1D build_evidence_graph_from_campaign is not available.")
    graph = build_evidence_graph_from_campaign(campaign)
    return evaluate_policy_from_graph(graph)


def evaluate_policy_from_events(
    events: Sequence[Dict[str, Any]],
    time_window_minutes: float = 30.0,
    campaign_id_prefix: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Convenience helper executing the complete Phase 1 pipeline:
    1A Events -> 1B Campaign -> 1C Story -> 1D Graph -> 1E Lab -> 1F Twin -> 1G Policy.
    """
    if build_evidence_graph_from_events is None:
        raise PolicyEngineError("Phase 1D build_evidence_graph_from_events is not available.")
    graph = build_evidence_graph_from_events(
        events=events,
        time_window_minutes=time_window_minutes,
        campaign_id_prefix=campaign_id_prefix
    )
    if not graph:
        return None
    return evaluate_policy_from_graph(graph)
