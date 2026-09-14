"""
Internal Cyber Twin — Deterministic In-Memory Impact Simulation Layer
=====================================================================
Part of the SentinelX Detection & Incident Response Platform (Phase 1F).

Role:
  Consumes the Phase 1D Evidence Graph and Phase 1E Response Lab evaluation
  to predict the hypothetical operational impact, blast radius, containment
  effectiveness, and residual risk of each response option.

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
  Predicted Blast Radius, Service Impact & Residual Risk Matrix

Hypothetical Response Options Simulated:
  - BLOCK_SOURCE_IP: Simulates dropping adversary packets at perimeter firewalls.
  - ISOLATE_HOST: Simulates severing target host network interfaces.
  - NOTIFY_ADMIN: Simulates analyst notification without automated containment.
  - NO_ACTION: Simulates passive telemetry collection without intervention.

Safety & Boundary Rules:
  - SIMULATION ONLY: Does NOT represent a real network environment.
  - ZERO real containment: No system calls, no firewall changes, no host disconnects.
  - ZERO network traffic: No sockets, no HTTP, no external connections.
  - ZERO database modifications: Purely in-memory analysis.
  - ZERO containment layer invocation: Does NOT import services.containment.
  - ZERO external service calls: No Telegram, no Gemini, no third-party APIs.
  - Strictly deterministic: Identical Evidence Graph + Response Lab yields identical simulation.
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
        evaluate_responses_from_story,
        evaluate_responses_from_campaign,
        evaluate_responses_from_events,
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
    evaluate_responses_from_story = None  # type: ignore
    evaluate_responses_from_campaign = None  # type: ignore
    evaluate_responses_from_events = None  # type: ignore


# ------------------------------------------------------------------------------
# CONSTANTS & CONSTRAINTS
# ------------------------------------------------------------------------------

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

class CyberTwinError(ValueError):
    """Raised when evidence graph or response lab input to Cyber Twin is malformed or invalid."""
    pass


# ------------------------------------------------------------------------------
# VALIDATION UTILITIES
# ------------------------------------------------------------------------------

def validate_ip_address(ip_str: Any) -> str:
    """Validate that source IP is a syntactically valid IPv4 address."""
    if not isinstance(ip_str, str) or not ip_str.strip():
        raise CyberTwinError(f"Invalid source IP: {repr(ip_str)}")
    cleaned = ip_str.strip()
    try:
        addr = ipaddress.ip_address(cleaned)
        if not isinstance(addr, ipaddress.IPv4Address):
            raise CyberTwinError(f"Only IPv4 addresses supported: '{ip_str}'")
        return cleaned
    except ValueError as exc:
        raise CyberTwinError(f"Malformed IPv4 address '{ip_str}': {exc}") from exc


def validate_technique_id(tech_id: Any) -> str:
    """Validate MITRE technique ID format (e.g. 'T1110' or 'T1059.001')."""
    if not isinstance(tech_id, str) or not tech_id.strip():
        raise CyberTwinError(f"Invalid MITRE technique ID: {repr(tech_id)}")
    cleaned = tech_id.strip().upper()
    if not re.match(r"^T\d{4}(\.\d{3})?$", cleaned):
        raise CyberTwinError(f"Malformed MITRE technique ID format: '{tech_id}'")
    return cleaned


def validate_cyber_twin_inputs(
    graph: Any,
    lab_result: Any
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Strictly validate both Phase 1D Evidence Graph and Phase 1E Response Lab inputs.
    Enforces boundary limits, structural schema, and campaign identity consistency.
    """
    # 1. Validate Evidence Graph
    if graph is None:
        raise CyberTwinError("Evidence graph cannot be None.")
    if not isinstance(graph, dict):
        raise CyberTwinError(f"Evidence graph must be a dictionary, got: {type(graph).__name__}")
    if not graph:
        raise CyberTwinError("Evidence graph dictionary cannot be empty.")

    campaign = graph.get("campaign")
    if not isinstance(campaign, dict) or not campaign:
        raise CyberTwinError("Missing or invalid 'campaign' in evidence graph.")

    campaign_id = campaign.get("campaign_id")
    if not isinstance(campaign_id, str) or not campaign_id.strip():
        raise CyberTwinError(f"Missing or invalid 'campaign_id' in evidence graph campaign: {repr(campaign_id)}")

    raw_nodes = graph.get("nodes")
    if raw_nodes is None or not isinstance(raw_nodes, (list, tuple)):
        raise CyberTwinError(f"Missing or invalid 'nodes' in evidence graph: {repr(raw_nodes)}")
    if len(raw_nodes) > MAX_GRAPH_NODES_BOUND:
        raise CyberTwinError(f"Graph node count ({len(raw_nodes)}) exceeds safety limit ({MAX_GRAPH_NODES_BOUND}).")

    seen_node_ids = set()
    deduped_nodes: List[Dict[str, Any]] = []
    for idx, node in enumerate(raw_nodes):
        if not isinstance(node, dict):
            raise CyberTwinError(f"Node at index {idx} must be a dictionary.")
        node_id = node.get("node_id")
        if not isinstance(node_id, str) or not node_id.strip():
            raise CyberTwinError(f"Node at index {idx} has invalid 'node_id': {repr(node_id)}")
        node_type = node.get("node_type")
        if not isinstance(node_type, str) or node_type not in VALID_NODE_TYPES:
            raise CyberTwinError(f"Node '{node_id}' has invalid 'node_type': {repr(node_type)}")

        metadata = node.get("metadata")
        if metadata is not None and not isinstance(metadata, dict):
            raise CyberTwinError(f"Node '{node_id}' metadata must be a dictionary.")

        if metadata:
            if node_type == "TECHNIQUE":
                tech_id = metadata.get("technique_id")
                if tech_id is not None:
                    validate_technique_id(tech_id)
            elif node_type == "EVENT":
                source_ip = metadata.get("source_ip")
                if source_ip is not None and str(source_ip).strip().lower() not in ("unknown", ""):
                    validate_ip_address(source_ip)
            elif node_type == "STAGE":
                sources = metadata.get("sources", [])
                if isinstance(sources, (list, tuple)):
                    for s in sources:
                        validate_ip_address(s)

        if node_id not in seen_node_ids:
            seen_node_ids.add(node_id)
            deduped_nodes.append(node)

    raw_edges = graph.get("edges")
    if raw_edges is None or not isinstance(raw_edges, (list, tuple)):
        raise CyberTwinError(f"Missing or invalid 'edges' in evidence graph: {repr(raw_edges)}")
    if len(raw_edges) > MAX_GRAPH_EDGES_BOUND:
        raise CyberTwinError(f"Graph edge count ({len(raw_edges)}) exceeds safety limit ({MAX_GRAPH_EDGES_BOUND}).")

    for idx, edge in enumerate(raw_edges):
        if not isinstance(edge, dict):
            raise CyberTwinError(f"Edge at index {idx} must be a dictionary.")
        src = edge.get("source")
        tgt = edge.get("target")
        rel = edge.get("relationship")
        if not isinstance(src, str) or not src.strip():
            raise CyberTwinError(f"Edge at index {idx} has invalid 'source': {repr(src)}")
        if not isinstance(tgt, str) or not tgt.strip():
            raise CyberTwinError(f"Edge at index {idx} has invalid 'target': {repr(tgt)}")
        if not isinstance(rel, str) or rel not in VALID_RELATIONSHIPS:
            raise CyberTwinError(f"Edge at index {idx} has invalid 'relationship': {repr(rel)}")

    # 2. Validate Response Lab Result
    if lab_result is None:
        raise CyberTwinError("Response lab result cannot be None.")
    if not isinstance(lab_result, dict):
        raise CyberTwinError(f"Response lab result must be a dictionary, got: {type(lab_result).__name__}")
    if not lab_result:
        raise CyberTwinError("Response lab result dictionary cannot be empty.")

    lab_campaign_id = lab_result.get("campaign_id")
    if not isinstance(lab_campaign_id, str) or not lab_campaign_id.strip():
        raise CyberTwinError(f"Missing or invalid 'campaign_id' in response lab result: {repr(lab_campaign_id)}")

    if lab_campaign_id.strip() != campaign_id.strip():
        raise CyberTwinError(
            f"Campaign ID mismatch: Evidence Graph has '{campaign_id.strip()}', "
            f"but Response Lab has '{lab_campaign_id.strip()}'."
        )

    raw_responses = lab_result.get("responses")
    if raw_responses is None or not isinstance(raw_responses, (list, tuple)):
        raise CyberTwinError(f"Missing or invalid 'responses' in response lab result: {repr(raw_responses)}")
    if not raw_responses:
        raise CyberTwinError("Response lab result 'responses' list cannot be empty.")
    if len(raw_responses) > MAX_RESPONSES_BOUND:
        raise CyberTwinError(f"Response count ({len(raw_responses)}) exceeds limit ({MAX_RESPONSES_BOUND}).")

    seen_types = set()
    validated_responses: List[Dict[str, Any]] = []
    for idx, resp in enumerate(raw_responses):
        if not isinstance(resp, dict):
            raise CyberTwinError(f"Response at index {idx} must be a dictionary.")

        resp_type = resp.get("response_type")
        if not isinstance(resp_type, str) or resp_type.strip().upper() not in VALID_RESPONSE_TYPES:
            raise CyberTwinError(f"Response at index {idx} has invalid or unsupported 'response_type': {repr(resp_type)}")
        norm_type = resp_type.strip().upper()

        # Validate numeric scores
        for score_field in (
            "coverage_score",
            "risk_reduction_score",
            "operational_impact_score",
            "residual_risk_score",
            "confidence",
        ):
            score_val = resp.get(score_field)
            if not isinstance(score_val, (int, float)):
                raise CyberTwinError(f"Response '{norm_type}' field '{score_field}' must be numeric, got: {type(score_val).__name__}")
            if not (0 <= score_val <= 100):
                raise CyberTwinError(f"Response '{norm_type}' field '{score_field}' ({score_val}) outside [0, 100].")

        if norm_type not in seen_types:
            seen_types.add(norm_type)
            validated_responses.append(resp)

    clean_graph = {
        "campaign": campaign,
        "nodes": deduped_nodes,
        "edges": list(raw_edges),
        "summary": graph.get("summary") or {},
    }

    clean_lab = {
        "campaign_id": campaign_id.strip(),
        "responses": validated_responses,
        "recommendation": lab_result.get("recommendation") or {},
        "comparison_reason": lab_result.get("comparison_reason", ""),
    }

    return clean_graph, clean_lab


# ------------------------------------------------------------------------------
# CYBER TWIN FEATURE EXTRACTION
# ------------------------------------------------------------------------------

def extract_cyber_twin_features(graph: Dict[str, Any], lab_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract structured telemetry, topological relationships, and Phase 1E metrics
    for hypothetical impact modeling.
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
    stage_keys_list: List[str] = []
    event_ids_list: List[Any] = []

    for s in campaign.get("sources", []):
        if s:
            source_ips_set.add(s)

    for node in nodes:
        ntype = node.get("node_type")
        meta = node.get("metadata", {})

        if ntype == "STAGE":
            stage_nodes.append(node)
            s_key = meta.get("stage_key") or f"stage_{meta.get('stage_number', len(stage_nodes))}"
            stage_keys_list.append(s_key)
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
            eid = meta.get("event_id")
            if eid is not None:
                event_ids_list.append(eid)
            else:
                event_ids_list.append(node.get("node_id"))

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

    # Technique and Stage Semantics
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

    # Build Map of Phase 1E Responses
    responses_by_type = {r["response_type"]: r for r in lab_result["responses"]}

    # Initial campaign base risk (derived consistently from evidence)
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
    base_risk_score = min(100, max(15, int(base_risk)))

    return {
        "campaign_id": campaign_id,
        "stage_count": stage_count,
        "event_count": event_count,
        "source_ips": sorted_sources,
        "techniques": sorted_techniques,
        "stage_keys": stage_keys_list,
        "event_ids": event_ids_list,
        "has_recon": has_recon,
        "has_auth_attack": has_auth_attack,
        "has_successful_auth": has_successful_auth,
        "has_powershell": has_powershell,
        "has_privilege_escalation": has_privilege_escalation,
        "has_host_compromise": has_host_compromise,
        "base_risk_score": base_risk_score,
        "responses_by_type": responses_by_type,
        "recommendation": lab_result.get("recommendation", {}),
    }


# ------------------------------------------------------------------------------
# DETERMINISTIC CYBER TWIN IMPACT MODEL
# ------------------------------------------------------------------------------

def simulate_single_response(
    response_type: str,
    features: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Simulate the hypothetical blast radius, service impact, containment effectiveness,
    and residual risk of a single response option against the cyber twin model.
    """
    camp_id = features["campaign_id"]
    base_risk = features["base_risk_score"]
    source_ips = features["source_ips"]
    source_count = len(source_ips)
    techniques = features["techniques"]
    stage_keys = features["stage_keys"]
    event_ids = features["event_ids"]

    has_recon = features["has_recon"]
    has_auth = features["has_auth_attack"]
    has_success_auth = features["has_successful_auth"]
    has_ps = features["has_powershell"]
    has_priv = features["has_privilege_escalation"]
    has_host_comp = features["has_host_compromise"]

    # Phase 1E score reference if present
    lab_resp = features["responses_by_type"].get(response_type, {})
    lab_cov = lab_resp.get("coverage_score", 0)
    lab_risk_red = lab_resp.get("risk_reduction_score", 0)
    lab_op_impact = lab_resp.get("operational_impact_score", 0)
    lab_residual = lab_resp.get("residual_risk_score", base_risk)
    lab_conf = lab_resp.get("confidence", 75)

    if response_type == BLOCK_SOURCE_IP:
        affected_sources = list(source_ips)
        affected_stages = [
            s for s in stage_keys
            if "recon" in s.lower() or "auth" in s.lower() or "brute" in s.lower()
        ]
        if not affected_stages and stage_keys:
            affected_stages = [stage_keys[0]]

        affected_techniques = [t for t in techniques if t in ("T1046", "T1110")]
        if not affected_techniques and (has_recon or has_auth):
            affected_techniques = ["T1110"] if has_auth else ["T1046"]

        affected_events = event_ids[:min(len(event_ids), len(affected_stages) * 4)]

        # Blast Radius: localized perimeter firewall filtering (low radius)
        blast_radius = min(30, 10 + source_count * 4)

        # Service Impact: minor overhead on perimeter ACLs, zero endpoint disruption
        service_impact = min(30, 10 + source_count * 3)

        # Containment Effectiveness:
        # High against perimeter reconnaissance/brute force, but leaves host uncontained if breached
        if not has_host_comp:
            containment_eff = min(88, max(70, int(lab_cov * 0.95) if lab_cov else 82))
            residual_risk = max(0, min(100, base_risk - containment_eff))
            predicted_outcome = (
                f"Simulated outcome: Firewall drops ingress packets across {source_count} adversary IP(s). "
                f"Halts external reconnaissance and credential brute-force attacks at the boundary. "
                f"Internal services and hosts remain fully operational."
            )
            reason = (
                f"BLOCK_SOURCE_IP isolates {source_count} external source(s) with minimal blast radius ({blast_radius}) "
                f"and low service impact ({service_impact}). No active host compromise is present, yielding "
                f"high containment effectiveness ({containment_eff})."
            )
        else:
            containment_eff = min(45, max(30, int(lab_cov * 0.95) if lab_cov else 38))
            residual_risk = max(35, min(100, base_risk - containment_eff))
            predicted_outcome = (
                f"Simulated outcome: Perimeter firewall blocks future ingress from {source_count} adversary IP(s). "
                f"However, on-host adversary execution (PowerShell / credential foothold / privilege escalation) "
                f"remains active and unmitigated on the endpoint."
            )
            reason = (
                f"BLOCK_SOURCE_IP provides partial boundary containment ({containment_eff}), but leaves substantial "
                f"residual risk ({residual_risk}) because evidence indicates active host compromise already occurred."
            )

        confidence = lab_conf or 80

    elif response_type == ISOLATE_HOST:
        affected_sources = []
        affected_stages = [
            s for s in stage_keys
            if "success" in s.lower() or "powershell" in s.lower() or "priv" in s.lower() or "valid" in s.lower()
        ]
        if not affected_stages:
            affected_stages = list(stage_keys)

        affected_techniques = [t for t in techniques if t in ("T1078", "T1059.001", "T1068")]
        if not affected_techniques and techniques:
            affected_techniques = list(techniques)

        affected_events = list(event_ids)

        # Blast Radius: broad endpoint footprint (entire machine disconnected from network)
        blast_radius = 80

        # Service Impact: severing host network interfaces takes all legitimate business services offline
        service_impact = 80

        # Containment Effectiveness:
        # Decisive against on-host foothold, lateral movement, and privilege escalation
        if has_host_comp:
            containment_eff = min(95, max(85, int(lab_cov * 0.98) if lab_cov else 90))
            residual_risk = max(5, min(25, base_risk - containment_eff))
            predicted_outcome = (
                f"Simulated outcome: Target host network interfaces are severed. Active PowerShell processes, "
                f"privilege escalation, and lateral movement channels are halted immediately. "
                f"All business services hosted on this machine are temporarily inaccessible."
            )
            reason = (
                f"ISOLATE_HOST exerts high blast radius ({blast_radius}) and service impact ({service_impact}), "
                f"but achieves decisive threat containment ({containment_eff}) against confirmed on-host compromise, "
                f"reducing residual risk to {residual_risk}."
            )
        else:
            containment_eff = 50
            residual_risk = max(15, base_risk - containment_eff)
            predicted_outcome = (
                f"Simulated outcome: Target host network interfaces are severed. Halts potential host compromise, "
                f"but creates an unnecessary service outage given only external perimeter scanning was detected."
            )
            reason = (
                f"ISOLATE_HOST imposes disproportionately high service disruption ({service_impact}) for an external "
                f"probing attack with no confirmed endpoint foothold."
            )

        confidence = min(95, (lab_conf or 80) + 5) if has_host_comp else (lab_conf or 75)

    elif response_type == NOTIFY_ADMIN:
        affected_sources = []
        affected_stages = []
        affected_events = []
        affected_techniques = []

        blast_radius = 5
        service_impact = 5
        containment_eff = 15
        residual_risk = max(10, base_risk - containment_eff)
        confidence = min(95, (lab_conf or 85) + 5)

        predicted_outcome = (
            f"Simulated outcome: Alert context is dispatched to the SOC triage queue. Telemetry collection continues "
            f"normally without automated network intervention. Adversary attack sequence proceeds uninterrupted."
        )
        reason = (
            f"NOTIFY_ADMIN causes negligible service disruption ({service_impact}) and blast radius ({blast_radius}), "
            f"but delivers minimal automated containment ({containment_eff}), leaving elevated residual risk ({residual_risk})."
        )

    elif response_type == NO_ACTION:
        affected_sources = []
        affected_stages = []
        affected_events = []
        affected_techniques = []

        blast_radius = 0
        service_impact = 0
        containment_eff = 0
        residual_risk = base_risk
        confidence = 100

        predicted_outcome = (
            f"Simulated outcome: Zero intervention. The adversary executes uninterrupted through reconnaissance, "
            f"authentication attempts, and on-host objectives."
        )
        reason = (
            f"NO_ACTION incurs zero blast radius (0) and zero service disruption (0), but offers zero containment (0). "
            f"Full initial threat risk ({residual_risk}) remains entirely unmitigated."
        )

    else:
        raise CyberTwinError(f"Unsupported response type in simulation: {repr(response_type)}")

    # Comparison metrics
    risk_change = max(0, base_risk - residual_risk)
    impact_summary = (
        f"Simulated {response_type}: containment={containment_eff}, service impact={service_impact}, "
        f"blast radius={blast_radius}, risk reduced by {risk_change} (residual: {residual_risk})."
    )

    rec_type = features.get("recommendation", {}).get("response_type")
    is_recommended = (response_type == rec_type)
    if is_recommended:
        sim_reason = (
            f"{response_type} is the optimal response predicted by the Cyber Twin. "
            f"It maximizes containment effectiveness ({containment_eff}) relative to operational blast radius ({blast_radius})."
        )
    else:
        sim_reason = (
            f"{response_type} yields {impact_summary}. Compared to the recommended response ({rec_type or 'N/A'}), "
            f"it represents a suboptimal trade-off between threat neutralization and operational impact."
        )

    return {
        "campaign_id": camp_id,
        "response_type": response_type,
        "simulation": {
            "affected_sources": affected_sources,
            "affected_stages": affected_stages,
            "affected_events": affected_events,
            "affected_techniques": affected_techniques,
            "blast_radius_score": int(blast_radius),
            "service_impact_score": int(service_impact),
            "containment_effectiveness_score": int(containment_eff),
            "residual_risk_score": int(residual_risk),
            "confidence": int(confidence),
            "predicted_outcome": predicted_outcome,
            "reason": reason,
        },
        "comparison": {
            "risk_change": int(risk_change),
            "impact_summary": impact_summary,
            "simulation_reason": sim_reason,
        }
    }


# ------------------------------------------------------------------------------
# HIGH-LEVEL CYBER TWIN API
# ------------------------------------------------------------------------------

def simulate_response_impact(
    graph: Dict[str, Any],
    lab_result: Dict[str, Any],
    response_type: str
) -> Dict[str, Any]:
    """
    Simulate the hypothetical impact of a single response option against an Evidence Graph
    and Phase 1E Response Lab result.
    """
    clean_graph, clean_lab = validate_cyber_twin_inputs(graph, lab_result)
    norm_type = str(response_type).strip().upper()
    if norm_type not in VALID_RESPONSE_TYPES:
        raise CyberTwinError(f"Unknown or unsupported response type: {repr(response_type)}")

    features = extract_cyber_twin_features(clean_graph, clean_lab)
    return simulate_single_response(norm_type, features)


def simulate_all_responses(
    graph: Dict[str, Any],
    lab_result: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Simulate all hypothetical response options evaluated in the Response Lab result.
    Returns individual simulations and comparative trade-off analysis.
    """
    clean_graph, clean_lab = validate_cyber_twin_inputs(graph, lab_result)
    features = extract_cyber_twin_features(clean_graph, clean_lab)

    simulations: List[Dict[str, Any]] = []
    simulations_by_type: Dict[str, Dict[str, Any]] = {}

    for resp in clean_lab["responses"]:
        rtype = resp["response_type"]
        sim = simulate_single_response(rtype, features)
        simulations.append(sim)
        simulations_by_type[rtype] = sim

    rec = clean_lab.get("recommendation", {})
    rec_type = rec.get("response_type")
    optimal_sim = simulations_by_type.get(rec_type) if rec_type else (simulations[0] if simulations else None)

    summary_lines = [
        f"Cyber Twin Impact Simulation for campaign '{features['campaign_id']}' across {len(simulations)} response option(s):"
    ]
    for s in simulations:
        rtype = s["response_type"]
        sim_data = s["simulation"]
        summary_lines.append(
            f"  - {rtype}: containment={sim_data['containment_effectiveness_score']}, "
            f"blast radius={sim_data['blast_radius_score']}, service impact={sim_data['service_impact_score']}, "
            f"residual risk={sim_data['residual_risk_score']}"
        )

    overall_summary = "\n".join(summary_lines)

    return {
        "campaign_id": features["campaign_id"],
        "simulations": simulations,
        "simulations_by_type": simulations_by_type,
        "optimal_simulation": optimal_sim,
        "overall_comparison": {
            "summary": overall_summary,
            "recommended_response": rec_type or "UNKNOWN",
            "trade_off_analysis": (
                f"Recommendation '{rec_type}' balances threat containment against operational blast radius. "
                f"Simulated evidence indicates {'confirmed host breach' if features['has_host_compromise'] else 'perimeter-focused attack activity'}."
            )
        }
    }


class CyberTwin:
    """
    Object-oriented wrapper for the Internal Cyber Twin simulation engine.
    Provides reproducible, deterministic in-memory impact modeling.
    """

    def __init__(self) -> None:
        pass

    def simulate_response(
        self,
        graph: Dict[str, Any],
        lab_result: Dict[str, Any],
        response_type: str
    ) -> Dict[str, Any]:
        """Simulate a single response option."""
        return simulate_response_impact(graph=graph, lab_result=lab_result, response_type=response_type)

    def simulate_all(
        self,
        graph: Dict[str, Any],
        lab_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Simulate all responses present in Response Lab result."""
        return simulate_all_responses(graph=graph, lab_result=lab_result)


# ------------------------------------------------------------------------------
# CONVENIENCE PIPELINE HELPERS
# ------------------------------------------------------------------------------

def simulate_response_from_graph(
    graph: Dict[str, Any],
    response_type: Optional[str] = None
) -> Dict[str, Any]:
    """
    Convenience helper executing:
    Phase 1D Evidence Graph -> Phase 1E Response Lab -> Phase 1F Cyber Twin.
    """
    if evaluate_responses is None:
        raise CyberTwinError("Phase 1E evaluate_responses is not available.")
    lab_result = evaluate_responses(graph)
    if response_type:
        return simulate_response_impact(graph, lab_result, response_type=response_type)
    return simulate_all_responses(graph, lab_result)


def simulate_impact_from_story(
    story: Dict[str, Any],
    response_type: Optional[str] = None
) -> Dict[str, Any]:
    """
    Convenience helper executing:
    Phase 1C Story -> Phase 1D Evidence Graph -> Phase 1E Response Lab -> Phase 1F Cyber Twin.
    """
    if build_evidence_graph is None or evaluate_responses is None:
        raise CyberTwinError("Phase 1D or Phase 1E dependencies not available.")
    graph = build_evidence_graph(story)
    lab_result = evaluate_responses(graph)
    if response_type:
        return simulate_response_impact(graph, lab_result, response_type=response_type)
    return simulate_all_responses(graph, lab_result)


def simulate_impact_from_campaign(
    campaign: Dict[str, Any],
    response_type: Optional[str] = None
) -> Dict[str, Any]:
    """
    Convenience helper executing:
    Phase 1B Campaign -> Phase 1C Story -> Phase 1D Evidence Graph -> Phase 1E Response Lab -> Phase 1F Cyber Twin.
    """
    if build_evidence_graph_from_campaign is None or evaluate_responses is None:
        raise CyberTwinError("Phase 1D or Phase 1E dependencies not available.")
    graph = build_evidence_graph_from_campaign(campaign)
    lab_result = evaluate_responses(graph)
    if response_type:
        return simulate_response_impact(graph, lab_result, response_type=response_type)
    return simulate_all_responses(graph, lab_result)


def simulate_impact_from_events(
    events: Sequence[Dict[str, Any]],
    time_window_minutes: float = 30.0,
    campaign_id_prefix: Optional[str] = None,
    response_type: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Convenience helper executing the complete Phase 1 pipeline:
    1A Events -> 1B Campaign -> 1C Story -> 1D Evidence Graph -> 1E Response Lab -> 1F Cyber Twin.
    """
    if build_evidence_graph_from_events is None or evaluate_responses is None:
        raise CyberTwinError("Phase 1D or Phase 1E dependencies not available.")
    graph = build_evidence_graph_from_events(
        events=events,
        time_window_minutes=time_window_minutes,
        campaign_id_prefix=campaign_id_prefix
    )
    if not graph:
        return None
    lab_result = evaluate_responses(graph)
    if response_type:
        return simulate_response_impact(graph, lab_result, response_type=response_type)
    return simulate_all_responses(graph, lab_result)
