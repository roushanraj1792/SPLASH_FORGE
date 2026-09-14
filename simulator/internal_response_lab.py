"""
Internal Response Lab — Deterministic In-Memory Response Comparison Layer
========================================================================
Part of the SentinelX Detection & Incident Response Platform (Phase 1E).

Role:
  Consumes the Phase 1D Evidence Graph and deterministically evaluates
  hypothetical response options without executing any active containment.
  Produces explainable predicted outcomes, risk reduction scores, operational
  impact assessments, residual risk calculations, and comparative recommendations.

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
  Hypothetical Response Options (A vs B vs C)
           ↓
  Deterministic Predicted Scores & Explainable Recommendation

Hypothetical Response Options Evaluated:
  - BLOCK_SOURCE_IP: Perimeter firewall / ingress blocking of adversary IPs.
  - ISOLATE_HOST: Endpoint network segmentation / host isolation.
  - NOTIFY_ADMIN: Escalation alert to SOC analysts / on-call engineers.
  - NO_ACTION: Passive telemetry monitoring with zero intervention.

Safety & Boundary Rules:
  - SIMULATION & REASONING ONLY: No real firewall commands or system isolation.
  - ZERO network traffic: No HTTP, no sockets, no external APIs.
  - ZERO database modifications: Purely in-memory evaluation.
  - ZERO containment layer invocation: Does NOT import services.containment.
  - ZERO external service calls: No Telegram, no Gemini, no external alerts.
  - Strictly deterministic: Identical Evidence Graph + options yield identical output.
  - No randomness, no datetime.now(), no UUIDs.
"""

import ipaddress
import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

# Optional convenience imports for end-to-end chaining
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


# ------------------------------------------------------------------------------
# CONSTANTS & CONSTRAINTS
# ------------------------------------------------------------------------------

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

VALID_RESPONSE_TYPES = set(SUPPORTED_RESPONSE_OPTIONS)

MAX_GRAPH_NODES_BOUND = 5000
MAX_GRAPH_EDGES_BOUND = 10000
MAX_RESPONSE_OPTIONS_BOUND = 20
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

# Known MITRE technique IDs mapped to semantics
MITRE_HOST_COMPROMISE_TECHNIQUES = {
    "T1078",     # Valid Accounts (Foothold / Initial Access)
    "T1059.001", # PowerShell Execution
    "T1068",     # Exploitation for Privilege Escalation
}

MITRE_PERIMETER_TECHNIQUES = {
    "T1046",     # Network Service Discovery / Port Scan
    "T1110",     # Brute Force / Credential Stuffing
}


# ------------------------------------------------------------------------------
# EXCEPTIONS
# ------------------------------------------------------------------------------

class ResponseLabError(ValueError):
    """Raised when evidence graph input or response options are malformed or invalid."""
    pass


# ------------------------------------------------------------------------------
# VALIDATION UTILITIES
# ------------------------------------------------------------------------------

def validate_technique_id(tech_id: Any) -> str:
    """Validate MITRE technique ID format (e.g. 'T1110' or 'T1059.001')."""
    if not isinstance(tech_id, str) or not tech_id.strip():
        raise ResponseLabError(f"Invalid MITRE technique ID: {repr(tech_id)}")
    cleaned = tech_id.strip().upper()
    if not re.match(r"^T\d{4}(\.\d{3})?$", cleaned):
        raise ResponseLabError(f"Malformed MITRE technique ID format: '{tech_id}'")
    return cleaned


def validate_ip_address(ip_str: Any) -> str:
    """Validate that source IP is a syntactically valid IPv4 address."""
    if not isinstance(ip_str, str) or not ip_str.strip():
        raise ResponseLabError(f"Invalid source IP: {repr(ip_str)}")
    cleaned = ip_str.strip()
    try:
        addr = ipaddress.ip_address(cleaned)
        if not isinstance(addr, ipaddress.IPv4Address):
            raise ResponseLabError(f"Only IPv4 addresses supported: '{ip_str}'")
        return cleaned
    except ValueError as exc:
        raise ResponseLabError(f"Malformed IPv4 address '{ip_str}': {exc}") from exc


def validate_response_options(response_options: Any) -> List[str]:
    """
    Validate and deduplicate the list of hypothetical response options.
    Rejects unknown options and bounds total options.
    """
    if response_options is None:
        return list(SUPPORTED_RESPONSE_OPTIONS)

    if not isinstance(response_options, (list, tuple)):
        raise ResponseLabError(
            f"Response options must be a list or tuple, got: {type(response_options).__name__}"
        )

    if not response_options:
        raise ResponseLabError("Response options list cannot be empty.")

    if len(response_options) > MAX_RESPONSE_OPTIONS_BOUND:
        raise ResponseLabError(
            f"Response options count ({len(response_options)}) exceeds safety limit ({MAX_RESPONSE_OPTIONS_BOUND})."
        )

    seen = set()
    cleaned: List[str] = []
    for idx, opt in enumerate(response_options):
        if not isinstance(opt, str):
            raise ResponseLabError(f"Response option at index {idx} must be a string, got: {type(opt).__name__}")
        norm_opt = opt.strip().upper()
        if norm_opt not in VALID_RESPONSE_TYPES:
            raise ResponseLabError(f"Unknown or unsupported response option: {repr(opt)}")
        if norm_opt not in seen:
            seen.add(norm_opt)
            cleaned.append(norm_opt)

    return cleaned


def validate_evidence_graph_input(graph: Any) -> Dict[str, Any]:
    """
    Strictly validate that the Evidence Graph dictionary adheres to the Phase 1D schema
    and is bounded in size.
    """
    if graph is None:
        raise ResponseLabError("Evidence graph cannot be None.")

    if not isinstance(graph, dict):
        raise ResponseLabError(f"Evidence graph must be a dictionary, got: {type(graph).__name__}")

    if not graph:
        raise ResponseLabError("Evidence graph dictionary cannot be empty.")

    # 1. Validate Campaign
    campaign = graph.get("campaign")
    if not isinstance(campaign, dict) or not campaign:
        raise ResponseLabError("Missing or invalid 'campaign' dictionary in evidence graph.")

    campaign_id = campaign.get("campaign_id")
    if not isinstance(campaign_id, str) or not campaign_id.strip():
        raise ResponseLabError(f"Missing or invalid 'campaign_id' in campaign: {repr(campaign_id)}")

    # Validate campaign sources if present
    camp_sources = campaign.get("sources", [])
    if not isinstance(camp_sources, (list, tuple)):
        raise ResponseLabError("Campaign 'sources' must be a list or tuple.")
    for ip in camp_sources:
        validate_ip_address(ip)

    # 2. Validate Nodes
    raw_nodes = graph.get("nodes")
    if raw_nodes is None or not isinstance(raw_nodes, (list, tuple)):
        raise ResponseLabError(f"Missing or invalid 'nodes' in evidence graph: {repr(raw_nodes)}")

    if len(raw_nodes) > MAX_GRAPH_NODES_BOUND:
        raise ResponseLabError(
            f"Graph node count ({len(raw_nodes)}) exceeds safety limit ({MAX_GRAPH_NODES_BOUND})."
        )

    seen_node_ids = set()
    deduped_nodes: List[Dict[str, Any]] = []

    for idx, node in enumerate(raw_nodes):
        if not isinstance(node, dict):
            raise ResponseLabError(f"Node at index {idx} must be a dictionary.")

        node_id = node.get("node_id")
        if not isinstance(node_id, str) or not node_id.strip():
            raise ResponseLabError(f"Node at index {idx} has invalid 'node_id': {repr(node_id)}")

        node_type = node.get("node_type")
        if not isinstance(node_type, str) or node_type not in VALID_NODE_TYPES:
            raise ResponseLabError(f"Node '{node_id}' has invalid 'node_type': {repr(node_type)}")

        metadata = node.get("metadata")
        if metadata is not None and not isinstance(metadata, dict):
            raise ResponseLabError(f"Node '{node_id}' metadata must be a dictionary.")

        # Validate node-specific metadata
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
                stage_sources = metadata.get("sources", [])
                if isinstance(stage_sources, (list, tuple)):
                    for s_ip in stage_sources:
                        validate_ip_address(s_ip)

        # Deduplicate nodes safely
        if node_id not in seen_node_ids:
            seen_node_ids.add(node_id)
            deduped_nodes.append(node)

    # 3. Validate Edges
    raw_edges = graph.get("edges")
    if raw_edges is None or not isinstance(raw_edges, (list, tuple)):
        raise ResponseLabError(f"Missing or invalid 'edges' in evidence graph: {repr(raw_edges)}")

    if len(raw_edges) > MAX_GRAPH_EDGES_BOUND:
        raise ResponseLabError(
            f"Graph edge count ({len(raw_edges)}) exceeds safety limit ({MAX_GRAPH_EDGES_BOUND})."
        )

    for idx, edge in enumerate(raw_edges):
        if not isinstance(edge, dict):
            raise ResponseLabError(f"Edge at index {idx} must be a dictionary.")

        source = edge.get("source")
        target = edge.get("target")
        rel = edge.get("relationship")

        if not isinstance(source, str) or not source.strip():
            raise ResponseLabError(f"Edge at index {idx} has invalid 'source': {repr(source)}")
        if not isinstance(target, str) or not target.strip():
            raise ResponseLabError(f"Edge at index {idx} has invalid 'target': {repr(target)}")
        if not isinstance(rel, str) or rel not in VALID_RELATIONSHIPS:
            raise ResponseLabError(f"Edge at index {idx} has invalid 'relationship': {repr(rel)}")

    return {
        "campaign": campaign,
        "nodes": deduped_nodes,
        "edges": list(raw_edges),
        "summary": graph.get("summary") or {}
    }


# ------------------------------------------------------------------------------
# EVIDENCE INDICATOR EXTRACTION
# ------------------------------------------------------------------------------

def extract_graph_indicators(graph: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract structured decision indicators from the validated Evidence Graph.
    These indicators drive explainable, deterministic response scoring.
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

    # Collect source IPs from campaign root
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
            tech_id = meta.get("technique_id")
            if tech_id:
                techniques_set.add(tech_id)

        elif ntype == "EVENT":
            event_nodes.append(node)
            src = meta.get("source_ip")
            if src and str(src).strip().lower() not in ("unknown", ""):
                source_ips_set.add(src)

    # Check summary if present to supplement
    if summary:
        for t in summary.get("techniques", []):
            if t:
                techniques_set.add(t)
        for s in summary.get("source_ips", []):
            if s:
                source_ips_set.add(s)

    sorted_source_ips = sorted(list(source_ips_set))
    sorted_techniques = sorted(list(techniques_set))

    stage_count = len(stage_nodes) or campaign.get("stage_count", 0)
    event_count = len(event_nodes) or campaign.get("event_count", 0)

    # Stage and Technique semantic analysis
    has_recon = False
    has_auth_attack = False
    has_successful_auth = False
    has_powershell = False
    has_privilege_escalation = False

    # Check techniques
    for t in sorted_techniques:
        if t == "T1046":
            has_recon = True
        elif t == "T1110":
            has_auth_attack = True
        elif t == "T1078":
            has_successful_auth = True
        elif t == "T1059.001":
            has_powershell = True
        elif t == "T1068":
            has_privilege_escalation = True

    # Check stage metadata keys and labels
    for stage in stage_nodes:
        meta = stage.get("metadata", {})
        s_key = str(meta.get("stage_key", "")).lower()
        s_title = str(stage.get("label", "")).lower()

        if "recon" in s_key or "recon" in s_title or "service discovery" in s_title:
            has_recon = True
        if "auth" in s_key and "fail" in s_key or "brute" in s_key or "brute" in s_title or s_key == "authentication_attack":
            has_auth_attack = True
        if "success" in s_key or "valid account" in s_title or s_key == "successful_authentication":
            has_successful_auth = True
        if "powershell" in s_key or "powershell" in s_title or s_key == "suspicious_powershell":
            has_powershell = True
        if "priv" in s_key or "escalation" in s_key or "privilege" in s_title or s_key == "privilege_escalation":
            has_privilege_escalation = True

    has_host_compromise = has_successful_auth or has_powershell or has_privilege_escalation

    # Deterministic Base Risk Calculation (scale 10 to 100)
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
    if len(sorted_source_ips) > 1:
        base_risk += min(10, (len(sorted_source_ips) - 1) * 3)
    base_risk += min(10, event_count // 4)

    base_risk_score = min(100, max(15, int(base_risk)))

    # Deterministic Assessment Confidence (scale 50 to 95)
    conf = 55
    conf += min(20, stage_count * 5)
    conf += min(15, event_count // 2)
    if len(sorted_techniques) >= 2:
        conf += 10
    elif len(sorted_techniques) == 1:
        conf += 5
    confidence_score = min(95, max(50, int(conf)))

    return {
        "campaign_id": campaign_id,
        "stage_count": stage_count,
        "event_count": event_count,
        "source_ips": sorted_source_ips,
        "source_ip_count": len(sorted_source_ips),
        "techniques": sorted_techniques,
        "technique_count": len(sorted_techniques),
        "has_recon": has_recon,
        "has_auth_attack": has_auth_attack,
        "has_successful_auth": has_successful_auth,
        "has_powershell": has_powershell,
        "has_privilege_escalation": has_privilege_escalation,
        "has_host_compromise": has_host_compromise,
        "base_risk_score": base_risk_score,
        "confidence_score": confidence_score,
    }


# ------------------------------------------------------------------------------
# RESPONSE EVALUATION ENGINE
# ------------------------------------------------------------------------------

def make_response_id(campaign_id: str, response_type: str) -> str:
    """Generate deterministic response ID."""
    return f"resp:{campaign_id}:{response_type.lower()}"


def evaluate_single_response(response_type: str, indicators: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluate a single hypothetical response option using explainable, deterministic rules.
    Calculates coverage, risk reduction, operational impact, residual risk, and confidence.
    """
    camp_id = indicators["campaign_id"]
    resp_id = make_response_id(camp_id, response_type)
    base_risk = indicators["base_risk_score"]
    base_conf = indicators["confidence_score"]
    source_ips = indicators["source_ips"]
    source_count = indicators["source_ip_count"]
    has_host_comp = indicators["has_host_compromise"]
    has_auth = indicators["has_auth_attack"]
    has_recon = indicators["has_recon"]
    has_ps = indicators["has_powershell"]
    has_priv = indicators["has_privilege_escalation"]
    has_success_auth = indicators["has_successful_auth"]

    ip_desc = ", ".join(source_ips[:3]) + ("..." if len(source_ips) > 3 else "") if source_ips else "all external sources"

    if response_type == BLOCK_SOURCE_IP:
        scope = f"Perimeter firewall / Ingress filter ({ip_desc})"
        predicted_effect = "Drop incoming network traffic and terminate active sessions from adversary source IPs."

        # Coverage: strong against external/ingress, but low against already established host footholds
        if not has_host_comp:
            if has_auth or has_recon:
                cov = 85
                if source_count > 2:
                    cov = max(65, 85 - (source_count - 1) * 4)
            else:
                cov = 75
        else:
            # Attacker already penetrated perimeter; blocking IP leaves host malware/session active
            cov = 40
            if has_priv:
                cov = 35

        # Operational impact: low disruption for perimeter blocks
        op_impact = min(35, 10 + source_count * 3)

        # Risk reduction: high when attack is purely external; moderate when host compromised
        if not has_host_comp:
            reduction = min(85, int(base_risk * 0.78))
        else:
            reduction = min(45, int(base_risk * 0.38))

        residual = max(0, min(100, base_risk - reduction))
        conf = base_conf

        if not has_host_comp:
            reason = (
                f"BLOCK_SOURCE_IP effectively mitigates {source_count} external source IP(s) driving "
                f"ingress attacks (reconnaissance/brute-force) with minimal operational impact ({op_impact}). "
                f"No evidence of active host compromise detected."
            )
        else:
            reason = (
                f"BLOCK_SOURCE_IP blocks ingress from {source_count} IP(s) but yields only partial protection "
                f"(risk reduction: {reduction}) because evidence indicates host compromise has already occurred "
                f"(valid credentials, PowerShell, or privilege escalation)."
            )

    elif response_type == ISOLATE_HOST:
        scope = "Target host endpoint / Network segmentation"
        predicted_effect = "Sever host network interfaces to contain active processes, lateral movement, and data exfiltration."

        # Coverage: extremely high when host compromise exists; moderate for purely external probes
        if has_host_comp:
            cov = 90
            if has_priv:
                cov = 95
        else:
            # Overkill for external scanning
            cov = 45

        # Operational impact: high disruption to endpoint business operations
        op_impact = 75

        # Risk reduction: very high for host compromise; moderate for pure external probes
        if has_host_comp:
            reduction = min(90, int(base_risk * 0.86))
        else:
            reduction = min(55, int(base_risk * 0.50))

        residual = max(0, min(100, base_risk - reduction))
        conf = min(95, base_conf + 5) if has_host_comp else base_conf

        if has_host_comp:
            reasons_list = []
            if has_success_auth:
                reasons_list.append("valid account compromise")
            if has_ps:
                reasons_list.append("suspicious PowerShell execution")
            if has_priv:
                reasons_list.append("privilege escalation")
            evidence_str = ", ".join(reasons_list) or "host compromise indicators"
            reason = (
                f"ISOLATE_HOST achieves decisive risk reduction ({reduction}) by halting adversary lateral movement "
                f"and active execution on the compromised endpoint ({evidence_str}), accepting high operational impact ({op_impact})."
            )
        else:
            reason = (
                f"ISOLATE_HOST neutralizes potential host execution, but is disproportionately disruptive ({op_impact}) "
                f"as current evidence reflects only external probing without confirmed endpoint foothold."
            )

    elif response_type == NOTIFY_ADMIN:
        scope = "Security Operations Center (SOC) / On-Call Incident Responder"
        predicted_effect = "Dispatch high-priority incident context to analysts for manual investigation and triage."
        cov = 20
        op_impact = 5
        reduction = min(20, max(10, int(base_risk * 0.18)))
        residual = max(0, min(100, base_risk - reduction))
        conf = min(95, base_conf + 5)
        reason = (
            f"NOTIFY_ADMIN alerts security personnel without automated containment. Operational impact is negligible ({op_impact}), "
            f"but residual risk remains high ({residual}) requiring manual intervention."
        )

    elif response_type == NO_ACTION:
        scope = "None / Telemetry Passive Monitoring"
        predicted_effect = "Maintain continuous passive telemetry collection without automated or manual intervention."
        cov = 0
        op_impact = 0
        reduction = 0
        residual = base_risk
        conf = 100
        reason = (
            f"NO_ACTION incurs zero operational impact ({op_impact}), but provides zero threat containment (residual risk: {residual}). "
            f"Adversary activity continues unhindered."
        )

    else:
        raise ResponseLabError(f"Unsupported response type: {repr(response_type)}")

    return {
        "response_id": resp_id,
        "response_type": response_type,
        "scope": scope,
        "predicted_effect": predicted_effect,
        "coverage_score": int(cov),
        "risk_reduction_score": int(reduction),
        "operational_impact_score": int(op_impact),
        "residual_risk_score": int(residual),
        "confidence": int(conf),
        "reason": reason,
    }


def compare_and_recommend(
    evaluated_responses: List[Dict[str, Any]],
    indicators: Dict[str, Any]
) -> Tuple[Dict[str, Any], str]:
    """
    Deterministically compare evaluated response options and select the optimal recommendation.
    Generates explainable rationale justifying why the selected response is preferable.
    """
    if not evaluated_responses:
        raise ResponseLabError("Cannot compare an empty list of evaluated responses.")

    camp_id = indicators["campaign_id"]
    has_host_comp = indicators["has_host_compromise"]
    has_auth = indicators["has_auth_attack"]
    has_recon = indicators["has_recon"]
    has_ps = indicators["has_powershell"]
    has_priv = indicators["has_privilege_escalation"]
    has_success_auth = indicators["has_successful_auth"]

    resp_map = {r["response_type"]: r for r in evaluated_responses}

    # Decision Matrix:
    # 1. If host compromise (foothold, powershell, priv esc) exists AND ISOLATE_HOST was evaluated:
    if has_host_comp and ISOLATE_HOST in resp_map:
        rec = resp_map[ISOLATE_HOST]
        reasons = []
        if has_priv:
            reasons.append("privilege escalation (T1068)")
        if has_ps:
            reasons.append("PowerShell execution (T1059.001)")
        if has_success_auth:
            reasons.append("valid account compromise (T1078)")
        evidence_summary = " and ".join(reasons) or "endpoint compromise telemetry"

        block_resp = resp_map.get(BLOCK_SOURCE_IP)
        comparison_note = ""
        if block_resp:
            comparison_note = (
                f" BLOCK_SOURCE_IP provides only {block_resp['risk_reduction_score']}% risk reduction because "
                f"active execution is already established on the host."
            )

        recommendation_reason = (
            f"ISOLATE_HOST is the recommended primary response for campaign '{camp_id}'. "
            f"Evidence confirms {evidence_summary}. Immediate host isolation is required to prevent "
            f"adversary persistence and lateral movement despite high operational impact ({rec['operational_impact_score']})."
            f"{comparison_note}"
        )

    # 2. If perimeter/ingress attack (recon, brute force) without confirmed host compromise AND BLOCK_SOURCE_IP was evaluated:
    elif (has_auth or has_recon or not has_host_comp) and BLOCK_SOURCE_IP in resp_map:
        rec = resp_map[BLOCK_SOURCE_IP]
        iso_resp = resp_map.get(ISOLATE_HOST)
        comparison_note = ""
        if iso_resp:
            comparison_note = (
                f" Compared to ISOLATE_HOST (operational impact: {iso_resp['operational_impact_score']}), "
                f"BLOCK_SOURCE_IP achieves high risk reduction ({rec['risk_reduction_score']}) with "
                f"negligible disruption ({rec['operational_impact_score']})."
            )

        recommendation_reason = (
            f"BLOCK_SOURCE_IP is the recommended primary response for campaign '{camp_id}'. "
            f"Adversary activity is perimeter-driven without confirmed on-host execution.{comparison_note}"
        )

    # 3. If NOTIFY_ADMIN was evaluated:
    elif NOTIFY_ADMIN in resp_map:
        rec = resp_map[NOTIFY_ADMIN]
        recommendation_reason = (
            f"NOTIFY_ADMIN is recommended for campaign '{camp_id}'. Escalates threat telemetry to SOC analysts "
            f"with zero disruption to operational services."
        )

    # 4. Fallback: Select the evaluated option with highest net score: risk_reduction - (operational_impact // 3)
    else:
        rec = max(
            evaluated_responses,
            key=lambda r: r["risk_reduction_score"] - (r["operational_impact_score"] // 3)
        )
        recommendation_reason = (
            f"{rec['response_type']} is selected based on highest net benefit scoring "
            f"(risk reduction: {rec['risk_reduction_score']}, operational impact: {rec['operational_impact_score']})."
        )

    # Compile Comprehensive Comparison Summary
    summary_parts = []
    for r in evaluated_responses:
        summary_parts.append(
            f"{r['response_type']}: risk reduction={r['risk_reduction_score']}, "
            f"impact={r['operational_impact_score']}, residual={r['residual_risk_score']}"
        )

    comparison_reason = (
        f"Comparative Response Evaluation for campaign '{camp_id}' across {len(evaluated_responses)} option(s): "
        f"[{'; '.join(summary_parts)}]. "
        f"Recommendation prioritizes {rec['response_type']} due to "
        f"{'confirmed host breach' if has_host_comp else 'perimeter-driven threat activity'}."
    )

    return (
        {
            "response_id": rec["response_id"],
            "response_type": rec["response_type"],
            "reason": recommendation_reason,
        },
        comparison_reason
    )


# ------------------------------------------------------------------------------
# HIGH-LEVEL API & INTERFACE
# ------------------------------------------------------------------------------

def evaluate_responses(
    graph: Dict[str, Any],
    response_options: Optional[Sequence[str]] = None
) -> Dict[str, Any]:
    """
    Evaluate hypothetical response options against a Phase 1D Evidence Graph.

    Parameters:
      graph: Validated Evidence Graph dictionary from build_evidence_graph.
      response_options: Optional sequence of hypothetical response types to evaluate.
                        Defaults to all standard options (BLOCK_SOURCE_IP, ISOLATE_HOST,
                        NOTIFY_ADMIN, NO_ACTION).

    Returns:
      Deterministic evaluation report dictionary containing:
        - campaign_id: Identifier of the analyzed campaign.
        - responses: List of evaluated response option dictionaries.
        - recommendation: Recommended response option with rationale.
        - comparison_reason: Comparative analysis narrative across all options.
    """
    valid_graph = validate_evidence_graph_input(graph)
    valid_options = validate_response_options(response_options)
    indicators = extract_graph_indicators(valid_graph)

    evaluated_responses: List[Dict[str, Any]] = []
    for opt in valid_options:
        resp_result = evaluate_single_response(opt, indicators)
        evaluated_responses.append(resp_result)

    recommendation, comparison_reason = compare_and_recommend(evaluated_responses, indicators)

    return {
        "campaign_id": indicators["campaign_id"],
        "responses": evaluated_responses,
        "recommendation": recommendation,
        "comparison_reason": comparison_reason,
    }


class ResponseLab:
    """
    Object-oriented wrapper for the Internal Response Lab.
    Provides state-free, reproducible, deterministic evaluation.
    """

    def __init__(self, default_response_options: Optional[Sequence[str]] = None) -> None:
        self.default_response_options = validate_response_options(default_response_options)

    def evaluate(
        self,
        graph: Dict[str, Any],
        response_options: Optional[Sequence[str]] = None
    ) -> Dict[str, Any]:
        """Evaluate hypothetical response options against an Evidence Graph."""
        opts = response_options if response_options is not None else self.default_response_options
        return evaluate_responses(graph=graph, response_options=opts)


# ------------------------------------------------------------------------------
# CONVENIENCE PIPELINE HELPERS
# ------------------------------------------------------------------------------

def evaluate_responses_from_story(
    story: Dict[str, Any],
    response_options: Optional[Sequence[str]] = None
) -> Dict[str, Any]:
    """
    Convenience helper executing:
    Phase 1C Attack Story -> Phase 1D Evidence Graph -> Phase 1E Response Lab.
    """
    if build_evidence_graph is None:
        raise ResponseLabError("Phase 1D build_evidence_graph is not available.")
    graph = build_evidence_graph(story)
    return evaluate_responses(graph, response_options=response_options)


def evaluate_responses_from_campaign(
    campaign: Dict[str, Any],
    response_options: Optional[Sequence[str]] = None
) -> Dict[str, Any]:
    """
    Convenience helper executing:
    Phase 1B Correlated Campaign -> Phase 1C Attack Story -> Phase 1D Evidence Graph -> Phase 1E Response Lab.
    """
    if build_evidence_graph_from_campaign is None:
        raise ResponseLabError("Phase 1D build_evidence_graph_from_campaign is not available.")
    graph = build_evidence_graph_from_campaign(campaign)
    return evaluate_responses(graph, response_options=response_options)


def evaluate_responses_from_events(
    events: Sequence[Dict[str, Any]],
    time_window_minutes: float = 30.0,
    campaign_id_prefix: Optional[str] = None,
    response_options: Optional[Sequence[str]] = None
) -> Optional[Dict[str, Any]]:
    """
    Convenience helper executing the complete Phase 1 pipeline:
    1A Events -> 1B Campaign -> 1C Attack Story -> 1D Evidence Graph -> 1E Response Lab.
    """
    if build_evidence_graph_from_events is None:
        raise ResponseLabError("Phase 1D build_evidence_graph_from_events is not available.")
    graph = build_evidence_graph_from_events(
        events=events,
        time_window_minutes=time_window_minutes,
        campaign_id_prefix=campaign_id_prefix
    )
    if not graph:
        return None
    return evaluate_responses(graph, response_options=response_options)
