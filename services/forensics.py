import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from services.ai_copilot import build_incident_timeline


def extract_chain_of_custody(events: List[Dict]) -> Dict[str, Any]:
    """
    Extract forensic chain of custody metrics from raw security events.
    Computes earliest/latest observation window, affected accounts,
    targeted ports, and telemetry packet counts.
    """
    if not events:
        return {
            "total_events": 0,
            "earliest_timestamp": None,
            "latest_timestamp": None,
            "source_ips": [],
            "usernames": [],
            "targeted_ports": [],
            "event_types": []
        }

    valid_events = [ev for ev in events if isinstance(ev, dict)]
    timestamps = [ev.get("timestamp") for ev in valid_events if ev.get("timestamp")]
    sorted_ts = sorted(timestamps)

    source_ips = sorted(list({ev.get("source_ip") for ev in valid_events if ev.get("source_ip")}))
    usernames = sorted(list({ev.get("username") for ev in valid_events if ev.get("username")}))
    ports = sorted(list({ev.get("port") for ev in valid_events if ev.get("port") is not None}))
    event_types = sorted(list({ev.get("event_type") for ev in valid_events if ev.get("event_type")}))

    return {
        "total_events": len(valid_events),
        "earliest_timestamp": sorted_ts[0] if sorted_ts else None,
        "latest_timestamp": sorted_ts[-1] if sorted_ts else None,
        "source_ips": source_ips,
        "usernames": usernames,
        "targeted_ports": ports,
        "event_types": event_types
    }


def generate_forensic_dossier_json(
    incident: Dict[str, Any],
    events: List[Dict[str, Any]],
    containment_actions: Optional[List[Dict[str, Any]]] = None,
    status_history: Optional[List[Dict[str, Any]]] = None,
    ai_report: Optional[Dict[str, Any]] = None,
    verification_status: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Generate an immutable, comprehensive JSON forensic dossier bundle
    for compliance archiving, SIEM ingestion, or court/audit submission.
    """
    incident = incident or {}
    events = events or []
    containment_actions = containment_actions or []
    status_history = status_history or []

    chain_of_custody = extract_chain_of_custody(events)
    attack_timeline = build_incident_timeline(events)

    dossier = {
        "export_metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "generator": "SPLASH FORGE Autonomous SOC Platform v2.0",
            "spec_version": "1.0-forensic-dossier",
            "analyst_role": "SPLASH FORGE Autonomous SOC Operations"
        },
        "incident_profile": {
            "incident_id": incident.get("incident_id", "UNKNOWN"),
            "title": incident.get("title", "Untitled Security Incident"),
            "severity": incident.get("severity", "UNKNOWN"),
            "status": incident.get("status", "NEW"),
            "detection_type": incident.get("detection_type", "UNKNOWN"),
            "mitre_technique": incident.get("mitre_technique", "UNKNOWN"),
            "source_ip": incident.get("source_ip", "UNKNOWN"),
            "risk_score": incident.get("risk_score"),
            "created_at": incident.get("created_at"),
            "updated_at": incident.get("updated_at")
        },
        "chain_of_custody": chain_of_custody,
        "chronological_attack_timeline": attack_timeline,
        "containment_records": containment_actions,
        "closed_loop_verification": verification_status or {
            "is_verified": False,
            "status_message": "Verification not performed or host not quarantined."
        },
        "workflow_audit_history": status_history,
        "ai_threat_intelligence": ai_report or {},
        "raw_correlated_evidence": events
    }

    return json.dumps(dossier, indent=2, default=str)


def generate_forensic_dossier_markdown(
    incident: Dict[str, Any],
    events: List[Dict[str, Any]],
    containment_actions: Optional[List[Dict[str, Any]]] = None,
    status_history: Optional[List[Dict[str, Any]]] = None,
    ai_report: Optional[Dict[str, Any]] = None,
    verification_status: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Generate an analyst-formatted Executive Briefing & Forensic Markdown report
    ready for executive distribution, CSIRT handoff, or compliance documentation.
    """
    incident = incident or {}
    events = events or []
    containment_actions = containment_actions or []
    status_history = status_history or []

    chain = extract_chain_of_custody(events)
    timeline = build_incident_timeline(events)

    inc_id = incident.get("incident_id", "UNKNOWN")
    title = incident.get("title", "Security Incident")
    sev = incident.get("severity", "HIGH")
    status = incident.get("status", "NEW")
    mitre = incident.get("mitre_technique", "T1110")
    engine = incident.get("detection_type", "HEURISTIC")
    src_ip = incident.get("source_ip", "UNKNOWN")
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = []
    lines.append(f"# 🛡️ SPLASH FORGE SOC Forensic Dossier: {inc_id}")
    lines.append(f"<!-- # 🛡️ SentinelX SOC Forensic Dossier: {inc_id} -->")
    lines.append("")
    lines.append(f"**Document Generated:** `{now_utc}` | **Classification:** TLP:AMBER | **Platform:** SPLASH FORGE Autonomous SOC v2.0")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 1. Incident Overview & Threat Profile")
    lines.append("")
    lines.append("| Attribute | Value |")
    lines.append("| :--- | :--- |")
    lines.append(f"| **Incident ID** | `{inc_id}` |")
    lines.append(f"| **Title** | **{title}** |")
    lines.append(f"| **Severity** | `{sev}` |")
    lines.append(f"| **Workflow Status** | `{status}` |")
    lines.append(f"| **Primary Adversary IP** | `{src_ip}` |")
    lines.append(f"| **MITRE ATT&CK ID** | `{mitre}` |")
    lines.append(f"| **Detection Engine** | `{engine}` |")
    lines.append(f"| **Calculated Risk Score** | `{incident.get('risk_score', 'N/A')}` |")
    lines.append(f"| **First Detected** | `{incident.get('created_at', 'N/A')}` |")
    lines.append("")

    # Forensic Chain of Custody
    lines.append("## 2. Forensic Chain of Custody")
    lines.append("")
    lines.append(f"- **Correlated Evidence Packets:** {chain['total_events']} events")
    lines.append(f"- **Telemetry Observation Window:** `{chain['earliest_timestamp'] or 'N/A'}` ➔ `{chain['latest_timestamp'] or 'N/A'}`")
    lines.append(f"- **Involved Source IP(s):** {', '.join(f'`{ip}`' for ip in chain['source_ips']) if chain['source_ips'] else 'None'}")
    lines.append(f"- **Targeted Accounts / Identities:** {', '.join(f'`{u}`' for u in chain['usernames']) if chain['usernames'] else 'None'}")
    lines.append(f"- **Targeted Destination Ports:** {', '.join(f'`{p}`' for p in chain['targeted_ports']) if chain['targeted_ports'] else 'None'}")
    lines.append(f"- **Observed Event Actions:** {', '.join(f'`{et}`' for et in chain['event_types']) if chain['event_types'] else 'None'}")
    lines.append("")

    # Chronological Attack Timeline
    lines.append("## 3. Chronological Attack Timeline")
    lines.append("")
    if timeline:
        lines.append("| Step | Offset | Milestone / Stage | Timestamp | Identity | Action | Status | Observation Details |")
        lines.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
        for node in timeline:
            lines.append(
                f"| #{node.get('step')} | {node.get('delta_str')} | **{node.get('stage')}** | "
                f"`{node.get('timestamp')}` | `{node.get('username')}` | {node.get('action')} | "
                f"`{node.get('status')}` | {node.get('message', '').replace('|', '-')} |"
            )
    else:
        lines.append("_No chronological sequence milestones recorded._")
    lines.append("")

    # Closed-Loop Verification & Containment
    lines.append("## 4. Response Actions & Closed-Loop Verification")
    lines.append("")
    if verification_status:
        v_status = "✅ THREAT NEUTRALIZED (VERIFIED)" if verification_status.get("is_verified") else "⚠️ UNVERIFIED / LEAK DETECTED"
        lines.append(f"**Verification State:** {v_status}")
        lines.append(f"- **Verification Assessment:** {verification_status.get('status_message', 'N/A')}")
        lines.append(f"- **Subsequent Telemetry Observed Post-Isolation:** `{verification_status.get('subsequent_events_count', 0)}` packets")
        if verification_status.get("blocked_at"):
            lines.append(f"- **Isolation Timestamp:** `{verification_status.get('blocked_at')}`")
    else:
        lines.append("_No automated containment verification record present._")
    lines.append("")

    if containment_actions:
        lines.append("### Containment Execution Audit Log")
        lines.append("")
        lines.append("| Timestamp | Action | Target Source IP | Execution Status | Operational Reason |")
        lines.append("| :--- | :--- | :--- | :--- | :--- |")
        for act in containment_actions:
            lines.append(
                f"| `{act.get('timestamp')}` | `{act.get('action')}` | `{act.get('source_ip')}` | "
                f"`{act.get('status')}` | {act.get('reason', '')} |"
            )
        lines.append("")

    # AI SOC Copilot Intelligence (if present)
    if ai_report:
        lines.append("## 5. SPLASH FORGE AI Copilot Intelligence Assessment")
        lines.append("")
        lines.append(f"**Intelligence Engine:** `{ai_report.get('ai_source', 'SPLASH FORGE AI Copilot')}`")
        lines.append("")
        if ai_report.get("incident_summary"):
            lines.append("### Executive Summary")
            lines.append(ai_report["incident_summary"])
            lines.append("")
        if ai_report.get("what_happened"):
            lines.append("### Forensic Analysis: What Happened")
            lines.append(ai_report["what_happened"])
            lines.append("")
        if ai_report.get("why_suspicious"):
            lines.append("### Threat Dynamics: Why Suspicious")
            lines.append(ai_report["why_suspicious"])
            lines.append("")
        if ai_report.get("mitre_explanation"):
            lines.append("### MITRE ATT&CK Operational Context")
            lines.append(ai_report["mitre_explanation"])
            lines.append("")
        if ai_report.get("investigation_steps"):
            lines.append("### Recommended SOC Investigation Playbook")
            steps = ai_report["investigation_steps"]
            if isinstance(steps, list):
                for i, s in enumerate(steps, 1):
                    lines.append(f"{i}. {s}")
            else:
                lines.append(str(steps))
            lines.append("")
        if ai_report.get("recommended_response"):
            lines.append("### Prescriptive Response & Containment Directives")
            recs = ai_report["recommended_response"]
            if isinstance(recs, list):
                for i, r in enumerate(recs, 1):
                    lines.append(f"{i}. {r}")
            else:
                lines.append(str(recs))
            lines.append("")

    # Audit Trail
    lines.append("## 6. Workflow Status Audit Trail")
    lines.append("")
    if status_history:
        lines.append("| Changed At | Previous Status | Transitioned To |")
        lines.append("| :--- | :--- | :--- |")
        for sh in status_history:
            lines.append(f"| `{sh.get('changed_at')}` | `{sh.get('old_status')}` | `{sh.get('new_status')}` |")
    else:
        lines.append("_No status changes recorded._")
    lines.append("")
    lines.append("---")
    lines.append("*End of SPLASH FORGE Incident Forensic Dossier. Confidential — Authorized SOC Personnel Only.*")
    lines.append("")

    return "\n".join(lines)
