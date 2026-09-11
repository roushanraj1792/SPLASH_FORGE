import streamlit as st

from database.database import (
    initialize_database,
    get_recent_events,
    get_incidents,
    update_incident_status,
    create_incident,
    link_event_to_incident,
    unlink_event_from_incident,
    get_incident_events,
    get_incident_status_history
)

from services.ai_copilot import analyze_incident

from detection.brute_force import detect_brute_force
from detection.port_scan import detect_port_scan
from detection.suspicious_auth import (
    detect_suspicious_authentication
)
from detection.privilege_escalation import detect_privilege_escalation
from detection.suspicious_powershell import (
    detect_suspicious_powershell
)

from services.risk_engine import enrich_alert_with_risk
from services.security_posture import calculate_security_posture

from services.telegram_alert import send_incident_alert

from services.containment import (
    initialize_containment_tables,
    block_source_ip,
    get_containment_actions
)


# ==================================================
# PAGE CONFIGURATION
# ==================================================

st.set_page_config(
    page_title="SentinelX SOC",
    page_icon="S",
    layout="wide",
    initial_sidebar_state="collapsed"
)



# ==================================================
# SENTINELX FRONTEND — PROFESSIONAL SOC UI
# Frontend only. Backend logic unchanged.
# ==================================================

st.markdown(
    """
    <style>
    :root {
        --sx-bg: #0B1420;
        --sx-panel: #111F2D;
        --sx-panel-2: #16283A;
        --sx-border: #263B4D;
        --sx-text: #E7EEF2;
        --sx-muted: #91A4B0;
        --sx-cyan: #4DD4E8;
        --sx-blue: #4EA1FF;
        --sx-green: #4FD39A;
        --sx-amber: #F0B95A;
        --sx-red: #F06A7A;
    }

    [data-testid="stAppViewContainer"] {
        background:
            radial-gradient(circle at 85% 5%, rgba(24,213,245,.07), transparent 28%),
            radial-gradient(circle at 5% 45%, rgba(79,156,255,.045), transparent 30%),
            linear-gradient(180deg, #0B1420 0%, #09121D 55%, #080F18 100%) !important;
    }

    [data-testid="stHeader"] {
        background: rgba(4,10,18,.72) !important;
    }

    section[data-testid="stSidebar"],
    [data-testid="collapsedControl"] {
        display: none !important;
    }

    .main .block-container {
        max-width: 1540px !important;
        width: 100% !important;
        margin: 0 auto !important;
        padding: 14px 24px 34px !important;
    }

    .main .block-container,
    .main .block-container p,
    .main .block-container span,
    .main .block-container label {
        color: var(--sx-text);
    }

    .sx-top-nav-header,
    .sx-command-header,
    .sx-command-identity,
    .sx-panel,
    .sx-kpi-card {
        background: linear-gradient(145deg, rgba(14,34,51,.98), rgba(7,20,33,.98)) !important;
        border: 1px solid var(--sx-border) !important;
        box-shadow:0 6px 18px rgba(0,0,0,.16), inset 0 1px 0 rgba(255,255,255,.018);
    }

    .sx-top-nav-header {
        display:flex;
        align-items:center;
        justify-content:space-between;
        gap:20px;
        padding:15px 18px;
        margin:0 0 10px;
        border-radius:10px;
    }

    .sx-top-nav-kicker,
    .sx-command-kicker,
    .sx-identity-kicker {
        color:var(--sx-cyan) !important;
        font-size:.68rem;
        font-weight:800;
        letter-spacing:1.5px;
        text-transform:uppercase;
    }

    .sx-top-nav-title {
        color:#f1f8fb;
        font-size:1.08rem;
        font-weight:800;
        letter-spacing:.5px;
        margin-top:2px;
    }

    .sx-top-nav-live {
        display:flex;
        align-items:center;
        gap:8px;
        color:var(--sx-green) !important;
        font-size:.70rem;
        font-weight:800;
        letter-spacing:1px;
        white-space:nowrap;
    }

    .sx-top-live-dot,
    .sx-status-dot,
    .sx-identity-online span {
        width:7px;
        height:7px;
        display:inline-block;
        border-radius:50%;
        background:var(--sx-green);
        box-shadow:0 0 10px rgba(57,223,145,.7);
    }

    div[data-testid="stHorizontalBlock"] button {
        min-height:42px !important;
        border-radius:8px !important;
        border:1px solid rgba(79,156,255,.22) !important;
        background:linear-gradient(145deg,#10283d,#111F2D) !important;
        color:#a9c1cc !important;
        font-weight:750 !important;
        font-size:.76rem !important;
        letter-spacing:.1px;
        transition:background .16s ease,border-color .16s ease,color .16s ease,box-shadow .16s ease;
    }

    div[data-testid="stHorizontalBlock"] button:hover {
        color:#ecfbff !important;
        border-color:rgba(24,213,245,.58) !important;
        background:linear-gradient(145deg,#16283A,#16283A) !important;
        box-shadow:0 0 18px rgba(24,213,245,.08);
    }

    .sx-command-header {
        position:relative;
        display:flex;
        justify-content:space-between;
        align-items:center;
        gap:24px;
        padding:19px 23px;
        margin:0 0 10px;
        border-radius:10px;
        overflow:hidden;
    }

    .sx-command-header:before,
    .sx-command-identity:before {
        content:"";
        position:absolute;
        left:0;
        top:0;
        bottom:0;
        width:3px;
        background:var(--sx-cyan);
        box-shadow:0 0 18px rgba(24,213,245,.5);
    }

    .sx-command-title {
        color:#edf8fb;
        font-size:1.8rem;
        line-height:1.05;
        font-weight:800;
        letter-spacing:-.4px;
        margin-top:4px;
    }

    .sx-command-subtitle {
        color:var(--sx-muted);
        font-size:.78rem;
        margin-top:6px;
    }

    .sx-command-right {
        display:flex;
        align-items:center;
        gap:20px;
    }

    .sx-command-status,
    .sx-command-context {
        display:flex;
        align-items:center;
        gap:8px;
    }

    .sx-command-status-label,
    .sx-command-context span {
        display:block;
        color:#8198A6;
        font-size:.6rem;
        letter-spacing:1px;
        font-weight:800;
    }

    .sx-command-status strong,
    .sx-command-context strong {
        color:#dff8ef;
        font-size:.70rem;
        letter-spacing:.7px;
    }

    .sx-command-divider,
    .sx-identity-divider {
        width:1px;
        height:34px;
        background:rgba(91,143,167,.22);
    }

    .sx-command-identity {
        position:relative;
        display:grid;
        grid-template-columns:1.35fr .7fr 1.9fr 1fr;
        align-items:center;
        gap:20px;
        padding:14px 19px;
        margin-bottom:14px;
        border-radius:10px;
    }

    .sx-identity-brand {
        display:flex;
        align-items:center;
        gap:11px;
    }

    .sx-identity-shield {
        width:32px;
        height:32px;
        display:grid;
        place-items:center;
        border-radius:8px;
        background:#111F2D;
        border:1px solid rgba(24,213,245,.22);
        font-size:16px;
    }

    .sx-identity-name {
        color:#eef9fc;
        font-weight:800;
        font-size:1rem;
        letter-spacing:.6px;
    }

    .sx-identity-name span {
        color:var(--sx-cyan);
    }

    .sx-identity-subtitle {
        color:#91A4B0;
        font-size:.56rem;
        letter-spacing:1.2px;
        margin-top:2px;
    }

    .sx-identity-online {
        color:var(--sx-green) !important;
        font-size:.68rem;
        font-weight:800;
        display:flex;
        align-items:center;
        gap:7px;
        margin-top:3px;
    }

    .sx-status-items {
        display:flex;
        flex-wrap:wrap;
        gap:8px 16px;
        margin-top:4px;
    }

    .sx-status-items > div {
        display:flex;
        align-items:center;
        gap:5px;
        color:#b6cbd4;
        font-size:.60rem;
        white-space:nowrap;
    }

    .sx-status-items b {
        color:#b9cbd3;
        font-weight:700;
    }

    .sx-status-items em {
        color:var(--sx-green);
        font-style:normal;
        font-weight:800;
        font-size:.60rem;
    }

    .sx-ai-line {
        display:flex;
        gap:6px;
        align-items:center;
        margin-top:4px;
        color:#c8dce4;
        font-size:.65rem;
    }

    .sx-ai-line span {
        color:#567482 !important;
    }

    .sx-panel {
        border-radius:10px;
        padding:18px 20px;
        margin-bottom:14px;
    }

    .sx-panel-kicker {
        color:var(--sx-cyan);
        font-size:.60rem;
        font-weight:800;
        letter-spacing:1.4px;
        text-transform:uppercase;
    }

    .sx-panel-title {
        color:#edf8fb;
        font-size:1.32rem;
        font-weight:800;
        letter-spacing:-.3px;
        margin-top:3px;
    }

    .sx-panel-subtitle,
    .sx-muted {
        color:var(--sx-muted) !important;
        font-size:.76rem;
    }

    .sx-hero-row {
        display:flex;
        justify-content:space-between;
        align-items:flex-end;
        gap:20px;
    }

    .sx-hero-state {
        text-align:right;
        color:#93aeb9;
        font-size:.68rem;
    }

    .sx-hero-state strong {
        color:#e7f6fb;
        display:block;
        font-size:.72rem;
        margin-top:3px;
    }

    .sx-kpi-card {
        position:relative;
        min-height:112px;
        border-radius:10px;
        padding:15px 16px 13px;
        overflow:hidden;
    }

    .sx-kpi-card:before {
        content:"";
        position:absolute;
        left:0;
        top:0;
        bottom:0;
        width:3px;
        background:var(--sx-cyan);
        box-shadow:0 0 12px rgba(24,213,245,.4);
    }

    .sx-kpi-high:before { background:var(--sx-amber); }
    .sx-kpi-critical:before { background:var(--sx-red); }
    .sx-kpi-incidents:before { background:var(--sx-blue); }
    .sx-kpi-contained:before { background:var(--sx-green); }

    .sx-kpi-label {
        color:#91A4B0;
        font-size:.60rem;
        font-weight:800;
        letter-spacing:1.15px;
        text-transform:uppercase;
    }

    .sx-kpi-value {
        color:#f2f8fb !important;
        font-size:1.92rem;
        line-height:1;
        font-weight:800;
        margin-top:10px;
        letter-spacing:-.6px;
    }

    .sx-kpi-meta {
        color:#7F95A2 !important;
        font-size:.59rem;
        margin-top:8px;
    }

    .sx-section-title {
        color:#e9f6fa;
        font-size:.90rem;
        font-weight:800;
        letter-spacing:.3px;
        margin:5px 0 8px;
    }

    .sx-posture-score {
        color:#f0f8fb;
        font-size:2.15rem;
        font-weight:800;
    }

    .sx-posture-label {
        color:var(--sx-green);
        font-size:.70rem;
        font-weight:800;
        letter-spacing:.8px;
    }

    .sx-status-card {
        background:#111F2D;
        border:1px solid #263B4D;
        border-radius:9px;
        padding:13px 14px;
    }

    .sx-status-card-title {
        color:#a8bec8;
        font-size:.67rem;
        font-weight:800;
    }

    .sx-status-card-value {
        color:var(--sx-green);
        font-size:.72rem;
        font-weight:800;
        margin-top:6px;
    }

    .stMetric {
        background:linear-gradient(145deg,#10283b,#16283A) !important;
        border:1px solid rgba(83,132,156,.24) !important;
        border-radius:8px !important;
        padding:11px !important;
    }

    [data-testid="stDataFrame"] {
        border:1px solid rgba(83,132,156,.24) !important;
        border-radius:8px !important;
        overflow:hidden;
    }

    .stCaption {
        color:#819aa6 !important;
    }

    ::-webkit-scrollbar { width:7px; height:7px; }
    ::-webkit-scrollbar-track { background:#080F18; }
    ::-webkit-scrollbar-thumb { background:#263B4D; border-radius:10px; }
    ::-webkit-scrollbar-thumb:hover { background:#3A5870; }

    @media (max-width: 1100px) {
        .sx-command-identity { grid-template-columns:1fr 1fr; gap:14px; }
        .sx-command-right { display:none; } .sx-top-nav-header { flex-wrap:wrap; } }

@media (max-width: 700px) { .main .block-container { padding:10px 12px 24px !important; } .sx-command-identity { grid-template-columns:1fr; } .sx-top-nav-header { padding:12px 14px; } .sx-kpi-card { min-height:100px; } }
    }
    </style>
    """,
    unsafe_allow_html=True
)


# ==================================================
# ALERT TYPE NORMALIZATION
# ==================================================

ALERT_TYPE_NORMALIZATION = {
    "BRUTE FORCE": "BRUTE_FORCE",
    "BRUTE FORCE ATTACK": "BRUTE_FORCE",
    "BRUTE FORCE ATTACK DETECTED": "BRUTE_FORCE",

    "PORT SCAN": "PORT_SCAN",
    "PORT SCAN DETECTED": "PORT_SCAN",

    "SUSPICIOUS POWERSHELL": "SUSPICIOUS_POWERSHELL",
    "SUSPICIOUS POWERSHELL DETECTED": "SUSPICIOUS_POWERSHELL",

    "PRIVILEGE ESCALATION": "PRIVILEGE_ESCALATION",
    "PRIVILEGE ESCALATION DETECTED": "PRIVILEGE_ESCALATION",

    "SUSPICIOUS AUTH": "SUSPICIOUS_AUTH",
    "SUSPICIOUS AUTHENTICATION": "SUSPICIOUS_AUTH",
    "SUSPICIOUS AUTHENTICATION DETECTED": "SUSPICIOUS_AUTH",
}


def normalize_alert_type(alert_type):
    if not alert_type:
        return ""

    normalized = str(
        alert_type
    ).strip().upper()

    return ALERT_TYPE_NORMALIZATION.get(
        normalized,
        normalized
    )


# ==================================================
# DATABASE INITIALIZATION
# ==================================================

initialize_database()
initialize_containment_tables()


# ==================================================
# FRONT-PAGE NAVIGATION — SIDEBAR CONTENT MOVED HERE
# ==================================================

if "selected_page" not in st.session_state:
    st.session_state.selected_page = "Dashboard"

selected_page = st.session_state.selected_page

st.markdown(
    """
    <div class="sx-top-nav-header">
        <div>
            <div class="sx-top-nav-kicker">SENTINELX / SECURITY OPERATIONS CENTER</div>
            <div class="sx-top-nav-title">SECURITY OPERATIONS COMMAND CENTER</div>
        </div>
        <div class="sx-top-nav-live">
            <span class="sx-top-live-dot"></span>
            SOC SYSTEM OPERATIONAL
        </div>
    </div>
    """,
    unsafe_allow_html=True
)

nav_items = [
    ("⌂  Dashboard", "Dashboard", "nav_dashboard"),
    ("◉  Live Events", "Live Events", "nav_live_events"),
    ("!  Security Alerts", "Security Alerts", "nav_security_alerts"),
    ("◆  Incidents", "Incidents", "nav_incidents"),
    ("✣  MITRE ATT&CK", "MITRE ATT&CK", "nav_mitre"),
    ("≡  Audit Logs", "Audit Logs", "nav_audit")
]

nav_cols = st.columns(6)

for col, (label, page, key) in zip(nav_cols, nav_items):
    with col:
        if st.button(label, use_container_width=True, key=key):
            st.session_state.selected_page = page
            st.rerun()


# ==================================================
# GET SECURITY EVENTS
# ==================================================
# GET SECURITY EVENTS
# ==================================================

events = get_recent_events(
    100
)


# ==================================================
# DETECTION ENGINE
# ==================================================

brute_force_alerts = detect_brute_force(
    events
)

port_scan_alerts = detect_port_scan(
    events
)

suspicious_auth_alerts = (
    detect_suspicious_authentication(
        events
    )
)

privilege_escalation_alerts = (
    detect_privilege_escalation(
        events
    )
)

suspicious_powershell_alerts = (
    detect_suspicious_powershell(
        events
    )
)


# ==================================================
# COMBINE ALL ALERTS
# ==================================================

all_alerts = (
    brute_force_alerts
    + port_scan_alerts
    + suspicious_auth_alerts
    + privilege_escalation_alerts
    + suspicious_powershell_alerts
)


# ==================================================
# NORMALIZE DETECTION ALERT TYPES
# ==================================================

for alert in all_alerts:

    alert["alert_type"] = normalize_alert_type(
        alert.get("alert_type")
    )


# ==================================================
# RISK ENGINE
# ==================================================

risk_alerts = []

for alert in all_alerts:

    enriched_alert = enrich_alert_with_risk(
        alert
    )

    enriched_alert["alert_type"] = (
        normalize_alert_type(
            enriched_alert.get(
                "alert_type"
            )
        )
    )

    risk_alerts.append(
        enriched_alert
    )


# ==================================================
# INCIDENT CREATION
# EXACT EVIDENCE LINKING
# TELEGRAM ALERT
# SAFE CONTAINMENT
# ==================================================

for alert in risk_alerts:

    alert_type = normalize_alert_type(
        alert.get("alert_type")
    )

    source_ip = alert.get(
        "source_ip"
    )

    if not alert_type or not source_ip:
        continue


    # ----------------------------------------------
    # KEEP CANONICAL ALERT TYPE
    # ----------------------------------------------

    alert["alert_type"] = alert_type


    # ----------------------------------------------
    # FIND EXISTING INCIDENT
    # ----------------------------------------------

    existing_incident = None

    current_incidents = get_incidents(
        100
    )

    for incident in current_incidents:

        incident_alert_type = (
            normalize_alert_type(
                incident["alert_type"]
            )
        )

        if (
            incident_alert_type == alert_type
            and incident["source_ip"] == source_ip
        ):

            existing_incident = incident
            break


    # ----------------------------------------------
    # CREATE OR REUSE INCIDENT
    # ----------------------------------------------

    is_new_incident = False

    if existing_incident:

        incident_id = existing_incident[
            "incident_id"
        ]

    else:

        incident_id = create_incident(
            alert
        )

        if not incident_id:
            continue

        is_new_incident = True


    # ----------------------------------------------
    # GET EXACT DETECTOR EVIDENCE
    # ----------------------------------------------

    evidence = alert.get(
        "evidence",
        {}
    )

    detector_event_ids = evidence.get(
        "event_ids",
        []
    )

    detector_event_ids = [
        event_id
        for event_id in detector_event_ids
        if event_id is not None
    ]


    # ----------------------------------------------
    # GET CURRENT INCIDENT EVENTS
    # ----------------------------------------------

    linked_events = get_incident_events(
        incident_id
    )

    linked_event_ids = {
        event["id"]
        for event in linked_events
    }


    # ----------------------------------------------
    # EXACT EVIDENCE LINKING
    # ----------------------------------------------

    if detector_event_ids:

        # Remove incorrect evidence links.

        for linked_event in linked_events:

            linked_event_id = linked_event[
                "id"
            ]

            if linked_event_id not in detector_event_ids:

                unlink_event_from_incident(
                    incident_id,
                    linked_event_id
                )


        # Add exact detector evidence.

        for event_id in detector_event_ids:

            if event_id not in linked_event_ids:

                link_event_to_incident(
                    incident_id,
                    event_id
                )

    # IMPORTANT:
    # There is intentionally NO fallback here.
    #
    # We do NOT link every event from the source IP.
    #
    # This prevents incorrect evidence such as:
    # 15 events for SUSPICIOUS_AUTH
    # 30 events for PORT_SCAN

       # ----------------------------------------------
    # NEW INCIDENT ACTIONS
    # ----------------------------------------------

    if is_new_incident:

        # ------------------------------------------
        # TELEGRAM ALERT
        # ------------------------------------------

        telegram_incident = {

            "incident_id": incident_id,

            "alert_type": alert.get(
                "alert_type"
            ),

            "title": alert.get(
                "title",
                "Security Incident"
            ),

            "source_ip": alert.get(
                "source_ip",
                ""
            ),

            "severity": alert.get(
                "severity",
                "LOW"
            ),

            "risk_score": alert.get(
                "risk_score",
                0
            ),

            "mitre_technique": alert.get(
                "mitre_technique",
                "N/A"
            ),

            "description": alert.get(
                "description",
                alert.get(
                    "message",
                    ""
                )
            )
        }

        telegram_result = send_incident_alert(
            telegram_incident
        )

        print(
            "TELEGRAM ALERT RESULT:",
            telegram_result
        )

        # ------------------------------------------
        # AUTONOMOUS SAFE CONTAINMENT
        # ------------------------------------------

        severity = alert.get(
            "severity",
            "LOW"
        )

        risk_score = alert.get(
            "risk_score",
            0
        )

        if (
            severity in [
                "HIGH",
                "CRITICAL"
            ]
            or risk_score >= 80
        ):

            containment_reason = (
                f"Automated containment for "
                f"{alert.get('title', 'Security Incident')}"
            )

            containment_result = block_source_ip(
                incident_id,
                source_ip,
                containment_reason
            )

            if containment_result.get(
                "success"
            ):

                update_incident_status(
                    incident_id,
                    "CONTAINED"
                )
# ==================================================
# DASHBOARD DATA
# ==================================================

total_events = len(
    events
)

critical_alerts = sum(
    1
    for alert in risk_alerts
    if alert.get(
        "risk_level"
    ) == "CRITICAL"
)

high_alerts = sum(
    1
    for alert in risk_alerts
    if alert.get(
        "risk_level"
    ) == "HIGH"
)

incidents = get_incidents(
    100
)


# ==================================================
# INCIDENT COUNTS
# ==================================================

active_statuses = {
    "NEW",
    "TRIAGED",
    "INVESTIGATING"
}

active_incidents = sum(
    1
    for incident in incidents
    if incident["status"]
    in active_statuses
)

contained_incidents = sum(
    1
    for incident in incidents
    if incident["status"]
    == "CONTAINED"
)


# ==================================================
# SECURITY POSTURE
# ==================================================

posture = calculate_security_posture()

posture_score = posture[
    "score"
]

posture_label = posture[
    "label"
]


# ==================================================
# CONTAINMENT ACTIONS
# ==================================================

containment_actions = (
    get_containment_actions()
)


# ==================================================
# PAGE 1 — DASHBOARD — SENTINELX SOC COMMAND CENTER
# ==================================================

if selected_page == "Dashboard":

    # Identity + system-status content formerly shown in the sidebar.
    st.markdown(
        """
        <div class="sx-command-identity">
            <div class="sx-identity-brand">
                <div class="sx-identity-shield">🛡</div>
                <div>
                    <div class="sx-identity-name">SENTINEL<span>X</span></div>
                    <div class="sx-identity-subtitle">SECURITY OPERATIONS CENTER</div>
                </div>
            </div>
            <div>
                <div class="sx-identity-kicker">SOC SYSTEM</div>
                <div class="sx-identity-online">
                    <span></span> OPERATIONAL
                </div>
            </div>
            <div>
                <div class="sx-identity-kicker">SYSTEM STATUS</div>
                <div class="sx-status-items">
                    <div><span class="sx-status-dot"></span><b>Detection Engine</b><em>ONLINE</em></div>
                    <div><span class="sx-status-dot"></span><b>Risk Engine</b><em>ONLINE</em></div>
                    <div><span class="sx-status-dot"></span><b>Database</b><em>CONNECTED</em></div>
                </div>
            </div>
            <div>
                <div class="sx-identity-kicker">AI-ASSISTED SOC</div>
                <div class="sx-ai-line">
                    <strong>Detect</strong><span>•</span>
                    <strong>Analyze</strong><span>•</span>
                    <strong>Respond</strong>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Command-center hero.
    st.markdown(
        """
        <div class="sx-panel">
            <div class="sx-hero-row">
                <div>
                    <div class="sx-panel-kicker">SENTINELX • SECURITY OPERATIONS CENTER</div>
                    <div class="sx-panel-title">Autonomous Threat Command Center</div>
                    <div class="sx-panel-subtitle">
                        Detect → Prioritize → Investigate → Contain
                    </div>
                </div>
                <div class="sx-hero-state">
                    SOC ENGINE ACTIVE
                    <strong>AI-assisted security monitoring</strong>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Primary SOC KPIs.
    critical_high = critical_alerts + high_alerts
    threat_pressure = min(
        100,
        critical_high * 10 + active_incidents * 4
    )

    k1, k2, k3, k4, k5 = st.columns(5)

    kpi_data = [
        (k1, "Security Events", total_events, "LIVE TELEMETRY", "sx-kpi-card"),
        (k2, "High Alerts", high_alerts, "PRIORITY THREATS", "sx-kpi-card sx-kpi-high"),
        (k3, "Critical Alerts", critical_alerts, "IMMEDIATE ATTENTION", "sx-kpi-card sx-kpi-critical"),
        (k4, "Active Incidents", active_incidents, "UNDER INVESTIGATION", "sx-kpi-card sx-kpi-incidents"),
        (k5, "Contained", contained_incidents, "RESPONSE COMPLETE", "sx-kpi-card sx-kpi-contained"),
    ]

    for col, label, value, meta, card_class in kpi_data:
        with col:
            st.markdown(
                f"""
                <div class="{card_class}">
                    <div class="sx-kpi-label">{label}</div>
                    <div class="sx-kpi-value">{value}</div>
                    <div class="sx-kpi-meta">— {meta}</div>
                </div>
                """,
                unsafe_allow_html=True
            )

    st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)

    # Threat pressure + security posture.
    left, right = st.columns([1.05, 1.95])

    with left:
        st.markdown(
            f"""
            <div class="sx-panel">
                <div class="sx-panel-kicker">THREAT PRESSURE</div>
                <div class="sx-posture-score">{threat_pressure}<span style="font-size:.9rem;color:#7894a3">/100</span></div>
                <div class="sx-panel-subtitle">
                    Current pressure from high/critical alerts and active incidents.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with right:
        st.markdown(
            f"""
            <div class="sx-panel">
                <div class="sx-section-title">SECURITY POSTURE</div>
                <div style="display:flex;align-items:center;gap:12px;">
                    <div class="sx-posture-score">{posture_score}<span style="font-size:.9rem;color:#7894a3">/100</span></div>
                    <div class="sx-posture-label">{posture_label}</div>
                </div>
                <div class="sx-panel-subtitle" style="margin-top:8px;">
                    Active: {posture['details']['active_incidents']}
                    &nbsp;•&nbsp; High/Critical: {posture['details']['high_critical_incidents']}
                    &nbsp;•&nbsp; Contained: {posture['details']['contained_incidents']}
                    &nbsp;•&nbsp; Resolved: {posture['details']['resolved_incidents']}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    # Threat overview.
    st.markdown(
        """
        <div class="sx-section-title">THREAT OVERVIEW</div>
        """,
        unsafe_allow_html=True
    )

    summary_col1, summary_col2, summary_col3 = st.columns(3)

    high_critical_count = sum(
        1
        for alert in risk_alerts
        if alert.get("risk_level") in ["HIGH", "CRITICAL"]
    )

    detection_types = len(
        set(
            alert.get("alert_type", "UNKNOWN")
            for alert in risk_alerts
        )
    )

    with summary_col1:
        st.markdown(
            f"""
            <div class="sx-status-card">
                <div class="sx-status-card-title">TOTAL ALERTS</div>
                <div class="sx-status-card-value" style="color:#4DD4E8">{len(risk_alerts)}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with summary_col2:
        st.markdown(
            f"""
            <div class="sx-status-card">
                <div class="sx-status-card-title">HIGH / CRITICAL</div>
                <div class="sx-status-card-value" style="color:#F0B95A">{high_critical_count}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with summary_col3:
        st.markdown(
            f"""
            <div class="sx-status-card">
                <div class="sx-status-card-title">DETECTION TYPES</div>
                <div class="sx-status-card-value" style="color:#4EA1FF">{detection_types}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

    # Engine health — same backend state, upgraded presentation.
    st.markdown(
        """
        <div class="sx-section-title">SENTINELX ENGINE STATUS</div>
        """,
        unsafe_allow_html=True
    )

    e1, e2, e3 = st.columns(3)

    for col, title, state in [
        (e1, "Detection Engine", "ONLINE"),
        (e2, "Risk Engine", "ONLINE"),
        (e3, "SQLite Database", "CONNECTED"),
    ]:
        with col:
            st.markdown(
                f"""
                <div class="sx-status-card">
                    <div class="sx-status-card-title">
                        <span class="sx-status-dot"></span>&nbsp; {title}
                    </div>
                    <div class="sx-status-card-value">{state}</div>
                </div>
                """,
                unsafe_allow_html=True
            )


# ==================================================
# PAGE 2 — LIVE EVENTS
# ==================================================

elif selected_page == "Live Events":

    st.title(
        "📡 Live Security Events"
    )

    st.caption(
        "Real-time security telemetry collected by SentinelX."
    )

    st.divider()


    if events:

        event_data = []

        for event in events:

            event_data.append(
                {
                    "ID": event["id"],
                    "Timestamp": event["timestamp"],
                    "Source IP": event["source_ip"],
                    "Username": event["username"],
                    "Event Type": event["event_type"],
                    "Action": event["action"],
                    "Status": event["status"],
                    "Severity": event["severity"],
                    "Message": event["message"]
                }
            )


        st.dataframe(
            event_data,
            width="stretch",
            hide_index=True
        )

        st.caption(
            f"Showing latest {len(events)} security events."
        )

    else:

        st.info(
            "No security events received yet."
        )


# ==================================================
# PAGE 3 — SECURITY ALERTS
# ==================================================

elif selected_page == "Security Alerts":

    st.title(
        "🚨 Security Alerts"
    )

    st.caption(
        "Prioritized detections generated by the "
        "SentinelX detection and risk engines."
    )

    st.divider()


    # ----------------------------------------------
    # ALERT SUMMARY
    # ----------------------------------------------

    alert_summary_col1, alert_summary_col2, alert_summary_col3 = (
        st.columns(3)
    )

    with alert_summary_col1:

        st.metric(
            "Total Alerts",
            len(risk_alerts)
        )

    with alert_summary_col2:

        high_critical_count = sum(
            1
            for alert in risk_alerts
            if alert.get(
                "risk_level"
            ) in [
                "HIGH",
                "CRITICAL"
            ]
        )

        st.metric(
            "High / Critical",
            high_critical_count
        )

    with alert_summary_col3:

        detection_types = len(
            set(
                alert.get(
                    "alert_type",
                    "UNKNOWN"
                )
                for alert in risk_alerts
            )
        )

        st.metric(
            "Detection Types",
            detection_types
        )


    st.divider()


    # ----------------------------------------------
    # ALERT CARDS
    # ----------------------------------------------

    if risk_alerts:

        for alert in risk_alerts:

            risk_level = alert.get(
                "risk_level",
                "LOW"
            )

            risk_score = alert.get(
                "risk_score",
                0
            )

            alert_type = normalize_alert_type(
                alert.get(
                    "alert_type",
                    "UNKNOWN"
                )
            )

            title = alert.get(
                "title",
                "Security Alert"
            )

            source_ip = alert.get(
                "source_ip",
                "Unknown"
            )

            mitre = alert.get(
                "mitre_technique",
                "N/A"
            )

            description = alert.get(
                "description",
                alert.get(
                    "message",
                    "No detection summary available."
                )
            )


            # Severity icon

            if risk_level == "CRITICAL":

                severity_icon = "🔴"

            elif risk_level == "HIGH":

                severity_icon = "🟠"

            elif risk_level == "MEDIUM":

                severity_icon = "🟡"

            else:

                severity_icon = "🟢"


            # ------------------------------------------
            # INCIDENT LOOKUP
            # ------------------------------------------

            incident_for_alert = None

            for incident in incidents:

                incident_alert_type = (
                    normalize_alert_type(
                        incident["alert_type"]
                    )
                )

                if (
                    incident_alert_type == alert_type
                    and incident["source_ip"]
                    == source_ip
                ):

                    incident_for_alert = incident
                    break


            # ------------------------------------------
            # ALERT CARD
            # ------------------------------------------

            with st.container(
                border=True
            ):

                header_col1, header_col2 = st.columns(
                    [4, 1]
                )

                with header_col1:

                    st.markdown(
                        f"### {severity_icon} {title}"
                    )

                    st.caption(
                        f"Detection Type: {alert_type}"
                    )

                with header_col2:

                    st.metric(
                        "Risk Score",
                        f"{risk_score}/100"
                    )


                info_col1, info_col2, info_col3 = st.columns(
                    3
                )

                with info_col1:

                    st.write(
                        "**Severity**"
                    )

                    if risk_level == "CRITICAL":

                        st.error(
                            "CRITICAL"
                        )

                    elif risk_level == "HIGH":

                        st.warning(
                            "HIGH"
                        )

                    elif risk_level == "MEDIUM":

                        st.warning(
                            "MEDIUM"
                        )

                    else:

                        st.success(
                            "LOW"
                        )


                with info_col2:

                    st.write(
                        "**Source IP**"
                    )

                    st.code(
                        source_ip
                    )


                with info_col3:

                    st.write(
                        "**MITRE ATT&CK**"
                    )

                    st.code(
                        mitre
                    )


                evidence = alert.get(
                    "evidence",
                    {}
                )

                detector_event_ids = evidence.get(
                    "event_ids",
                    []
                )


                st.divider()


                evidence_col1, evidence_col2 = st.columns(
                    2
                )

                with evidence_col1:

                    st.write(
                        "**Evidence Events**"
                    )

                    st.metric(
                        "Events",
                        len(detector_event_ids)
                    )

                with evidence_col2:

                    st.write(
                        "**Detection Summary**"
                    )

                    st.write(
                        description
                    )


                if incident_for_alert:

                    incident_id = incident_for_alert[
                        "incident_id"
                    ]

                    incident_status = incident_for_alert[
                        "status"
                    ]


                    st.divider()


                    incident_col1, incident_col2 = (
                        st.columns(2)
                    )

                    with incident_col1:

                        st.write(
                            "**Incident ID**"
                        )

                        st.code(
                            incident_id
                        )

                    with incident_col2:

                        st.write(
                            "**Incident Status**"
                        )

                        if incident_status in [
                            "CONTAINED",
                            "RESOLVED"
                        ]:

                            st.success(
                                incident_status
                            )

                        elif incident_status in [
                            "INVESTIGATING",
                            "TRIAGED"
                        ]:

                            st.warning(
                                incident_status
                            )

                        else:

                            st.info(
                                incident_status
                            )


                    with st.expander(
                        "View Detection Evidence"
                    ):

                        if detector_event_ids:

                            st.write(
                                "Detector-confirmed event IDs:"
                            )

                            st.code(
                                ", ".join(
                                    str(event_id)
                                    for event_id
                                    in detector_event_ids
                                )
                            )

                        else:

                            st.info(
                                "Detector-specific evidence IDs "
                                "are not available."
                            )


                    if incident_status in [
                        "CONTAINED",
                        "RESOLVED"
                    ]:

                        st.success(
                            "SentinelX automated response "
                            "has been recorded for this incident."
                        )

                    elif risk_level in [
                        "HIGH",
                        "CRITICAL"
                    ]:

                        st.warning(
                            "High-risk alert requires SOC "
                            "investigation and containment "
                            "according to SentinelX policy."
                        )

                    else:

                        st.info(
                            "Alert requires analyst validation "
                            "and continued monitoring."
                        )

                else:

                    st.info(
                        "Incident correlation is pending."
                    )

    else:

        st.success(
            "No active security threats detected."
        )


# ==================================================
# PAGE 4 — INCIDENT MANAGEMENT
# ==================================================

elif selected_page == "Incidents":

    st.title(
        "🛡️ Incident Management"
    )

    st.caption(
        "Track, investigate and manage detected security incidents."
    )

    st.divider()


    if incidents:

        for incident in incidents:

            incident_id = incident[
                "incident_id"
            ]

            title = incident[
                "title"
            ]

            severity = incident[
                "severity"
            ]

            status = incident[
                "status"
            ]

            source_ip = incident[
                "source_ip"
            ]

            risk_score = incident[
                "risk_score"
            ]

            mitre = incident[
                "mitre_technique"
            ]

            description = (
                incident["description"]
                or "No incident description available."
            )


            # ------------------------------------------
            # INCIDENT EVIDENCE
            # ------------------------------------------

            incident_events = get_incident_events(
                incident_id
            )

            evidence_count = len(
                incident_events
            )


            # ------------------------------------------
            # CONTAINMENT HISTORY
            # ------------------------------------------

            incident_containment_actions = [
                action
                for action in containment_actions
                if action["incident_id"]
                == incident_id
            ]


            # ------------------------------------------
            # STATUS ICON
            # ------------------------------------------

            if status == "NEW":

                status_icon = "🆕"

            elif status == "TRIAGED":

                status_icon = "🔎"

            elif status == "INVESTIGATING":

                status_icon = "🕵️"

            elif status == "CONTAINED":

                status_icon = "🛡️"

            elif status == "RESOLVED":

                status_icon = "✅"

            else:

                status_icon = "⚪"


            # ------------------------------------------
            # SEVERITY ICON
            # ------------------------------------------

            if severity == "CRITICAL":

                severity_icon = "🔴"

            elif severity == "HIGH":

                severity_icon = "🟠"

            elif severity == "MEDIUM":

                severity_icon = "🟡"

            else:

                severity_icon = "🟢"


            # ------------------------------------------
            # INCIDENT CARD
            # ------------------------------------------

            with st.container(
                border=True
            ):

                header_col1, header_col2 = st.columns(
                    [4, 1]
                )

                with header_col1:

                    st.markdown(
                        f"### {status_icon} "
                        f"{incident_id} — {title}"
                    )

                    st.caption(
                        f"{severity_icon} Severity: {severity}"
                    )

                with header_col2:

                    st.metric(
                        "Risk Score",
                        f"{risk_score}/100"
                    )


                # --------------------------------------
                # INCIDENT OVERVIEW
                # --------------------------------------

                (
                    info_col1,
                    info_col2,
                    info_col3,
                    info_col4
                ) = st.columns(4)


                with info_col1:

                    st.write(
                        "**Source IP**"
                    )

                    st.code(
                        source_ip
                    )


                with info_col2:

                    st.write(
                        "**Severity**"
                    )

                    st.write(
                        severity
                    )


                with info_col3:

                    st.write(
                        "**MITRE ATT&CK**"
                    )

                    st.code(
                        mitre
                    )


                with info_col4:

                    st.write(
                        "**Evidence Events**"
                    )

                    st.metric(
                        "Events",
                        evidence_count
                    )


                st.write(
                    "**Detection Summary**"
                )

                st.write(
                    description
                )


                st.divider()


                # --------------------------------------
                # INCIDENT LIFECYCLE
                # --------------------------------------

                st.write(
                    "**Incident Lifecycle**"
                )

                lifecycle = [
                    "NEW",
                    "TRIAGED",
                    "INVESTIGATING",
                    "CONTAINED",
                    "RESOLVED"
                ]

                st.caption(
                    " → ".join(lifecycle)
                )

                lifecycle_index = (
                    lifecycle.index(status)
                    if status in lifecycle
                    else 0
                )

                lifecycle_cols = st.columns(
                    len(lifecycle)
                )


                for index, lifecycle_status in enumerate(
                    lifecycle
                ):

                    with lifecycle_cols[index]:

                        if index < lifecycle_index:

                            st.success(
                                lifecycle_status
                            )

                        elif index == lifecycle_index:

                            st.warning(
                                lifecycle_status
                            )

                        else:

                            st.info(
                                lifecycle_status
                            )


                st.divider()


                # --------------------------------------
                # INCIDENT EVIDENCE
                # --------------------------------------

                               # --------------------------------------
                # INCIDENT STATUS HISTORY
                # --------------------------------------

                incident_status_history = (
                    get_incident_status_history(
                        incident_id
                    )
                )

                with st.expander(
                    "View Status History"
                ):

                    if incident_status_history:

                        for history in incident_status_history:

                            old_status = history[
                                "old_status"
                            ]

                            new_status = history[
                                "new_status"
                            ]

                            changed_at = history[
                                "changed_at"
                            ]

                            st.write(
                                f"**{old_status} → {new_status}**"
                            )

                            st.caption(
                                f"Changed at: {changed_at}"
                            )

                            st.divider()

                    else:

                        st.info(
                            "No status history recorded yet."
                        )


                # --------------------------------------
                # INCIDENT EVIDENCE
                # --------------------------------------

                with st.expander(
                    "View Incident Evidence"
                ):

                    if incident_events:

                        evidence_data = []

                        for event in incident_events:

                            evidence_data.append(
                                {
                                    "ID": event["id"],
                                    "Timestamp": event["timestamp"],
                                    "Source IP": event["source_ip"],
                                    "Username": event["username"],
                                    "Event Type": event["event_type"],
                                    "Action": event["action"],
                                    "Status": event["status"],
                                    "Severity": event["severity"],
                                    "Message": event["message"]
                                }
                            )

                        st.dataframe(
                            evidence_data,
                            width="stretch",
                            hide_index=True
                        )

                    else:

                        st.info(
                            "No evidence events linked "
                            "to this incident."
                        )

                incident_status_history = (
                    get_incident_status_history(
                        incident_id
                    )
                )



                st.divider()


                             # --------------------------------------
                # INCIDENT STATUS HISTORY
                # --------------------------------------

                incident_status_history = (
                    get_incident_status_history(
                        incident_id
                    )
                )
                # --------------------------------------
                # INCIDENT STATUS HISTORY
                # --------------------------------------

                incident_status_history = (
                    get_incident_status_history(
                        incident_id
                    )
                )



                # --------------------------------------
                # INCIDENT EVIDENCE
                # --------------------------------------



                # --------------------------------------
                # INCIDENT EVIDENCE
                # --------------------------------------



                # --------------------------------------
                # AI SOC COPILOT
                # --------------------------------------

                st.subheader(
                    "🤖 AI SOC Copilot"
                )

                st.caption(
                    "Evidence-grounded AI investigation "
                    "and response assistance."
                )


                if st.button(
                    "Analyze Incident with AI",
                    key=f"ai_analyze_{incident_id}",
                    use_container_width=True
                ):

                    with st.spinner(
                        "AI Copilot is analyzing "
                        "the incident..."
                    ):

                        ai_result = analyze_incident(
                            incident,
                            incident_events
                        )


                    if ai_result:

                        st.success(
                            "AI analysis completed."
                        )


                        st.write(
                            "**Incident Summary**"
                        )

                        st.write(
                            ai_result.get(
                                "incident_summary",
                                "Not available in supplied evidence."
                            )
                        )


                        st.write(
                            "**Severity Explanation**"
                        )

                        st.write(
                            ai_result.get(
                                "severity_explanation",
                                "Not available in supplied evidence."
                            )
                        )


                        st.write(
                            "**MITRE ATT&CK Explanation**"
                        )

                        st.write(
                            ai_result.get(
                                "mitre_explanation",
                                "Not available in supplied evidence."
                            )
                        )


                        st.write(
                            "**Investigation Steps**"
                        )

                        investigation_steps = ai_result.get(
                            "investigation_steps",
                            []
                        )


                        if isinstance(
                            investigation_steps,
                            list
                        ):

                            for step in investigation_steps:

                                st.markdown(
                                    f"- {step}"
                                )

                        else:

                            st.write(
                                investigation_steps
                            )


                        st.write(
                            "**Recommended Response**"
                        )

                        recommended_response = ai_result.get(
                            "recommended_response",
                            []
                        )


                        if isinstance(
                            recommended_response,
                            list
                        ):

                            for response_step in recommended_response:

                                st.markdown(
                                    f"- {response_step}"
                                )

                        else:

                            st.write(
                                recommended_response
                            )


                        st.caption(
                            f"Evidence events analyzed: "
                            f"{ai_result.get('evidence_count', 0)}"
                        )

                    else:

                        st.error(
                            "AI analysis could not be generated."
                        )


                st.divider()


                # --------------------------------------
                # AUTOMATED RESPONSE HISTORY
                # --------------------------------------

                with st.expander(
                    "View Automated Response History"
                ):

                    if incident_containment_actions:

                        response_data = []

                        for action in incident_containment_actions:

                            response_data.append(
                                {
                                    "Timestamp": action["timestamp"],
                                    "Action": action["action"],
                                    "Source IP": action["source_ip"],
                                    "Status": action["status"],
                                    "Reason": action["reason"]
                                }
                            )


                        st.dataframe(
                            response_data,
                            width="stretch",
                            hide_index=True
                        )

                    else:

                        st.info(
                            "No automated containment "
                            "actions recorded."
                        )


                # --------------------------------------
                # RESPONSE STATE
                # --------------------------------------

                st.write(
                    "**Response State**"
                )


                if status == "CONTAINED":

                    st.success(
                        "🛡️ Threat contained by SentinelX."
                    )

                elif status == "RESOLVED":

                    st.success(
                        "✅ Incident resolved."
                    )

                elif status == "INVESTIGATING":

                    st.warning(
                        "🕵️ Incident currently under investigation."
                    )

                elif status == "TRIAGED":

                    st.warning(
                        "🔎 Incident triaged and awaiting investigation."
                    )

                else:

                    st.info(
                        "🆕 New incident awaiting analyst triage."
                    )


                st.divider()


                # --------------------------------------
                # STATUS MANAGEMENT
                # --------------------------------------

                status_options = [
                    "NEW",
                    "TRIAGED",
                    "INVESTIGATING",
                    "CONTAINED",
                    "RESOLVED"
                ]


                selected_status = st.selectbox(
                    "Update Incident Status",
                    status_options,
                    index=status_options.index(status),
                    key=f"status_{incident_id}"
                )


                if selected_status != status:

                    if st.button(
                        "Update Status",
                        key=f"update_{incident_id}",
                        use_container_width=True
                    ):

                        updated_rows = update_incident_status(
                            incident_id,
                            selected_status
                        )


                        if updated_rows == 1:

                            st.success(
                                f"{incident_id} updated "
                                f"to {selected_status}."
                            )

                            st.rerun()

                        else:

                            st.error(
                                "Incident status update failed."
                            )

    else:

        st.info(
            "No incidents created yet."
        )


# ==================================================
# PAGE 5 — MITRE ATT&CK
# ==================================================

elif selected_page == "MITRE ATT&CK":

    st.title(
        "🎯 MITRE ATT&CK"
    )

    st.caption(
        "Technique mapping for SentinelX security detections."
    )

    st.divider()


    mitre_mapping = {

        "BRUTE_FORCE": {
            "technique": "T1110",
            "name": "Brute Force",
            "description": (
                "Attempts to gain access by repeatedly "
                "guessing or using credentials."
            )
        },

        "PORT_SCAN": {
            "technique": "T1046",
            "name": "Network Service Scanning",
            "description": (
                "Discovery of network services and "
                "accessible ports."
            )
        },

        "SUSPICIOUS_POWERSHELL": {
            "technique": "T1059.001",
            "name": "PowerShell",
            "description": (
                "Execution of commands and scripts "
                "through PowerShell."
            )
        },

        "PRIVILEGE_ESCALATION": {
            "technique": "T1068",
            "name": "Exploitation for Privilege Escalation",
            "description": (
                "Exploitation of vulnerabilities or "
                "weaknesses to obtain higher privileges."
            )
        },

        "SUSPICIOUS_AUTH": {
            "technique": "T1078",
            "name": "Valid Accounts",
            "description": (
                "Use of legitimate credentials to "
                "access systems or resources."
            )
        }
    }


    # ----------------------------------------------
    # DETECTION MAPPING
    # ----------------------------------------------

    st.subheader(
        "Detection → MITRE ATT&CK Mapping"
    )

    mitre_data = []

    for alert_type, mapping in mitre_mapping.items():

        matching_alerts = [
            alert
            for alert in risk_alerts
            if normalize_alert_type(
                alert.get(
                    "alert_type"
                )
            ) == alert_type
        ]

        mitre_data.append(
            {
                "Detection": alert_type,
                "MITRE ID": mapping["technique"],
                "Technique": mapping["name"],
                "Alerts": len(matching_alerts),
                "Description": mapping["description"]
            }
        )


    st.dataframe(
        mitre_data,
        width="stretch",
        hide_index=True
    )


    st.divider()


    # ----------------------------------------------
    # ACTIVE TECHNIQUES
    # ----------------------------------------------

    st.subheader(
        "Active MITRE Techniques"
    )

    active_techniques = set()

    for alert in risk_alerts:

        technique = alert.get(
            "mitre_technique"
        )

        if technique:

            active_techniques.add(
                technique
            )


    if active_techniques:

        for technique in sorted(
            active_techniques
        ):

            mapping = None

            for item in mitre_mapping.values():

                if item["technique"] == technique:

                    mapping = item
                    break


            if mapping:

                with st.container(
                    border=True
                ):

                    st.markdown(
                        f"### {mapping['technique']} — "
                        f"{mapping['name']}"
                    )

                    st.write(
                        mapping["description"]
                    )

            else:

                st.code(
                    technique
                )

    else:

        st.info(
            "No active MITRE ATT&CK techniques detected."
        )


# ==================================================
# PAGE 6 — AUDIT LOGS
# ==================================================

elif selected_page == "Audit Logs":

    st.title(
        "📋 Audit Logs"
    )

    st.caption(
        "Recorded security response and containment actions."
    )

    st.divider()


    # Reload latest actions

    containment_actions = (
        get_containment_actions()
    )


    if containment_actions:

        audit_data = []

        for action in containment_actions:

            audit_data.append(
                {
                    "ID": action["id"],
                    "Timestamp": action["timestamp"],
                    "Incident": action["incident_id"],
                    "Action": action["action"],
                    "Source IP": action["source_ip"],
                    "Status": action["status"],
                    "Reason": action["reason"]
                }
            )


        st.dataframe(
            audit_data,
            width="stretch",
            hide_index=True
        )


        st.divider()

        st.subheader(
            "Response Statistics"
        )


        successful_actions = sum(
            1
            for action in containment_actions
            if action["status"] == "SUCCESS"
        )


        failed_actions = sum(
            1
            for action in containment_actions
            if action["status"] != "SUCCESS"
        )


        stat_col1, stat_col2, stat_col3 = (
            st.columns(3)
        )


        with stat_col1:

            st.metric(
                "Total Actions",
                len(containment_actions)
            )


        with stat_col2:

            st.metric(
                "Successful",
                successful_actions
            )


        with stat_col3:

            st.metric(
                "Failed",
                failed_actions
            )

    else:

        st.info(
            "No containment actions recorded yet."
        )


# ==================================================
# FOOTER
# ==================================================

st.divider()

st.caption(
    "SentinelX — AI-Assisted Autonomous Security Operations Center"
)

st.caption(
    "Detection • Risk Analysis • MITRE Mapping • "
    "AI Investigation • Safe Containment • Audit"
)
st.markdown("""
<style id="SENTINELX_FINAL_FRONTEND_LOCK_V1">
/* =========================================================
   SENTINELX — FINAL FRONTEND LOCK
   Visual-only CSS. No backend/data/functionality changes.
   ========================================================= */

:root{
  --sx-bg:#0B1420;
  --sx-panel:#111F2D;
  --sx-panel-2:#16283A;
  --sx-border:#263B4D;
  --sx-text:#E7EEF2;
  --sx-muted:#91A4B0;
  --sx-blue:#4EA1FF;
  --sx-cyan:#4DD4E8;
  --sx-green:#4FD39A;
  --sx-amber:#F0B95A;
  --sx-red:#F06A7A;
}

/* ---------- APP SURFACE ---------- */
.stApp{
  background:#0B1420 !important;
  color:#E7EEF2 !important;
}

.main .block-container{
  max-width:1500px !important;
  padding-top:1.15rem !important;
  padding-bottom:2.5rem !important;
}

/* ---------- GLOBAL TEXT ---------- */
.stApp p,
.stApp span,
.stApp label,
.stApp div{
  font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
}

.stApp h1,
.stApp h2,
.stApp h3,
.stApp h4{
  color:#E7EEF2 !important;
  letter-spacing:-.25px;
}

/* ---------- TOP NAV ---------- */
[data-testid="stHorizontalBlock"]{
  gap:12px;
}

button{
  transition:
    background .16s ease,
    border-color .16s ease,
    color .16s ease,
    box-shadow .16s ease,
    transform .16s ease !important;
}

button:hover{
  border-color:#4EA1FF !important;
  box-shadow:0 5px 16px rgba(0,0,0,.18) !important;
}

button:focus{
  box-shadow:0 0 0 2px rgba(78,161,255,.18) !important;
}

/* ---------- CARDS / PANELS ---------- */
.sx-panel,
.sx-card,
.sx-kpi-card,
.sx-engine-card,
.sx-threat-card,
.sx-command-identity,
.sx-hero{
  border-color:#263B4D !important;
  border-radius:10px !important;
}

.sx-panel,
.sx-card,
.sx-engine-card,
.sx-threat-card{
  background:#111F2D !important;
  box-shadow:
    0 6px 18px rgba(0,0,0,.16),
    inset 0 1px 0 rgba(255,255,255,.018) !important;
}

/* ---------- KPI ---------- */
.sx-kpi-card{
  background:#111F2D !important;
  border:1px solid #263B4D !important;
  min-height:112px !important;
  padding:15px 16px 13px !important;
}

.sx-kpi-card:hover{
  border-color:#3A5870 !important;
  transform:translateY(-1px);
}

/* ---------- HERO ---------- */
.sx-hero{
  background:#111F2D !important;
  border:1px solid #263B4D !important;
  box-shadow:
    0 8px 24px rgba(0,0,0,.18),
    inset 0 1px 0 rgba(255,255,255,.02) !important;
}

/* ---------- IDENTITY / COMMAND CENTER ---------- */
.sx-command-identity{
  background:#111F2D !important;
  border:1px solid #263B4D !important;
  box-shadow:0 6px 18px rgba(0,0,0,.16) !important;
}

.sx-identity-name{
  color:#E7EEF2 !important;
}

.sx-identity-name span{
  color:#4DD4E8 !important;
}

.sx-identity-subtitle,
.sx-identity-kicker{
  color:#91A4B0 !important;
}

.sx-ai-line strong{
  color:#E7EEF2 !important;
}

/* ---------- SEMANTIC STATUS ---------- */
.sx-status-dot{
  box-shadow:none !important;
}

.sx-identity-online{
  color:#4FD39A !important;
}

.sx-status-items em{
  color:#4FD39A !important;
}

/* ---------- EXPANDERS ---------- */
[data-testid="stExpander"]{
  background:#111F2D !important;
  border:1px solid #263B4D !important;
  border-radius:10px !important;
  overflow:hidden !important;
}

[data-testid="stExpander"]:hover{
  border-color:#3A5870 !important;
}

/* ---------- DATA TABLES ---------- */
[data-testid="stDataFrame"],
[data-testid="stTable"]{
  border:1px solid #263B4D !important;
  border-radius:8px !important;
  overflow:hidden !important;
}

/* ---------- INPUTS ---------- */
input,
textarea,
[data-baseweb="select"] > div{
  background:#111F2D !important;
  color:#E7EEF2 !important;
  border-color:#263B4D !important;
}

input:focus,
textarea:focus{
  border-color:#4EA1FF !important;
  box-shadow:0 0 0 1px rgba(78,161,255,.18) !important;
}

/* ---------- ALERTS / CALLOUTS ---------- */
[data-testid="stAlert"]{
  border-radius:9px !important;
  border:1px solid #263B4D !important;
}

/* ---------- LINKS ---------- */
a{
  color:#4EA1FF !important;
}

a:hover{
  color:#4DD4E8 !important;
}

/* ---------- SIDEBAR REMAINS HIDDEN ----------
   Dashboard contains the required command-center identity.
   ------------------------------------------------------- */
section[data-testid="stSidebar"],
[data-testid="collapsedControl"]{
  display:none !important;
}

/* ---------- REMOVE UNNECESSARY VISUAL NOISE ---------- */
.stApp hr{
  border-color:#263B4D !important;
  opacity:.7;
}

/* ---------- RESPONSIVE ---------- */
@media (max-width:1100px){
  .main .block-container{
    padding-left:18px !important;
    padding-right:18px !important;
  }

  .sx-command-identity{
    grid-template-columns:1fr 1fr !important;
    gap:14px !important;
  }
}

@media (max-width:700px){
  .main .block-container{
    padding-left:12px !important;
    padding-right:12px !important;
  }

  .sx-command-identity{
    grid-template-columns:1fr !important;
  }

  .sx-kpi-card{
    min-height:100px !important;
  }
}

/* ---------- FINAL POLISH ---------- */
::selection{
  background:rgba(78,161,255,.22);
  color:#E7EEF2;
}

</style>
""", unsafe_allow_html=True)

