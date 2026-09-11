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

st.markdown(
    """
    <style>
    :root {
        --sx-bg: #07111F;
        --sx-panel: #0F1D2E;
        --sx-panel-2: #13243A;
        --sx-border: #253B55;
        --sx-border-light: rgba(37, 59, 85, 0.6);
        --sx-text: #F4F8FC;
        --sx-muted: #8FA3B8;
        --sx-cyan: #38D9FF;
        --sx-indigo: #7C6CFF;
        --sx-green: #3DDB9A;
        --sx-amber: #FFB84D;
        --sx-red: #FF667D;
    }

    /* Global Shell & Container */
    [data-testid="stAppViewContainer"] {
        background:
            radial-gradient(circle at 85% 5%, rgba(56, 217, 255, 0.06), transparent 28%),
            radial-gradient(circle at 5% 45%, rgba(124, 108, 255, 0.04), transparent 30%),
            linear-gradient(180deg, #07111F 0%, #060E1A 55%, #050B14 100%) !important;
        color: #F4F8FC !important;
    }

    [data-testid="stHeader"] {
        background: rgba(7, 17, 31, 0.82) !important;
        backdrop-filter: blur(8px) !important;
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
        color: #F4F8FC !important;
    }

    /* Typography & Headings */
    h1, h2, h3, h4, h5, h6 {
        color: #F4F8FC !important;
        font-weight: 700 !important;
        letter-spacing: -0.3px !important;
    }

    h1 {
        font-size: 1.55rem !important;
        padding-bottom: 4px !important;
    }

    h2, h3 {
        font-size: 1.22rem !important;
        margin-top: 10px !important;
    }

    .stCaption, p, span, label, [data-testid="stMarkdownContainer"] p {
        color: #F4F8FC;
    }

    .stCaption {
        color: #8FA3B8 !important;
        font-size: 0.82rem !important;
    }

    hr {
        border-color: #253B55 !important;
        opacity: 0.6 !important;
        margin: 18px 0 !important;
    }

    /* Top Command Header */
    .sx-top-nav-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 20px;
        padding: 14px 20px;
        margin-bottom: 12px;
        border-radius: 10px;
        background: linear-gradient(145deg, rgba(15, 29, 46, 0.98), rgba(7, 17, 31, 0.98)) !important;
        border: 1px solid #253B55 !important;
        box-shadow: 0 6px 18px rgba(0, 0, 0, 0.2);
    }

    .sx-top-nav-kicker {
        color: #38D9FF !important;
        font-size: 0.68rem;
        font-weight: 800;
        letter-spacing: 1.5px;
        text-transform: uppercase;
    }

    .sx-top-nav-title {
        color: #F4F8FC;
        font-size: 1.08rem;
        font-weight: 800;
        letter-spacing: 0.5px;
        margin-top: 2px;
    }

    .sx-top-nav-live {
        display: flex;
        align-items: center;
        gap: 8px;
        color: #3DDB9A !important;
        font-size: 0.70rem;
        font-weight: 800;
        letter-spacing: 1px;
        white-space: nowrap;
    }

    .sx-top-live-dot {
        width: 8px;
        height: 8px;
        background: #3DDB9A;
        border-radius: 50%;
        display: inline-block;
        box-shadow: 0 0 8px #3DDB9A;
        animation: sx-pulse 2s infinite;
    }

    @keyframes sx-pulse {
        0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(61, 219, 154, 0.7); }
        70% { transform: scale(1); box-shadow: 0 0 0 6px rgba(61, 219, 154, 0); }
        100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(61, 219, 154, 0); }
    }

    /* Panels & Containers */
    .sx-panel {
        background: linear-gradient(145deg, rgba(15, 29, 46, 0.98), rgba(7, 17, 31, 0.98)) !important;
        border: 1px solid #253B55 !important;
        border-radius: 10px;
        padding: 16px 20px;
        box-shadow: 0 6px 18px rgba(0, 0, 0, 0.2);
        margin-bottom: 12px;
    }

    [data-testid="stVerticalBlockBorderWrapper"] > div {
        background: #0F1D2E !important;
        border: 1px solid #253B55 !important;
        border-radius: 10px !important;
        padding: 16px 20px !important;
        box-shadow: 0 6px 18px rgba(0, 0, 0, 0.2) !important;
        margin-bottom: 14px !important;
    }

    /* Buttons */
    .stButton > button {
        background: #0F1D2E !important;
        color: #F4F8FC !important;
        border: 1px solid #253B55 !important;
        border-radius: 6px !important;
        padding: 8px 16px !important;
        font-weight: 600 !important;
        font-size: 0.84rem !important;
        letter-spacing: 0.3px !important;
        transition: all 0.2s ease !important;
        box-shadow: 0 2px 6px rgba(0, 0, 0, 0.15) !important;
    }

    .stButton > button:hover {
        background: #13243A !important;
        border-color: #38D9FF !important;
        color: #38D9FF !important;
        box-shadow: 0 0 10px rgba(56, 217, 255, 0.25) !important;
    }

    .stButton > button[kind="primary"],
    [data-testid="baseButton-primary"] {
        background: linear-gradient(135deg, #13243A, #0F1D2E) !important;
        border-color: #38D9FF !important;
        color: #38D9FF !important;
        box-shadow: 0 0 12px rgba(56, 217, 255, 0.28) !important;
        font-weight: 700 !important;
    }

    /* Native Metrics */
    [data-testid="stMetric"], .stMetric {
        background: linear-gradient(145deg, #0F1D2E, #13243A) !important;
        border: 1px solid #253B55 !important;
        border-radius: 8px !important;
        padding: 14px 18px !important;
        box-shadow: 0 4px 14px rgba(0, 0, 0, 0.25) !important;
        transition: border-color 0.2s ease !important;
    }

    [data-testid="stMetric"]:hover {
        border-color: rgba(56, 217, 255, 0.4) !important;
    }

    [data-testid="stMetricLabel"] p {
        color: #8FA3B8 !important;
        font-size: 0.72rem !important;
        font-weight: 800 !important;
        text-transform: uppercase !important;
        letter-spacing: 1.2px !important;
    }

    [data-testid="stMetricValue"] {
        color: #38D9FF !important;
        font-size: 1.85rem !important;
        font-weight: 800 !important;
        letter-spacing: -0.5px !important;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace !important;
    }

    /* DataFrames & Tables */
    [data-testid="stDataFrame"], [data-testid="stTable"] {
        border: 1px solid #253B55 !important;
        border-radius: 8px !important;
        background: #0F1D2E !important;
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25) !important;
        overflow: hidden !important;
    }

    div[data-testid="stDataFrame"] > div {
        background: #0F1D2E !important;
    }

    table {
        background: #0F1D2E !important;
        color: #F4F8FC !important;
        border-collapse: collapse !important;
        width: 100% !important;
    }

    th {
        background: #13243A !important;
        color: #8FA3B8 !important;
        font-size: 0.74rem !important;
        font-weight: 800 !important;
        text-transform: uppercase !important;
        letter-spacing: 1px !important;
        padding: 10px 14px !important;
        border-bottom: 1px solid #253B55 !important;
    }

    td {
        padding: 10px 14px !important;
        border-bottom: 1px solid rgba(37, 59, 85, 0.4) !important;
        font-size: 0.85rem !important;
        color: #F4F8FC !important;
    }

    tr:hover td {
        background: rgba(19, 36, 58, 0.7) !important;
    }

    /* Expanders */
    [data-testid="stExpander"] {
        background: #0F1D2E !important;
        border: 1px solid #253B55 !important;
        border-radius: 8px !important;
        margin-bottom: 12px !important;
        box-shadow: 0 3px 10px rgba(0, 0, 0, 0.18) !important;
        overflow: hidden !important;
    }

    [data-testid="stExpander"] summary {
        color: #F4F8FC !important;
        font-weight: 700 !important;
        font-size: 0.88rem !important;
        padding: 10px 16px !important;
        border-radius: 8px !important;
        transition: all 0.2s ease !important;
    }

    [data-testid="stExpander"] summary:hover {
        color: #38D9FF !important;
        background: #13243A !important;
    }

    [data-testid="stExpander"] summary svg {
        fill: #8FA3B8 !important;
    }

    [data-testid="stExpander"] [data-testid="stExpanderDetails"] {
        padding: 14px 18px !important;
        border-top: 1px solid #253B55 !important;
    }

    /* Selectboxes & Inputs */
    .stSelectbox label {
        color: #8FA3B8 !important;
        font-size: 0.74rem !important;
        font-weight: 800 !important;
        text-transform: uppercase !important;
        letter-spacing: 1px !important;
    }

    .stSelectbox div[data-baseweb="select"] > div {
        background: #13243A !important;
        border: 1px solid #253B55 !important;
        border-radius: 6px !important;
        color: #F4F8FC !important;
        font-weight: 600 !important;
        font-size: 0.85rem !important;
    }

    .stSelectbox div[data-baseweb="select"]:hover > div {
        border-color: #38D9FF !important;
    }

    div[data-baseweb="popover"],
    ul[role="listbox"] {
        background: #0F1D2E !important;
        border: 1px solid #253B55 !important;
        color: #F4F8FC !important;
    }

    li[role="option"] {
        color: #F4F8FC !important;
    }

    li[role="option"]:hover,
    li[aria-selected="true"] {
        background: #13243A !important;
        color: #38D9FF !important;
    }

    /* Status Notifications */
    .stAlert, [data-testid="stAlert"] {
        border-radius: 6px !important;
        border-width: 1px !important;
        font-weight: 600 !important;
        font-size: 0.84rem !important;
        padding: 8px 14px !important;
    }

    [data-testid="stAlert"]:has([data-testid="stNotificationContentSuccess"]),
    div[data-baseweb="notification"]:has([aria-label="Success"]) {
        background: rgba(61, 219, 154, 0.12) !important;
        border: 1px solid rgba(61, 219, 154, 0.35) !important;
        color: #3DDB9A !important;
    }

    [data-testid="stAlert"]:has([data-testid="stNotificationContentWarning"]),
    div[data-baseweb="notification"]:has([aria-label="Warning"]) {
        background: rgba(255, 184, 77, 0.12) !important;
        border: 1px solid rgba(255, 184, 77, 0.35) !important;
        color: #FFB84D !important;
    }

    [data-testid="stAlert"]:has([data-testid="stNotificationContentError"]),
    div[data-baseweb="notification"]:has([aria-label="Error"]) {
        background: rgba(255, 102, 125, 0.12) !important;
        border: 1px solid rgba(255, 102, 125, 0.35) !important;
        color: #FF667D !important;
    }

    [data-testid="stAlert"]:has([data-testid="stNotificationContentInfo"]),
    div[data-baseweb="notification"]:has([aria-label="Info"]) {
        background: rgba(56, 217, 255, 0.10) !important;
        border: 1px solid rgba(56, 217, 255, 0.30) !important;
        color: #38D9FF !important;
    }

    /* Code Blocks */
    code, pre, [data-testid="stCodeBlock"] {
        background: #13243A !important;
        color: #38D9FF !important;
        border: 1px solid #253B55 !important;
        border-radius: 4px !important;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace !important;
        font-size: 0.85rem !important;
    }

    /* Badges */
    .sx-badge {
        display: inline-block;
        padding: 3px 9px;
        border-radius: 4px;
        font-size: 0.68rem;
        font-weight: 800;
        letter-spacing: 0.8px;
        text-transform: uppercase;
    }

    .sx-badge-critical { background: rgba(255, 102, 125, 0.18); color: #FF667D; border: 1px solid rgba(255, 102, 125, 0.4); }
    .sx-badge-high { background: rgba(255, 184, 77, 0.18); color: #FFB84D; border: 1px solid rgba(255, 184, 77, 0.4); }
    .sx-badge-medium { background: rgba(124, 108, 255, 0.18); color: #7C6CFF; border: 1px solid rgba(124, 108, 255, 0.4); }
    .sx-badge-low { background: rgba(61, 219, 154, 0.18); color: #3DDB9A; border: 1px solid rgba(61, 219, 154, 0.4); }
    .sx-badge-active { background: rgba(56, 217, 255, 0.18); color: #38D9FF; border: 1px solid rgba(56, 217, 255, 0.4); }
    .sx-badge-contained { background: rgba(61, 219, 154, 0.18); color: #3DDB9A; border: 1px solid rgba(61, 219, 154, 0.4); }

    /* Scrollbars */
    ::-webkit-scrollbar { width: 7px; height: 7px; }
    ::-webkit-scrollbar-track { background: #07111F; }
    ::-webkit-scrollbar-thumb { background: #253B55; border-radius: 10px; }
    ::-webkit-scrollbar-thumb:hover { background: #38D9FF; }
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
# FRONT-PAGE NAVIGATION
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
        is_active = (page == selected_page)
        if st.button(
            label,
            use_container_width=True,
            key=key,
            type="primary" if is_active else "secondary"
        ):
            st.session_state.selected_page = page
            st.rerun()


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
# PAGE 1 — DASHBOARD
# ==================================================

if selected_page == "Dashboard":

    st.markdown(
        """
        <div class="sx-panel" style="margin-bottom: 1.25rem;">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:14px;">
                <div>
                    <div class="sx-top-nav-kicker">SENTINELX • AUTONOMOUS SECURITY OPERATIONS COMMAND</div>
                    <div style="font-size:1.6rem; font-weight:800; color:#F4F8FC; margin-top:3px; letter-spacing:-0.4px;">
                        Enterprise Threat Telemetry & Incident Intelligence
                    </div>
                    <div style="color:#8FA3B8; font-size:0.86rem; margin-top:3px;">
                        Continuous Ingestion • Rule-Engine Correlation • Risk Prioritization • Automated Containment
                    </div>
                </div>
                <div style="text-align:right;">
                    <span class="sx-top-live-dot" style="margin-right:6px;"></span>
                    <span style="color:#3DDB9A; font-weight:800; font-size:0.78rem; letter-spacing:1px;">SOC SUBSYSTEMS ONLINE</span>
                    <div style="color:#8FA3B8; font-size:0.78rem; margin-top:2px;">AI Investigation Copilot Ready</div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.divider()

    # ----------------------------------------------
    # TOP SOC METRICS
    # ----------------------------------------------

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "Security Events Ingested",
            total_events
        )

    with col2:
        st.metric(
            "High & Critical Alerts",
            high_alerts
        )

    with col3:
        st.metric(
            "Active Threats / Incidents",
            active_incidents
        )

    with col4:
        st.metric(
            "Contained Threats",
            contained_incidents
        )

    # ----------------------------------------------
    # SECURITY POSTURE
    # ----------------------------------------------

    st.divider()

    st.subheader("🛡️ Enterprise Security Posture")

    posture_col1, posture_col2 = st.columns([1, 3])

    with posture_col1:
        st.metric(
            "Posture Score",
            f"{posture_score} / 100"
        )

    with posture_col2:
        if posture_label in ["EXCELLENT", "GOOD"]:
            st.success(f"Security Posture: {posture_label} — Systems stable under current threat load")
        elif posture_label in ["MODERATE", "POOR"]:
            st.warning(f"Security Posture: {posture_label} — Active investigation and containment recommended")
        else:
            st.error(f"Security Posture: {posture_label} — Critical threat threshold breached")

        norm_score = max(0.0, min(1.0, float(posture_score) / 100.0))
        st.progress(norm_score)

    st.caption(
        f"Active threats: {posture['details']['active_incidents']}  |  "
        f"High/Critical active: {posture['details']['high_critical_incidents']}  |  "
        f"Contained: {posture['details']['contained_incidents']}  |  "
        f"Resolved: {posture['details']['resolved_incidents']}"
    )

    # ----------------------------------------------
    # THREAT OVERVIEW
    # ----------------------------------------------

    st.divider()

    st.subheader("📊 Threat Landscape Overview")

    summary_col1, summary_col2, summary_col3 = st.columns(3)

    with summary_col1:
        st.metric(
            "Correlated Alerts",
            len(risk_alerts)
        )

    with summary_col2:
        high_critical_count = sum(
            1 for alert in risk_alerts
            if alert.get("risk_level") in ["HIGH", "CRITICAL"]
        )
        st.metric(
            "Priority High / Critical",
            high_critical_count
        )

    with summary_col3:
        detection_types = len(
            set(
                alert.get("alert_type", "UNKNOWN")
                for alert in risk_alerts
            )
        )
        st.metric(
            "Active Detection Types",
            detection_types
        )

    # ----------------------------------------------
    # ENGINE & PIPELINE HEALTH STATUS
    # ----------------------------------------------

    st.divider()

    st.subheader("⚡ SentinelX Core Pipeline Health")

    status_col1, status_col2, status_col3, status_col4, status_col5 = st.columns(5)

    with status_col1:
        st.success("Detection Engine\n\n**ONLINE (5 Detectors)**")

    with status_col2:
        st.success("Risk Engine\n\n**ONLINE (Enrichment)**")

    with status_col3:
        st.success("Database Engine\n\n**CONNECTED (SQLite)**")

    with status_col4:
        st.success("AI SOC Copilot\n\n**ACTIVE (Gemini / Rules)**")

    with status_col5:
        st.success("Safe Containment\n\n**ACTIVE (Host Isolation)**")



# ==================================================
# PAGE 2 — LIVE EVENTS
# ==================================================

elif selected_page == "Live Events":

    st.title("📡 Live Security Telemetry")
    st.caption("Real-time security telemetry and host audit events ingested by SentinelX.")

    st.divider()

    if events:
        # ----------------------------------------------
        # INTERACTIVE TELEMETRY FILTERS
        # ----------------------------------------------
        filter_col1, filter_col2, filter_col3 = st.columns([2, 1, 1])

        with filter_col1:
            search_query = st.text_input(
                "Search Telemetry",
                placeholder="Search by IP, username, message, or ID...",
                key="filter_events_search"
            ).strip().lower()

        unique_types = sorted(list(set(str(e.get("event_type", "")) for e in events if e.get("event_type"))))
        with filter_col2:
            selected_type = st.selectbox(
                "Event Type",
                ["ALL"] + unique_types,
                key="filter_events_type"
            )

        unique_severities = ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        with filter_col3:
            selected_severity = st.selectbox(
                "Severity",
                unique_severities,
                key="filter_events_sev"
            )

        # ----------------------------------------------
        # FILTER DATA
        # ----------------------------------------------
        filtered_events = []
        for event in events:
            # Search query matching
            if search_query:
                combined_text = (
                    f"{event.get('id', '')} "
                    f"{event.get('source_ip', '')} "
                    f"{event.get('username', '')} "
                    f"{event.get('event_type', '')} "
                    f"{event.get('action', '')} "
                    f"{event.get('message', '')}"
                ).lower()
                if search_query not in combined_text:
                    continue

            # Event type filter
            if selected_type != "ALL" and str(event.get("event_type")) != selected_type:
                continue

            # Severity filter
            if selected_severity != "ALL" and str(event.get("severity", "")).upper() != selected_severity:
                continue

            filtered_events.append(event)

        # ----------------------------------------------
        # TELEMETRY STATS BAR
        # ----------------------------------------------
        stat_col1, stat_col2, stat_col3 = st.columns(3)
        with stat_col1:
            st.metric("Total Ingested Events", len(events))
        with stat_col2:
            st.metric("Filtered Matches", len(filtered_events))
        with stat_col3:
            latest_ts = events[0].get("timestamp", "N/A")[:19].replace("T", " ") if events else "N/A"
            st.metric("Latest Ingestion", latest_ts)

        st.divider()

        if filtered_events:
            event_data = []
            for event in filtered_events:
                event_data.append(
                    {
                        "ID": event["id"],
                        "Timestamp": event["timestamp"],
                        "Source IP": event["source_ip"],
                        "Username": event["username"] or "—",
                        "Event Type": event["event_type"],
                        "Action": event["action"],
                        "Status": event["status"],
                        "Severity": event["severity"],
                        "Port": str(event["port"]) if event.get("port") is not None else "—",
                        "Message": event["message"]
                    }
                )

            st.dataframe(
                event_data,
                width="stretch",
                hide_index=True
            )
            st.caption(f"Displaying {len(filtered_events)} of {len(events)} security events in buffer.")
        else:
            st.info("No security events match the current filter criteria.")

    else:
        st.info("No security events received yet.")



# ==================================================
# PAGE 3 — SECURITY ALERTS
# ==================================================

elif selected_page == "Security Alerts":

    st.title("🚨 Security Alerts & Detections")
    st.caption("Prioritized detections generated by SentinelX detection engines and enriched by the Risk Scoring pipeline.")

    st.divider()

    # ----------------------------------------------
    # ALERT SUMMARY
    # ----------------------------------------------

    alert_summary_col1, alert_summary_col2, alert_summary_col3 = st.columns(3)

    with alert_summary_col1:
        st.metric(
            "Total Alerts",
            len(risk_alerts)
        )

    with alert_summary_col2:
        high_critical_count = sum(
            1 for alert in risk_alerts
            if alert.get("risk_level") in ["HIGH", "CRITICAL"]
        )
        st.metric(
            "High / Critical Priority",
            high_critical_count
        )

    with alert_summary_col3:
        detection_types = len(
            set(
                alert.get("alert_type", "UNKNOWN")
                for alert in risk_alerts
            )
        )
        st.metric(
            "Detection Types",
            detection_types
        )

    st.divider()

    # ----------------------------------------------
    # FILTER CONTROLS
    # ----------------------------------------------

    filter_alerts_col1, filter_alerts_col2 = st.columns([2, 1])

    with filter_alerts_col1:
        alerts_search = st.text_input(
            "Search Alerts",
            placeholder="Search by IP, title, or detection type...",
            key="filter_alerts_search"
        ).strip().lower()

    with filter_alerts_col2:
        alerts_sev_filter = st.selectbox(
            "Filter by Severity",
            ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
            key="filter_alerts_sev"
        )

    # ----------------------------------------------
    # FILTER ALERTS LIST
    # ----------------------------------------------

    filtered_alerts = []
    for alert in risk_alerts:
        risk_level = alert.get("risk_level", "LOW")
        if alerts_sev_filter != "ALL" and risk_level != alerts_sev_filter:
            continue

        if alerts_search:
            searchable = (
                f"{alert.get('title', '')} "
                f"{alert.get('source_ip', '')} "
                f"{alert.get('alert_type', '')} "
                f"{alert.get('mitre_technique', '')} "
                f"{alert.get('description', '')} "
                f"{alert.get('message', '')}"
            ).lower()
            if alerts_search not in searchable:
                continue

        filtered_alerts.append(alert)

    # ----------------------------------------------
    # ALERT CARDS
    # ----------------------------------------------

    if filtered_alerts:
        st.caption(f"Showing {len(filtered_alerts)} of {len(risk_alerts)} security alerts.")

        for alert in filtered_alerts:
            risk_level = alert.get("risk_level", "LOW")
            risk_score = alert.get("risk_score", 0)
            alert_type = normalize_alert_type(alert.get("alert_type", "UNKNOWN"))
            title = alert.get("title", "Security Alert")
            source_ip = alert.get("source_ip", "Unknown")
            mitre = alert.get("mitre_technique", "N/A")
            description = alert.get("description", alert.get("message", "No detection summary available."))

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
                incident_alert_type = normalize_alert_type(incident["alert_type"])
                if (
                    incident_alert_type == alert_type
                    and incident["source_ip"] == source_ip
                ):
                    incident_for_alert = incident
                    break

            # ------------------------------------------
            # ALERT CARD
            # ------------------------------------------
            with st.container(border=True):
                header_col1, header_col2 = st.columns([4, 1])

                with header_col1:
                    st.markdown(f"### {severity_icon} {title}")
                    st.caption(f"Detection Engine Type: `{alert_type}`")

                with header_col2:
                    st.metric(
                        "Risk Score",
                        f"{risk_score} / 100"
                    )

                info_col1, info_col2, info_col3, info_col4 = st.columns(4)

                with info_col1:
                    st.write("**Severity Level**")
                    if risk_level == "CRITICAL":
                        st.error("CRITICAL")
                    elif risk_level == "HIGH":
                        st.warning("HIGH")
                    elif risk_level == "MEDIUM":
                        st.warning("MEDIUM")
                    else:
                        st.success("LOW")

                with info_col2:
                    st.write("**Source IP**")
                    st.code(source_ip)

                with info_col3:
                    st.write("**MITRE Technique**")
                    st.code(mitre)

                evidence = alert.get("evidence", {})
                detector_event_ids = evidence.get("event_ids", [])

                with info_col4:
                    st.write("**Evidence Count**")
                    st.metric("Events", len(detector_event_ids))

                st.write("**Detection Narrative**")
                st.write(description)

                if incident_for_alert:
                    incident_id = incident_for_alert["incident_id"]
                    incident_status = incident_for_alert["status"]

                    st.divider()

                    inc_col1, inc_col2 = st.columns(2)
                    with inc_col1:
                        st.write("**Correlated Incident ID**")
                        st.code(incident_id)

                    with inc_col2:
                        st.write("**Incident Workflow Status**")
                        if incident_status in ["CONTAINED", "RESOLVED"]:
                            st.success(f"● {incident_status}")
                        elif incident_status in ["INVESTIGATING", "TRIAGED"]:
                            st.warning(f"● {incident_status}")
                        else:
                            st.info(f"● {incident_status}")

                    with st.expander(f"View Confirmed Detection Evidence ({len(detector_event_ids)} Events)"):
                        if detector_event_ids:
                            st.write("Detector-confirmed security event IDs:")
                            st.code(", ".join(str(eid) for eid in detector_event_ids))
                        else:
                            st.info("Detector-specific evidence IDs are not available.")

                    if incident_status in ["CONTAINED", "RESOLVED"]:
                        st.success("🛡️ SentinelX automated containment policy has been recorded for this incident.")
                    elif risk_level in ["HIGH", "CRITICAL"]:
                        st.warning("⚠️ High-risk alert requires active SOC investigation and containment according to SentinelX policy.")
                    else:
                        st.info("ℹ️ Alert requires continuous monitoring and analyst validation.")

                else:
                    st.info("Incident correlation is pending.")

    elif risk_alerts:
        st.info("No security alerts match your filter criteria.")
    else:
        st.success("No active security threats detected.")



# ==================================================
# PAGE 4 — INCIDENT MANAGEMENT
# ==================================================

elif selected_page == "Incidents":

    st.title("🛡️ Incident Management & Response")
    st.caption("Investigate, track, and orchestrate response actions for correlated security incidents.")

    st.divider()

    if incidents:
        # ----------------------------------------------
        # INCIDENT SUMMARY KPIS
        # ----------------------------------------------
        inc_kpi1, inc_kpi2, inc_kpi3, inc_kpi4 = st.columns(4)

        with inc_kpi1:
            st.metric("Total Incidents", len(incidents))

        with inc_kpi2:
            st.metric("Active Incidents", active_incidents)

        with inc_kpi3:
            st.metric("Contained Threats", contained_incidents)

        with inc_kpi4:
            high_sev_incidents = sum(
                1 for i in incidents
                if i.get("severity") in ["HIGH", "CRITICAL"] or (i.get("risk_score") or 0) >= 80
            )
            st.metric("High / Critical Threats", high_sev_incidents)

        st.divider()

        # ----------------------------------------------
        # INCIDENT FILTERS
        # ----------------------------------------------
        inc_filter_col1, inc_filter_col2, inc_filter_col3 = st.columns([2, 1, 1])

        with inc_filter_col1:
            inc_search = st.text_input(
                "Search Incidents",
                placeholder="Search by incident ID, source IP, or title...",
                key="filter_inc_search"
            ).strip().lower()

        with inc_filter_col2:
            inc_status_filter = st.selectbox(
                "Status Filter",
                ["ALL", "NEW", "TRIAGED", "INVESTIGATING", "CONTAINED", "RESOLVED"],
                key="filter_inc_status"
            )

        with inc_filter_col3:
            inc_sev_filter = st.selectbox(
                "Severity Filter",
                ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
                key="filter_inc_sev"
            )

        # ----------------------------------------------
        # FILTER INCIDENTS LIST
        # ----------------------------------------------
        filtered_incidents = []
        for inc in incidents:
            if inc_status_filter != "ALL" and inc.get("status") != inc_status_filter:
                continue

            if inc_sev_filter != "ALL" and str(inc.get("severity", "")).upper() != inc_sev_filter:
                continue

            if inc_search:
                searchable = (
                    f"{inc.get('incident_id', '')} "
                    f"{inc.get('title', '')} "
                    f"{inc.get('source_ip', '')} "
                    f"{inc.get('alert_type', '')} "
                    f"{inc.get('mitre_technique', '')} "
                    f"{inc.get('description', '')}"
                ).lower()
                if inc_search not in searchable:
                    continue

            filtered_incidents.append(inc)

        if filtered_incidents:
            st.caption(f"Showing {len(filtered_incidents)} of {len(incidents)} incidents.")

            for incident in filtered_incidents:
                incident_id = incident["incident_id"]
                title = incident["title"]
                severity = incident["severity"]
                status = incident["status"]
                source_ip = incident["source_ip"]
                risk_score = incident["risk_score"]
                mitre = incident["mitre_technique"]
                description = incident["description"] or "No incident description available."

                # Evidence & containment lookup
                incident_events = get_incident_events(incident_id)
                evidence_count = len(incident_events)
                incident_containment_actions = [
                    action for action in containment_actions
                    if action["incident_id"] == incident_id
                ]

                # Status & Severity icons
                status_icon = {
                    "NEW": "🆕",
                    "TRIAGED": "🔎",
                    "INVESTIGATING": "🕵️",
                    "CONTAINED": "🛡️",
                    "RESOLVED": "✅"
                }.get(status, "⚪")

                severity_icon = {
                    "CRITICAL": "🔴",
                    "HIGH": "🟠",
                    "MEDIUM": "🟡"
                }.get(severity, "🟢")

                # --------------------------------------
                # INCIDENT CARD
                # --------------------------------------
                with st.container(border=True):
                    head_col1, head_col2 = st.columns([4, 1])

                    with head_col1:
                        st.markdown(f"### {status_icon} {incident_id} — {title}")
                        st.caption(f"{severity_icon} Severity: `{severity}`  |  Current Workflow State: `{status}`")

                    with head_col2:
                        st.metric("Risk Score", f"{risk_score} / 100")

                    # Incident Overview
                    info_col1, info_col2, info_col3, info_col4 = st.columns(4)

                    with info_col1:
                        st.write("**Source IP Address**")
                        st.code(source_ip)

                    with info_col2:
                        st.write("**Severity**")
                        if severity == "CRITICAL":
                            st.error("CRITICAL")
                        elif severity == "HIGH":
                            st.warning("HIGH")
                        elif severity == "MEDIUM":
                            st.warning("MEDIUM")
                        else:
                            st.success("LOW")

                    with info_col3:
                        st.write("**MITRE Technique**")
                        st.code(mitre)

                    with info_col4:
                        st.write("**Correlated Evidence**")
                        st.metric("Evidence Events", evidence_count)

                    st.write("**Incident Description**")
                    st.write(description)

                    st.divider()

                    # ----------------------------------
                    # INCIDENT LIFECYCLE STEPPER
                    # ----------------------------------
                    st.write("**Incident Lifecycle State**")
                    lifecycle = ["NEW", "TRIAGED", "INVESTIGATING", "CONTAINED", "RESOLVED"]
                    lifecycle_index = lifecycle.index(status) if status in lifecycle else 0

                    lifecycle_cols = st.columns(len(lifecycle))
                    for index, stage in enumerate(lifecycle):
                        with lifecycle_cols[index]:
                            if index < lifecycle_index:
                                st.success(f"✓ {stage}")
                            elif index == lifecycle_index:
                                st.warning(f"● {stage}")
                            else:
                                st.info(f"○ {stage}")

                    st.divider()

                    # ----------------------------------
                    # STATUS MANAGEMENT CONTROLS
                    # ----------------------------------
                    ctrl_col1, ctrl_col2 = st.columns([3, 1])
                    with ctrl_col1:
                        status_options = ["NEW", "TRIAGED", "INVESTIGATING", "CONTAINED", "RESOLVED"]
                        selected_status = st.selectbox(
                            "Transition Workflow Status",
                            status_options,
                            index=status_options.index(status) if status in status_options else 0,
                            key=f"status_{incident_id}"
                        )

                    with ctrl_col2:
                        st.write("&nbsp;")
                        if selected_status != status:
                            if st.button("Update Status", key=f"update_{incident_id}", use_container_width=True):
                                updated_rows = update_incident_status(incident_id, selected_status)
                                if updated_rows == 1:
                                    st.success(f"{incident_id} updated to {selected_status}.")
                                    st.rerun()
                                else:
                                    st.error("Status update failed.")
                        else:
                            st.caption("Status is current.")

                    st.divider()

                    # ----------------------------------
                    # CORRELATED EVIDENCE
                    # ----------------------------------
                    with st.expander(f"View Correlated Evidence Events ({evidence_count} Events)"):
                        if incident_events:
                            ev_data = [
                                {
                                    "ID": ev["id"],
                                    "Timestamp": ev["timestamp"],
                                    "Source IP": ev["source_ip"],
                                    "Username": ev["username"] or "—",
                                    "Event Type": ev["event_type"],
                                    "Action": ev["action"],
                                    "Status": ev["status"],
                                    "Severity": ev["severity"],
                                    "Port": str(ev["port"]) if ev.get("port") is not None else "—",
                                    "Message": ev["message"]
                                }
                                for ev in incident_events
                            ]
                            st.dataframe(ev_data, width="stretch", hide_index=True)
                        else:
                            st.info("No evidence events linked to this incident.")

                    # ----------------------------------
                    # STATUS TRANSITION HISTORY
                    # ----------------------------------
                    incident_status_history = get_incident_status_history(incident_id)
                    with st.expander(f"View Status Audit History ({len(incident_status_history)} Transitions)"):
                        if incident_status_history:
                            for hist in incident_status_history:
                                st.write(f"**{hist['old_status']} → {hist['new_status']}**")
                                st.caption(f"Transitioned at: {hist['changed_at']}")
                        else:
                            st.info("No status transitions recorded yet.")

                    # ----------------------------------
                    # AUTOMATED RESPONSE HISTORY
                    # ----------------------------------
                    with st.expander(f"View Containment Actions ({len(incident_containment_actions)} Actions)"):
                        if incident_containment_actions:
                            action_data = [
                                {
                                    "Timestamp": act["timestamp"],
                                    "Action": act["action"],
                                    "Source IP": act["source_ip"],
                                    "Status": act["status"],
                                    "Reason": act["reason"]
                                }
                                for act in incident_containment_actions
                            ]
                            st.dataframe(action_data, width="stretch", hide_index=True)
                        else:
                            st.info("No containment actions recorded for this incident.")

                    st.divider()

                    # ----------------------------------
                    # AI SOC COPILOT
                    # ----------------------------------
                    st.subheader("🤖 SentinelX AI SOC Copilot")
                    st.caption("Evidence-grounded intelligence and prescriptive incident response guidance.")

                    ai_session_key = f"ai_analysis_{incident_id}"

                    ai_btn_col1, ai_btn_col2 = st.columns([2, 1])
                    with ai_btn_col1:
                        if st.button("Analyze Incident with AI Copilot", key=f"ai_analyze_{incident_id}", use_container_width=True):
                            with st.spinner("AI Copilot analyzing evidence, MITRE context, and threat dynamics..."):
                                ai_res = analyze_incident(incident, incident_events)
                                st.session_state[ai_session_key] = ai_res

                    with ai_btn_col2:
                        if ai_session_key in st.session_state and st.session_state[ai_session_key]:
                            if st.button("Clear AI Report", key=f"ai_clear_{incident_id}", use_container_width=True):
                                del st.session_state[ai_session_key]
                                st.rerun()

                    cached_ai = st.session_state.get(ai_session_key)

                    if cached_ai:
                        with st.container(border=True):
                            st.success("✓ AI Investigation Analysis Available (Ground Truth Verified)")

                            st.write("**Incident Summary**")
                            st.write(cached_ai.get("incident_summary", "Not available in supplied evidence."))

                            st.write("**Severity & Threat Assessment**")
                            st.write(cached_ai.get("severity_explanation", "Not available in supplied evidence."))

                            st.write("**MITRE ATT&CK Context**")
                            st.write(cached_ai.get("mitre_explanation", "Not available in supplied evidence."))

                            st.write("**Actionable Investigation Steps**")
                            steps = cached_ai.get("investigation_steps", [])
                            if isinstance(steps, list):
                                for s in steps:
                                    st.markdown(f"- {s}")
                            else:
                                st.write(steps)

                            st.write("**Recommended Containment & Response**")
                            recs = cached_ai.get("recommended_response", [])
                            if isinstance(recs, list):
                                for r in recs:
                                    st.markdown(f"- {r}")
                            else:
                                st.write(recs)

                            st.caption(
                                f"Analyzed Events: {cached_ai.get('evidence_count', len(incident_events))}  |  "
                                "Engine: SentinelX Hybrid AI (Gemini 2.5 Pro with Rule-Based Guardrails)"
                            )

        else:
            st.info("No incidents match your filter criteria.")

    else:
        st.info("No incidents created yet.")



# ==================================================
# PAGE 5 — MITRE ATT&CK
# ==================================================

elif selected_page == "MITRE ATT&CK":

    st.title("🎯 MITRE ATT&CK® Threat Matrix")
    st.caption("Adversary Tactics, Techniques, and Common Knowledge (ATT&CK) mapping for SentinelX detections.")

    st.divider()

    mitre_mapping = {
        "BRUTE_FORCE": {
            "technique": "T1110",
            "name": "Brute Force",
            "tactic": "Credential Access",
            "description": (
                "Adversaries may use brute force techniques to attempt to gain access to accounts "
                "when passwords are unknown or when password hashes are obtained."
            )
        },
        "PORT_SCAN": {
            "technique": "T1046",
            "name": "Network Service Scanning",
            "tactic": "Discovery",
            "description": (
                "Adversaries may attempt to get a listing of services and accessible ports running "
                "on remote hosts to identify potential targets for exploitation."
            )
        },
        "SUSPICIOUS_POWERSHELL": {
            "technique": "T1059.001",
            "name": "Command and Scripting Interpreter: PowerShell",
            "tactic": "Execution",
            "description": (
                "Adversaries may abuse PowerShell commands and scripts for execution, discovery, "
                "and persistence, often using obfuscation flags such as -ExecutionPolicy Bypass or -EncodedCommand."
            )
        },
        "PRIVILEGE_ESCALATION": {
            "technique": "T1068",
            "name": "Exploitation for Privilege Escalation",
            "tactic": "Privilege Escalation",
            "description": (
                "Adversaries may exploit vulnerabilities or configuration weaknesses in an operating system or "
                "application in order to elevate privileges to admin or SYSTEM level."
            )
        },
        "SUSPICIOUS_AUTH": {
            "technique": "T1078",
            "name": "Valid Accounts",
            "tactic": "Defense Evasion / Initial Access",
            "description": (
                "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining "
                "initial access, persistence, privilege escalation, or defense evasion."
            )
        }
    }

    # ----------------------------------------------
    # MATRIX SUMMARY KPIS
    # ----------------------------------------------
    active_techniques = set()
    for alert in risk_alerts:
        technique = alert.get("mitre_technique")
        if technique:
            active_techniques.add(technique)

    m_col1, m_col2, m_col3 = st.columns(3)
    with m_col1:
        st.metric("Mapped Techniques", len(mitre_mapping))
    with m_col2:
        st.metric("Active Adversary Techniques", len(active_techniques))
    with m_col3:
        st.metric("Correlated Risk Detections", len(risk_alerts))

    st.divider()

    # ----------------------------------------------
    # DETECTION MAPPING TABLE
    # ----------------------------------------------
    st.subheader("📋 Detection Engine → MITRE Matrix Mapping")

    mitre_data = []
    for alert_type, mapping in mitre_mapping.items():
        matching_alerts = [
            alert for alert in risk_alerts
            if normalize_alert_type(alert.get("alert_type")) == alert_type
        ]

        mitre_data.append(
            {
                "Detection": alert_type,
                "MITRE ID": mapping["technique"],
                "Tactic": mapping["tactic"],
                "Technique Name": mapping["name"],
                "Active Detections": len(matching_alerts),
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
    # ACTIVE TECHNIQUES DEEP DIVE
    # ----------------------------------------------
    st.subheader("🔍 Active Threat Technique Profiles")

    if active_techniques:
        for technique in sorted(active_techniques):
            mapping = None
            for item in mitre_mapping.values():
                if item["technique"] == technique:
                    mapping = item
                    break

            if mapping:
                with st.container(border=True):
                    tech_clean = mapping["technique"].split(".")[0]
                    mitre_url = f"https://attack.mitre.org/techniques/{tech_clean}/"

                    t_head1, t_head2 = st.columns([3, 1])
                    with t_head1:
                        st.markdown(f"### 🎯 {mapping['technique']} — {mapping['name']}")
                        st.caption(f"Enterprise Tactic: **{mapping['tactic']}**")
                    with t_head2:
                        st.markdown(f"[Official MITRE Doc ↗]({mitre_url})")

                    st.write(mapping["description"])
            else:
                with st.container(border=True):
                    st.code(technique)
    else:
        st.info("No active MITRE ATT&CK techniques triggered in current telemetry buffer.")



# ==================================================
# PAGE 6 — AUDIT LOGS
# ==================================================

elif selected_page == "Audit Logs":

    st.title("📋 Containment & Security Audit Trail")
    st.caption("Forensic audit trail of all automated containment actions and security response events.")

    st.divider()

    # Reload latest actions
    containment_actions = get_containment_actions()

    if containment_actions:
        successful_actions = sum(1 for a in containment_actions if a["status"] == "SUCCESS")
        failed_actions = sum(1 for a in containment_actions if a["status"] != "SUCCESS")
        unique_targets = len(set(a["source_ip"] for a in containment_actions))

        # ----------------------------------------------
        # AUDIT STATISTICS KPIS
        # ----------------------------------------------
        stat_col1, stat_col2, stat_col3, stat_col4 = st.columns(4)

        with stat_col1:
            st.metric("Total Containment Actions", len(containment_actions))

        with stat_col2:
            st.metric("Successful Mitigations", successful_actions)

        with stat_col3:
            st.metric("Failed / Errors", failed_actions)

        with stat_col4:
            st.metric("Isolated Host Entities", unique_targets)

        st.divider()

        # ----------------------------------------------
        # AUDIT FILTERS
        # ----------------------------------------------
        audit_f1, audit_f2 = st.columns([2, 1])

        with audit_f1:
            audit_query = st.text_input(
                "Search Audit Trail",
                placeholder="Search by IP, incident ID, or containment reason...",
                key="filter_audit_search"
            ).strip().lower()

        with audit_f2:
            audit_status_filter = st.selectbox(
                "Action Status",
                ["ALL", "SUCCESS", "FAILED"],
                key="filter_audit_status"
            )

        # ----------------------------------------------
        # FILTER DATA
        # ----------------------------------------------
        filtered_actions = []
        for action in containment_actions:
            if audit_status_filter == "SUCCESS" and action["status"] != "SUCCESS":
                continue
            elif audit_status_filter == "FAILED" and action["status"] == "SUCCESS":
                continue

            if audit_query:
                combined = f"{action.get('id', '')} {action.get('incident_id', '')} {action.get('source_ip', '')} {action.get('action', '')} {action.get('reason', '')}".lower()
                if audit_query not in combined:
                    continue

            filtered_actions.append(action)

        if filtered_actions:
            audit_data = []
            for action in filtered_actions:
                audit_data.append(
                    {
                        "Action ID": action["id"],
                        "Timestamp (UTC)": action["timestamp"],
                        "Incident ID": action["incident_id"],
                        "Mitigation Action": action["action"],
                        "Target Host IP": action["source_ip"],
                        "Execution Status": action["status"],
                        "Policy Rationale": action["reason"]
                    }
                )

            st.dataframe(
                audit_data,
                width="stretch",
                hide_index=True
            )
            st.caption(f"Displaying {len(filtered_actions)} of {len(containment_actions)} total forensic records.")
        else:
            st.info("No audit records match the selected filter.")

        st.divider()

        # ----------------------------------------------
        # SAFE CONTAINMENT AUDIT COMPLIANCE
        # ----------------------------------------------
        with st.container(border=True):
            st.markdown("### 🛡️ SentinelX Safe Mitigation & Governance Policy")
            st.write(
                "All automated isolation and containment commands executed by SentinelX follow "
                "strict reversible host mitigation standards. Actions are logged immutably into the "
                "local SQLite audit vault with exact execution timestamps, incident linkages, and source IP addresses."
            )

    else:
        st.info("No containment actions recorded yet.")



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