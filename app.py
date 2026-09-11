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
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px;">
                <div>
                    <div class="sx-top-nav-kicker">SENTINELX • SECURITY OPERATIONS CENTER</div>
                    <div style="font-size:1.5rem; font-weight:800; color:#E7EEF2; margin-top:2px;">Autonomous Threat Command Center</div>
                    <div style="color:#91A4B0; font-size:0.88rem; margin-top:2px;">Detect → Prioritize → Investigate → Contain</div>
                </div>
                <div style="text-align:right;">
                    <span style="color:#4FD39A; font-weight:800; font-size:0.75rem; letter-spacing:1px;">● SOC ENGINE ACTIVE</span>
                    <div style="color:#91A4B0; font-size:0.78rem;">AI-assisted security monitoring</div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.divider()


    # ----------------------------------------------
    # TOP METRICS
    # ----------------------------------------------

    col1, col2, col3, col4 = st.columns(
        4
    )

    with col1:

        st.metric(
            "Security Events",
            total_events
        )

    with col2:

        st.metric(
            "High Alerts",
            high_alerts
        )

    with col3:

        st.metric(
            "Active Incidents",
            active_incidents
        )

    with col4:

        st.metric(
            "Contained",
            contained_incidents
        )


    # ----------------------------------------------
    # SECURITY POSTURE
    # ----------------------------------------------

    st.divider()

    st.subheader(
        "Security Posture"
    )

    posture_col1, posture_col2 = st.columns(
        [1, 3]
    )

    with posture_col1:

        st.metric(
            "Posture Score",
            f"{posture_score}/100"
        )

    with posture_col2:

        if posture_label in [
            "EXCELLENT",
            "GOOD"
        ]:

            st.success(
                f"Security Posture: {posture_label}"
            )

        elif posture_label in [
            "MODERATE",
            "POOR"
        ]:

            st.warning(
                f"Security Posture: {posture_label}"
            )

        else:

            st.error(
                f"Security Posture: {posture_label}"
            )


    st.caption(
        f"Active threats: "
        f"{posture['details']['active_incidents']} | "
        f"High/Critical active: "
        f"{posture['details']['high_critical_incidents']} | "
        f"Contained: "
        f"{posture['details']['contained_incidents']} | "
        f"Resolved: "
        f"{posture['details']['resolved_incidents']}"
    )


    # ----------------------------------------------
    # THREAT OVERVIEW
    # ----------------------------------------------

    st.divider()

    st.subheader(
        "Threat Overview"
    )

    summary_col1, summary_col2, summary_col3 = (
        st.columns(3)
    )

    with summary_col1:

        st.metric(
            "Total Alerts",
            len(risk_alerts)
        )

    with summary_col2:

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

    with summary_col3:

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


    # ----------------------------------------------
    # ENGINE STATUS
    # ----------------------------------------------

    st.divider()

    st.subheader(
        "SentinelX Engine Status"
    )

    status_col1, status_col2, status_col3 = (
        st.columns(3)
    )

    with status_col1:

        st.success(
            "Detection Engine ONLINE"
        )

    with status_col2:

        st.success(
            "Risk Engine ONLINE"
        )

    with status_col3:

        st.success(
            "SQLite Database CONNECTED"
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

                st.divider()


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