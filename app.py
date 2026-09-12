import json
from datetime import datetime

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

from services.ai_copilot import (
    analyze_incident,
    extract_incident_iocs,
    build_incident_timeline
)
from services.forensics import (
    generate_forensic_dossier_json,
    generate_forensic_dossier_markdown
)
from services.auth import (
    init_auth_table,
    authenticate_user
)

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
    unblock_source_ip,
    is_source_blocked,
    get_blocked_sources,
    get_containment_actions,
    get_source_containment_details,
    verify_source_containment,
)

from simulator.event_generator import simulate_brute_force
from simulator.port_scan_simulator import simulate_port_scan
from simulator.suspicious_auth_simulator import (
    simulate_suspicious_authentication
)
from simulator.privilege_escalation_simulator import (
    generate_privilege_escalation_events
)
from simulator.suspicious_powershell_simulator import (
    generate_suspicious_powershell_events
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
        --sx-bg: #090D16;
        --sx-panel: #0E1726;
        --sx-panel-2: #142032;
        --sx-surface: #19273C;
        --sx-border: #1E2E44;
        --sx-border-light: rgba(30, 46, 68, 0.7);
        --sx-text: #F1F5F9;
        --sx-muted: #94A3B8;
        --sx-dim: #64748B;
        --sx-accent: #38BDF8;
        --sx-secondary: #6366F1;
        --sx-critical: #EF4444;
        --sx-high: #F97316;
        --sx-medium: #FBBF24;
        --sx-low: #38BDF8;
        --sx-success: #10B981;
    }

    /* Global Application Shell */
    [data-testid="stAppViewContainer"] {
        background: #090D16 !important;
        color: #F1F5F9 !important;
    }

    [data-testid="stHeader"] {
        background: rgba(9, 13, 22, 0.95) !important;
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
        padding: 10px 20px 28px !important;
        color: #F1F5F9 !important;
    }

    /* Typography Hierarchy */
    h1, h2, h3, h4, h5, h6 {
        color: #F1F5F9 !important;
        font-weight: 700 !important;
        letter-spacing: -0.2px !important;
    }

    h1 {
        font-size: 1.35rem !important;
        margin-bottom: 2px !important;
    }

    h2, h3 {
        font-size: 1.10rem !important;
        margin-top: 6px !important;
        margin-bottom: 4px !important;
    }

    .stCaption, p, span, label, [data-testid="stMarkdownContainer"] p {
        color: #F1F5F9;
    }

    .stCaption {
        color: #94A3B8 !important;
        font-size: 0.78rem !important;
    }

    hr {
        border-color: #1E2E44 !important;
        opacity: 0.6 !important;
        margin: 12px 0 !important;
    }

    /* Top Command Header & Brand Lockup */
    .sx-top-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 16px;
        padding: 10px 18px;
        margin-bottom: 10px;
        border-radius: 6px;
        background: #0E1726 !important;
        border: 1px solid #1E2E44 !important;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.25);
    }

    .sx-brand-wrapper {
        display: flex;
        align-items: center;
        gap: 14px;
    }

    .sx-brand-text {
        display: flex;
        flex-direction: column;
        gap: 1px;
    }

    .sx-brand-title {
        font-size: 1.30rem;
        font-weight: 900;
        letter-spacing: 1.8px;
        color: #F8FAFC;
        line-height: 1.1;
    }

    .sx-brand-sub {
        font-size: 0.62rem;
        font-weight: 700;
        letter-spacing: 1.2px;
        color: #94A3B8;
        text-transform: uppercase;
    }

    .sx-chips-row {
        display: flex;
        align-items: center;
        gap: 6px;
        flex-wrap: wrap;
    }

    .sx-chip {
        display: inline-flex;
        align-items: center;
        gap: 5px;
        padding: 2px 7px;
        border-radius: 3px;
        font-size: 0.60rem;
        font-weight: 700;
        letter-spacing: 0.6px;
        text-transform: uppercase;
    }

    .sx-chip-green {
        background: rgba(16, 185, 129, 0.10);
        border: 1px solid rgba(16, 185, 129, 0.30);
        color: #10B981;
    }

    .sx-chip-indigo {
        background: rgba(99, 102, 241, 0.10);
        border: 1px solid rgba(99, 102, 241, 0.30);
        color: #818CF8;
    }

    .sx-chip-cyan {
        background: rgba(56, 189, 248, 0.10);
        border: 1px solid rgba(56, 189, 248, 0.30);
        color: #38BDF8;
    }

    .sx-chip-dot {
        width: 5px;
        height: 5px;
        border-radius: 50%;
        display: inline-block;
    }

    .sx-dot-green { background: #10B981; }
    .sx-dot-indigo { background: #818CF8; }
    .sx-dot-cyan { background: #38BDF8; }

    .sx-top-status-right {
        display: flex;
        flex-direction: column;
        align-items: flex-end;
        gap: 3px;
        text-align: right;
    }

    /* Operations Briefing Bar */
    .sx-briefing-bar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        background: #0E1726;
        border: 1px solid #1E2E44;
        border-left: 3px solid #38BDF8;
        border-radius: 6px;
        padding: 8px 14px;
        margin-bottom: 12px;
    }

    .sx-briefing-left {
        display: flex;
        align-items: center;
        gap: 8px;
        flex-wrap: wrap;
    }

    .sx-pulse-dot {
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background: #10B981;
        box-shadow: 0 0 6px #10B981;
        display: inline-block;
    }

    .sx-briefing-title {
        font-size: 0.70rem;
        font-weight: 800;
        letter-spacing: 0.6px;
        color: #F1F5F9;
        text-transform: uppercase;
    }

    .sx-briefing-divider {
        color: #38BDF8;
        font-size: 0.75rem;
    }

    .sx-briefing-text {
        color: #94A3B8;
        font-size: 0.78rem;
    }

    .sx-briefing-right {
        display: flex;
        align-items: center;
        gap: 6px;
        flex-wrap: wrap;
    }

    /* Enterprise Custom KPI Cards (Compact & Crisp) */
    .sx-kpi-card {
        background: #0E1726;
        border: 1px solid #1E2E44;
        border-radius: 6px;
        padding: 10px 14px;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        min-height: 92px;
        box-shadow: 0 2px 6px rgba(0, 0, 0, 0.2);
        transition: border-color 0.15s ease;
    }

    .sx-kpi-card:hover {
        border-color: #2D486B;
    }

    .sx-kpi-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 2px;
    }

    .sx-kpi-label {
        color: #94A3B8;
        font-size: 0.64rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.7px;
    }

    .sx-kpi-icon {
        width: 22px;
        height: 22px;
        border-radius: 4px;
        display: flex;
        align-items: center;
        justify-content: center;
    }

    .sx-kpi-value {
        font-size: 1.65rem;
        font-weight: 800;
        line-height: 1.1;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        margin: 2px 0;
    }

    .sx-kpi-meta {
        color: #64748B;
        font-size: 0.68rem;
        margin-top: 2px;
        display: flex;
        align-items: center;
        gap: 5px;
    }

    /* Visual SOC Pipeline Flow */
    .sx-pipeline-row {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 3px;
        overflow-x: auto;
        padding: 2px 0;
    }

    .sx-pipe-box {
        flex: 1;
        min-width: 82px;
        background: #142032;
        border: 1px solid #1E2E44;
        border-radius: 5px;
        padding: 6px 4px;
        text-align: center;
        transition: border-color 0.15s ease, background 0.15s ease;
    }

    .sx-pipe-box:hover {
        border-color: #38BDF8;
        background: #19273C;
    }

    .sx-pipe-step {
        font-size: 0.58rem;
        font-weight: 800;
        color: #38BDF8;
        font-family: ui-monospace, monospace;
        letter-spacing: 0.4px;
    }

    .sx-pipe-title {
        font-size: 0.68rem;
        font-weight: 700;
        color: #F1F5F9;
        margin: 1px 0;
        white-space: nowrap;
    }

    .sx-pipe-sub {
        font-size: 0.56rem;
        color: #64748B;
        white-space: nowrap;
    }

    .sx-pipe-arrow {
        color: #38BDF8;
        font-size: 0.66rem;
        font-weight: 700;
        opacity: 0.6;
        user-select: none;
        padding: 0 1px;
    }

    /* Panels & Containers */
    .sx-panel {
        background: #0E1726 !important;
        border: 1px solid #1E2E44 !important;
        border-radius: 6px;
        padding: 12px 16px;
        margin-bottom: 10px;
        box-shadow: 0 2px 6px rgba(0, 0, 0, 0.2);
    }

    [data-testid="stVerticalBlockBorderWrapper"] > div {
        background: #0E1726 !important;
        border: 1px solid #1E2E44 !important;
        border-radius: 6px !important;
        padding: 14px 16px !important;
        margin-bottom: 10px !important;
        box-shadow: 0 2px 6px rgba(0, 0, 0, 0.18) !important;
    }

    /* Buttons */
    .stButton > button,
    .stDownloadButton > button {
        background: #142032 !important;
        color: #94A3B8 !important;
        border: 1px solid #1E2E44 !important;
        border-radius: 5px !important;
        padding: 6px 12px !important;
        font-weight: 600 !important;
        font-size: 0.80rem !important;
        letter-spacing: 0.2px !important;
        transition: border-color 0.15s ease, color 0.15s ease, background 0.15s ease, box-shadow 0.15s ease !important;
    }

    .stButton > button:hover,
    .stDownloadButton > button:hover {
        background: #19273C !important;
        border-color: #38BDF8 !important;
        color: #F8FAFC !important;
        box-shadow: 0 0 10px rgba(56, 189, 248, 0.18) !important;
    }

    .stButton > button[kind="primary"],
    .stDownloadButton > button[kind="primary"],
    [data-testid="baseButton-primary"] {
        background: #0F2942 !important;
        border: 1px solid #38BDF8 !important;
        color: #38BDF8 !important;
        font-weight: 700 !important;
        box-shadow: 0 0 12px rgba(56, 189, 248, 0.25) !important;
    }

    /* Native Streamlit Metric Cards */
    [data-testid="stMetric"], .stMetric {
        background: #0E1726 !important;
        border: 1px solid #1E2E44 !important;
        border-radius: 5px !important;
        padding: 8px 12px !important;
        box-shadow: 0 1px 4px rgba(0, 0, 0, 0.15) !important;
    }

    [data-testid="stMetric"]:hover {
        border-color: #27405F !important;
    }

    [data-testid="stMetricLabel"] p {
        color: #94A3B8 !important;
        font-size: 0.66rem !important;
        font-weight: 700 !important;
        text-transform: uppercase !important;
        letter-spacing: 0.8px !important;
    }

    [data-testid="stMetricValue"] {
        color: #F1F5F9 !important;
        font-size: 1.55rem !important;
        font-weight: 800 !important;
        letter-spacing: -0.3px !important;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace !important;
    }

    /* High-Density DataFrames & Tables */
    [data-testid="stDataFrame"], [data-testid="stTable"] {
        border: 1px solid #1E2E44 !important;
        border-radius: 6px !important;
        background: #0E1726 !important;
        overflow: hidden !important;
    }

    div[data-testid="stDataFrame"] > div {
        background: #0E1726 !important;
    }

    table {
        background: #0E1726 !important;
        color: #F1F5F9 !important;
        border-collapse: collapse !important;
        width: 100% !important;
    }

    th {
        background: #142032 !important;
        color: #94A3B8 !important;
        font-size: 0.70rem !important;
        font-weight: 700 !important;
        text-transform: uppercase !important;
        letter-spacing: 0.7px !important;
        padding: 7px 10px !important;
        border-bottom: 1px solid #1E2E44 !important;
    }

    td {
        padding: 6px 10px !important;
        border-bottom: 1px solid rgba(30, 46, 68, 0.5) !important;
        font-size: 0.80rem !important;
        color: #F1F5F9 !important;
    }

    tr:hover td {
        background: #142032 !important;
    }

    /* Expanders */
    [data-testid="stExpander"] {
        background: #0E1726 !important;
        border: 1px solid #1E2E44 !important;
        border-radius: 5px !important;
        margin-bottom: 8px !important;
        overflow: hidden !important;
    }

    [data-testid="stExpander"] summary {
        color: #F1F5F9 !important;
        font-weight: 600 !important;
        font-size: 0.82rem !important;
        padding: 7px 12px !important;
    }

    [data-testid="stExpander"] summary:hover {
        color: #38BDF8 !important;
        background: #142032 !important;
    }

    [data-testid="stExpander"] summary svg {
        fill: #94A3B8 !important;
    }

    [data-testid="stExpander"] [data-testid="stExpanderDetails"] {
        padding: 10px 14px !important;
        border-top: 1px solid #1E2E44 !important;
    }

    /* Form Controls & Inputs */
    .stSelectbox label, .stTextInput label {
        color: #94A3B8 !important;
        font-size: 0.68rem !important;
        font-weight: 700 !important;
        text-transform: uppercase !important;
        letter-spacing: 0.7px !important;
    }

    .stSelectbox div[data-baseweb="select"] > div,
    .stTextInput div[data-baseweb="input"] {
        background: #142032 !important;
        border: 1px solid #1E2E44 !important;
        border-radius: 5px !important;
        color: #F1F5F9 !important;
        font-size: 0.82rem !important;
    }

    .stSelectbox div[data-baseweb="select"]:hover > div,
    .stTextInput div[data-baseweb="input"]:focus-within {
        border-color: #38BDF8 !important;
    }

    div[data-baseweb="popover"],
    ul[role="listbox"] {
        background: #0E1726 !important;
        border: 1px solid #1E2E44 !important;
        color: #F1F5F9 !important;
    }

    li[role="option"] {
        color: #F1F5F9 !important;
        font-size: 0.82rem !important;
    }

    li[role="option"]:hover,
    li[aria-selected="true"] {
        background: #142032 !important;
        color: #38BDF8 !important;
    }

    /* Tabs */
    [data-testid="stTabs"] [data-baseweb="tab-list"] {
        background: #0E1726 !important;
        border-bottom: 1px solid #1E2E44 !important;
        gap: 8px !important;
    }

    [data-testid="stTabs"] [data-baseweb="tab"] {
        color: #94A3B8 !important;
        font-weight: 600 !important;
        font-size: 0.82rem !important;
        padding: 8px 14px !important;
        background: transparent !important;
        border: none !important;
    }

    [data-testid="stTabs"] [data-baseweb="tab"]:hover {
        color: #38BDF8 !important;
    }

    [data-testid="stTabs"] [aria-selected="true"] {
        color: #38BDF8 !important;
        border-bottom: 2px solid #38BDF8 !important;
    }

    [data-testid="stTabs"] [data-baseweb="tab-highlight"] {
        background-color: #38BDF8 !important;
    }

    /* Text Area */
    .stTextArea textarea {
        background: #142032 !important;
        border: 1px solid #1E2E44 !important;
        border-radius: 5px !important;
        color: #F8FAFC !important;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace !important;
        font-size: 0.80rem !important;
    }

    .stTextArea textarea:focus {
        border-color: #38BDF8 !important;
        box-shadow: 0 0 8px rgba(56, 189, 248, 0.22) !important;
    }

    /* Alerts */
    .stAlert, [data-testid="stAlert"] {
        border-radius: 5px !important;
        border-width: 1px !important;
        font-weight: 600 !important;
        font-size: 0.80rem !important;
        padding: 7px 10px !important;
    }

    [data-testid="stAlert"]:has([data-testid="stNotificationContentSuccess"]),
    div[data-baseweb="notification"]:has([aria-label="Success"]) {
        background: rgba(16, 185, 129, 0.10) !important;
        border: 1px solid rgba(16, 185, 129, 0.30) !important;
        color: #10B981 !important;
    }

    [data-testid="stAlert"]:has([data-testid="stNotificationContentWarning"]),
    div[data-baseweb="notification"]:has([aria-label="Warning"]) {
        background: rgba(249, 115, 22, 0.10) !important;
        border: 1px solid rgba(249, 115, 22, 0.30) !important;
        color: #F97316 !important;
    }

    [data-testid="stAlert"]:has([data-testid="stNotificationContentError"]),
    div[data-baseweb="notification"]:has([aria-label="Error"]) {
        background: rgba(239, 68, 68, 0.10) !important;
        border: 1px solid rgba(239, 68, 68, 0.30) !important;
        color: #EF4444 !important;
    }

    [data-testid="stAlert"]:has([data-testid="stNotificationContentInfo"]),
    div[data-baseweb="notification"]:has([aria-label="Info"]) {
        background: rgba(56, 189, 248, 0.08) !important;
        border: 1px solid rgba(56, 189, 248, 0.25) !important;
        color: #38BDF8 !important;
    }

    /* Monospace Code Blocks */
    code, pre, [data-testid="stCodeBlock"] {
        background: #142032 !important;
        color: #38BDF8 !important;
        border: 1px solid #1E2E44 !important;
        border-radius: 4px !important;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace !important;
        font-size: 0.80rem !important;
    }

    /* Semantic Badges */
    .sx-badge {
        display: inline-flex;
        align-items: center;
        gap: 5px;
        padding: 2px 7px;
        border-radius: 3px;
        font-size: 0.66rem;
        font-weight: 700;
        letter-spacing: 0.5px;
        text-transform: uppercase;
    }

    .sx-badge-critical { background: rgba(239, 68, 68, 0.14); color: #EF4444; border: 1px solid rgba(239, 68, 68, 0.35); }
    .sx-badge-high { background: rgba(249, 115, 22, 0.14); color: #F97316; border: 1px solid rgba(249, 115, 22, 0.35); }
    .sx-badge-medium { background: rgba(251, 191, 36, 0.14); color: #FBBF24; border: 1px solid rgba(251, 191, 36, 0.35); }
    .sx-badge-low { background: rgba(56, 189, 248, 0.14); color: #38BDF8; border: 1px solid rgba(56, 189, 248, 0.35); }
    .sx-badge-success { background: rgba(16, 185, 129, 0.14); color: #10B981; border: 1px solid rgba(16, 185, 129, 0.35); }

    /* Health Cards Grid */
    .sx-health-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
        gap: 10px;
        margin-top: 6px;
    }

    .sx-health-card {
        background: #0E1726;
        border: 1px solid #1E2E44;
        border-radius: 5px;
        padding: 10px 14px;
        display: flex;
        align-items: center;
        gap: 10px;
    }

    .sx-health-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: #10B981;
        box-shadow: 0 0 6px rgba(16, 185, 129, 0.6);
        flex-shrink: 0;
    }

    .sx-health-name {
        font-size: 0.70rem;
        font-weight: 700;
        color: #F1F5F9;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    .sx-health-status {
        font-size: 0.64rem;
        color: #10B981;
        font-weight: 600;
        font-family: ui-monospace, monospace;
    }

    /* Empty States */
    .sx-empty-card {
        background: #0E1726;
        border: 1px dashed #1E2E44;
        border-radius: 6px;
        padding: 32px 20px;
        text-align: center;
        margin: 12px 0;
    }

    .sx-empty-icon {
        font-size: 1.8rem;
        margin-bottom: 6px;
        opacity: 0.8;
    }

    .sx-empty-title {
        font-size: 0.90rem;
        font-weight: 700;
        color: #F1F5F9;
        margin-bottom: 4px;
    }

    .sx-empty-desc {
        font-size: 0.76rem;
        color: #94A3B8;
        max-width: 460px;
        margin: 0 auto;
    }

    /* Stepper */
    .sx-stepper {
        display: flex;
        align-items: center;
        gap: 6px;
        margin: 6px 0 12px;
        overflow-x: auto;
        padding-bottom: 2px;
    }

    .sx-step {
        flex: 1;
        min-width: 85px;
        padding: 6px 8px;
        border-radius: 5px;
        text-align: center;
        font-size: 0.70rem;
        font-weight: 700;
        letter-spacing: 0.4px;
        background: #142032;
        border: 1px solid #1E2E44;
        color: #64748B;
        transition: all 0.15s ease;
    }

    .sx-step-completed {
        background: rgba(16, 185, 129, 0.10);
        border: 1px solid rgba(16, 185, 129, 0.35);
        color: #10B981;
    }

    .sx-step-current {
        background: rgba(56, 189, 248, 0.16);
        border: 1px solid #38BDF8;
        color: #38BDF8;
        font-weight: 800;
        box-shadow: 0 0 8px rgba(56, 189, 248, 0.25);
    }

    .sx-stepper-sep {
        color: #2D486B;
        font-weight: bold;
        font-size: 0.75rem;
        user-select: none;
    }

    /* AI Copilot Investigation Report */
    .sx-ai-report {
        background: #0E1726;
        border: 1px solid #1E2E44;
        border-top: 3px solid #6366F1;
        border-radius: 6px;
        padding: 16px 18px;
        margin-top: 10px;
    }

    .sx-ai-banner {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding-bottom: 10px;
        margin-bottom: 12px;
        border-bottom: 1px solid #1E2E44;
        flex-wrap: wrap;
        gap: 8px;
    }

    .sx-ai-section-title {
        font-size: 0.74rem;
        font-weight: 800;
        color: #38BDF8;
        text-transform: uppercase;
        letter-spacing: 0.6px;
        margin-top: 10px;
        margin-bottom: 5px;
        display: flex;
        align-items: center;
        gap: 6px;
    }

    .sx-ai-text {
        color: #F1F5F9;
        font-size: 0.82rem;
        line-height: 1.5;
        background: #142032;
        border: 1px solid #1E2E44;
        border-radius: 5px;
        padding: 8px 12px;
        margin-bottom: 8px;
    }

    /* Clean Scrollbars */
    ::-webkit-scrollbar { width: 5px; height: 5px; }
    ::-webkit-scrollbar-track { background: #090D16; }
    ::-webkit-scrollbar-thumb { background: #1E2E44; border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: #38BDF8; }
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
init_auth_table()


# ==================================================
# AUTHENTICATION & MULTI-USER SESSION GATE
# ==================================================

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "current_user" not in st.session_state:
    st.session_state.current_user = None

if not st.session_state.authenticated:
    st.markdown(
        """
        <div style="max-width: 480px; margin: 30px auto 14px; text-align: center;">
            <div class="sx-brand-wrapper" style="justify-content: center; margin-bottom: 10px;">
                <svg width="56" height="56" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M24 3.5L7 10.5V22C7 33.2 14.3 43.5 24 46C33.7 43.5 41 33.2 41 22V10.5L24 3.5Z" stroke="#38BDF8" stroke-width="2.4" stroke-linejoin="round" fill="rgba(56, 189, 248, 0.08)"/>
                    <path d="M24 8L11.5 13.8V22C11.5 30.5 16.8 38.3 24 40.8C31.2 38.3 36.5 30.5 36.5 22V13.8L24 8Z" stroke="rgba(99, 102, 241, 0.5)" stroke-width="1.5" stroke-linejoin="round" fill="none"/>
                    <path d="M16.5 17.5L31.5 30.5M31.5 17.5L16.5 30.5" stroke="#38BDF8" stroke-width="2.8" stroke-linecap="round"/>
                    <circle cx="24" cy="24" r="3.2" fill="#38BDF8" stroke="#0A111C" stroke-width="1.6"/>
                </svg>
            </div>
            <div style="font-size: 1.55rem; font-weight: 900; letter-spacing: 2px; color: #F8FAFC;">
                SENTINEL<span style="color: #38BDF8;">X</span>
            </div>
            <div style="font-size: 0.74rem; font-weight: 700; letter-spacing: 1.2px; color: #94A3B8; text-transform: uppercase; margin-bottom: 20px;">
                Autonomous Security Operations Center
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    _, login_col, _ = st.columns([1, 1.4, 1])
    with login_col:
        with st.container():
            st.markdown(
                """
                <div class="sx-panel" style="padding: 20px 22px; margin-bottom: 12px;">
                    <div style="font-size: 0.82rem; font-weight: 800; color: #38BDF8; letter-spacing: 0.6px; text-transform: uppercase; margin-bottom: 12px;">
                        🔐 Analyst Access Gateway
                    </div>
                """,
                unsafe_allow_html=True
            )

            login_user = st.text_input("Username", key="login_username", placeholder="Enter username")
            login_pass = st.text_input("Password", key="login_password", type="password", placeholder="Enter password")

            if st.button("Access SentinelX SOC", type="primary", use_container_width=True, key="btn_login_submit"):
                user_obj = authenticate_user(login_user, login_pass)
                if user_obj:
                    st.session_state.authenticated = True
                    st.session_state.current_user = user_obj
                    st.session_state.selected_page = "Dashboard"
                    st.success(f"Authenticated as {user_obj['username'].upper()} ({user_obj['role']})")
                    st.rerun()
                else:
                    st.error("Invalid credentials. Please verify your username and password.")

            st.markdown("</div>", unsafe_allow_html=True)

            with st.expander("🔑 Demo Access Credentials (Judges & Team)", expanded=True):
                st.markdown(
                    """
                    <div style="font-size: 0.78rem; line-height: 1.6; color: #94A3B8;">
                        <b>SOC Analyst Account</b> (Triage, investigate & export):<br>
                        <code>analyst</code> / <code>SentinelX@Analyst2026</code>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

    st.stop()


# ==================================================
# FRONT-PAGE NAVIGATION & LIVE SOC CONTROLS
# ==================================================

if "selected_page" not in st.session_state:
    st.session_state.selected_page = "Dashboard"

selected_page = st.session_state.selected_page
current_user = st.session_state.current_user or {"username": "analyst", "role": "ANALYST"}
user_disp = str(current_user.get("username", "analyst")).upper()
role_disp = str(current_user.get("role", "ANALYST")).upper()

st.markdown(
    f"""
    <div class="sx-top-header">
        <div class="sx-brand-wrapper">
            <svg width="44" height="44" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg" style="flex-shrink:0;">
                <path d="M24 3.5L7 10.5V22C7 33.2 14.3 43.5 24 46C33.7 43.5 41 33.2 41 22V10.5L24 3.5Z" stroke="#38BDF8" stroke-width="2.4" stroke-linejoin="round" fill="rgba(56, 189, 248, 0.08)"/>
                <path d="M24 8L11.5 13.8V22C11.5 30.5 16.8 38.3 24 40.8C31.2 38.3 36.5 30.5 36.5 22V13.8L24 8Z" stroke="rgba(99, 102, 241, 0.5)" stroke-width="1.5" stroke-linejoin="round" fill="none"/>
                <path d="M16.5 17.5L31.5 30.5M31.5 17.5L16.5 30.5" stroke="#38BDF8" stroke-width="2.8" stroke-linecap="round"/>
                <circle cx="24" cy="24" r="3.2" fill="#38BDF8" stroke="#0A111C" stroke-width="1.6"/>
            </svg>
            <div class="sx-brand-text">
                <div class="sx-brand-title">SENTINEL<span style="color:#38BDF8;">X</span></div>
                <div class="sx-brand-sub">Autonomous Security Operations Center</div>
            </div>
        </div>
        <div class="sx-top-status-right">
            <div class="sx-chips-row" style="margin-top:0;">
                <span class="sx-chip sx-chip-green"><span class="sx-chip-dot sx-dot-green"></span>SOC ENGINE ONLINE</span>
                <span class="sx-chip sx-chip-indigo"><span class="sx-chip-dot sx-dot-indigo"></span>AI ASSISTED</span>
                <span class="sx-chip sx-chip-cyan"><span class="sx-chip-dot sx-dot-cyan"></span>CONTAINMENT READY</span>
                <span class="sx-chip sx-chip-indigo" style="border:1px solid rgba(56,189,248,0.4); color:#38BDF8;">
                    👤 {user_disp} [{role_disp}]
                </span>
            </div>
            <div style="color:#64748B; font-size:0.68rem; font-family:ui-monospace, monospace; letter-spacing:0.6px; margin-top:3px;">
                ● TELEMETRY STREAM ACTIVE • SQLITE WAL ENGINE
            </div>
        </div>
    </div>
    """,
    unsafe_allow_html=True
)

nav_items = [
    ("Dashboard", "Dashboard", "nav_dashboard"),
    ("Live Events", "Live Events", "nav_live_events"),
    ("Security Alerts", "Security Alerts", "nav_security_alerts"),
    ("Incidents", "Incidents", "nav_incidents"),
    ("MITRE ATT&CK", "MITRE ATT&CK", "nav_mitre"),
    ("Audit Logs", "Audit Logs", "nav_audit")
]

nav_cols = st.columns([1, 1, 1, 1, 1, 1, 0.9, 0.9])

for col, (label, page, key) in zip(nav_cols[:6], nav_items):
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

with nav_cols[6]:
    if st.button(
        "🔄 Refresh",
        use_container_width=True,
        key="nav_refresh_telemetry"
    ):
        st.rerun()

with nav_cols[7]:
    if st.button(
        "🚪 Logout",
        use_container_width=True,
        key="nav_logout_btn"
    ):
        st.session_state.authenticated = False
        st.session_state.current_user = None
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

current_incidents = get_incidents(100)

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

    for incident in current_incidents:

        incident_alert_type = (
            normalize_alert_type(
                incident["alert_type"]
            )
        )

        if (
            incident_alert_type == alert_type
            and incident["source_ip"] == source_ip
            and incident.get("status") != "RESOLVED"
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

        current_incidents.insert(0, {
            "incident_id": incident_id,
            "alert_type": alert_type,
            "title": alert.get("title", "Security Incident"),
            "source_ip": source_ip,
            "severity": alert.get("severity", "LOW"),
            "risk_score": alert.get("risk_score", 0),
            "mitre_technique": alert.get("mitre_technique", "N/A"),
            "description": alert.get("description", alert.get("message", "")),
            "status": "NEW",
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        })


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
        f"""
        <div class="sx-briefing-bar">
            <div class="sx-briefing-left">
                <span class="sx-pulse-dot"></span>
                <span class="sx-briefing-title">LIVE SOC SITUATIONAL BRIEFING</span>
                <span class="sx-briefing-divider">•</span>
                <span class="sx-briefing-text">All 5 detection engines synchronized. Policy-based autonomous host containment active.</span>
            </div>
            <div class="sx-briefing-right">
                <span class="sx-badge sx-badge-success">POSTURE: {posture_label}</span>
                <span class="sx-badge sx-badge-critical" style="background:rgba(239,68,68,0.12); color:#EF4444; border:1px solid rgba(239,68,68,0.3);">ACTIVE THREATS: {active_incidents}</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # ----------------------------------------------
    # TOP SOC METRICS
    # ----------------------------------------------

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(
            f"""
            <div class="sx-kpi-card">
                <div class="sx-kpi-header">
                    <span class="sx-kpi-label">Security Events</span>
                    <div class="sx-kpi-icon" style="background:rgba(56, 189, 248, 0.12); color:#38BDF8;">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
                        </svg>
                    </div>
                </div>
                <div class="sx-kpi-value" style="color:#F1F5F9;">{total_events}</div>
                <div class="sx-kpi-meta">
                    <span class="sx-chip-dot sx-dot-cyan"></span> Host telemetry buffer
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col2:
        alert_accent = "#F97316" if high_alerts > 0 else "#38BDF8"
        alert_bg = "rgba(249, 115, 22, 0.12)" if high_alerts > 0 else "rgba(56, 189, 248, 0.12)"
        st.markdown(
            f"""
            <div class="sx-kpi-card">
                <div class="sx-kpi-header">
                    <span class="sx-kpi-label">High & Critical Alerts</span>
                    <div class="sx-kpi-icon" style="background:{alert_bg}; color:{alert_accent};">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                            <line x1="12" y1="9" x2="12" y2="13"/>
                            <line x1="12" y1="17" x2="12.01" y2="17"/>
                        </svg>
                    </div>
                </div>
                <div class="sx-kpi-value" style="color:{alert_accent};">{high_alerts}</div>
                <div class="sx-kpi-meta">
                    <span class="sx-chip-dot" style="background:{alert_accent};"></span> Risk score ≥ 70 or Critical
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col3:
        threat_accent = "#EF4444" if active_incidents > 0 else "#10B981"
        threat_bg = "rgba(239, 68, 68, 0.12)" if active_incidents > 0 else "rgba(16, 185, 129, 0.12)"
        st.markdown(
            f"""
            <div class="sx-kpi-card">
                <div class="sx-kpi-header">
                    <span class="sx-kpi-label">Active Incidents</span>
                    <div class="sx-kpi-icon" style="background:{threat_bg}; color:{threat_accent};">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <circle cx="12" cy="12" r="10"/>
                            <line x1="22" y1="12" x2="18" y2="12"/>
                            <line x1="6" y1="12" x2="2" y2="12"/>
                            <line x1="12" y1="6" x2="12" y2="2"/>
                            <line x1="12" y1="22" x2="12" y2="18"/>
                        </svg>
                    </div>
                </div>
                <div class="sx-kpi-value" style="color:{threat_accent};">{active_incidents}</div>
                <div class="sx-kpi-meta">
                    <span class="sx-chip-dot" style="background:{threat_accent};"></span> Requiring triage or response
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col4:
        st.markdown(
            f"""
            <div class="sx-kpi-card">
                <div class="sx-kpi-header">
                    <span class="sx-kpi-label">Contained Threats</span>
                    <div class="sx-kpi-icon" style="background:rgba(16, 185, 129, 0.12); color:#10B981;">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                            <path d="m9 12 2 2 4-4"/>
                        </svg>
                    </div>
                </div>
                <div class="sx-kpi-value" style="color:#10B981;">{contained_incidents}</div>
                <div class="sx-kpi-meta">
                    <span class="sx-chip-dot sx-dot-green"></span> Isolated via host containment
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    # ----------------------------------------------
    # SOC DETECTION & RESPONSE PIPELINE
    # ----------------------------------------------

    st.markdown(
        """
        <div class="sx-panel" style="margin-top: 10px; margin-bottom: 10px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                <div style="font-size:0.78rem; font-weight:800; color:#F1F5F9; letter-spacing:0.5px;">
                    ⚡ AUTONOMOUS SOC DETECTION & RESPONSE PIPELINE
                </div>
                <div style="font-size:0.66rem; color:#64748B; font-weight:600;">
                    END-TO-END THREAT CORRELATION LIFECYCLE
                </div>
            </div>
            <div class="sx-pipeline-row">
                <div class="sx-pipe-box">
                    <div class="sx-pipe-step">01</div>
                    <div class="sx-pipe-title">Telemetry</div>
                    <div class="sx-pipe-sub">Host & Ingest</div>
                </div>
                <div class="sx-pipe-arrow">➔</div>
                <div class="sx-pipe-box">
                    <div class="sx-pipe-step">02</div>
                    <div class="sx-pipe-title">Detection</div>
                    <div class="sx-pipe-sub">5 Engine Rules</div>
                </div>
                <div class="sx-pipe-arrow">➔</div>
                <div class="sx-pipe-box">
                    <div class="sx-pipe-step">03</div>
                    <div class="sx-pipe-title">Risk Engine</div>
                    <div class="sx-pipe-sub">0-100 Scoring</div>
                </div>
                <div class="sx-pipe-arrow">➔</div>
                <div class="sx-pipe-box">
                    <div class="sx-pipe-step">04</div>
                    <div class="sx-pipe-title">Security Alert</div>
                    <div class="sx-pipe-sub">Prioritized</div>
                </div>
                <div class="sx-pipe-arrow">➔</div>
                <div class="sx-pipe-box">
                    <div class="sx-pipe-step">05</div>
                    <div class="sx-pipe-title">Incident</div>
                    <div class="sx-pipe-sub">Correlation Hub</div>
                </div>
                <div class="sx-pipe-arrow">➔</div>
                <div class="sx-pipe-box">
                    <div class="sx-pipe-step">06</div>
                    <div class="sx-pipe-title">Evidence</div>
                    <div class="sx-pipe-sub">Exact Event Links</div>
                </div>
                <div class="sx-pipe-arrow">➔</div>
                <div class="sx-pipe-box">
                    <div class="sx-pipe-step">07</div>
                    <div class="sx-pipe-title">MITRE ATT&CK</div>
                    <div class="sx-pipe-sub">Adversary TTPs</div>
                </div>
                <div class="sx-pipe-arrow">➔</div>
                <div class="sx-pipe-box">
                    <div class="sx-pipe-step">08</div>
                    <div class="sx-pipe-title">Containment</div>
                    <div class="sx-pipe-sub">Safe Isolation</div>
                </div>
                <div class="sx-pipe-arrow">➔</div>
                <div class="sx-pipe-box">
                    <div class="sx-pipe-step">09</div>
                    <div class="sx-pipe-title">Audit Trail</div>
                    <div class="sx-pipe-sub">Forensic Ledger</div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # ----------------------------------------------
    # INTERACTIVE ATTACK DEMO RUNNER (PRESENTER MODE)
    # ----------------------------------------------
    with st.expander("⚡ Interactive Threat Simulation & Attack Scenarios (Presenter Mode)", expanded=False):
        st.markdown(
            """
            <div style="font-size:0.80rem; color:#94A3B8; margin-bottom:8px;">
                Inject realistic multi-stage cyberattack telemetry directly into the SentinelX pipeline to demonstrate real-time heuristic detection, explainable risk scoring, and automated host isolation.
            </div>
            """,
            unsafe_allow_html=True
        )

        sim_cols = st.columns(3)
        with sim_cols[0]:
            if st.button("💥 Brute Force (T1110)", key="demo_sim_bf", use_container_width=True):
                with st.spinner("Injecting 5 failed authentication attempts..."):
                    e_ids = simulate_brute_force()
                    st.success(f"Injected {len(e_ids)} Brute Force events (IP: 192.168.1.101).")
                    st.rerun()

            if st.button("⬆️ Privilege Escalation (T1068)", key="demo_sim_priv", use_container_width=True):
                with st.spinner("Injecting 3 unauthorized privilege elevation events..."):
                    e_ids = generate_privilege_escalation_events()
                    st.success(f"Injected {len(e_ids)} Privilege Escalation events (IP: 192.168.1.80).")
                    st.rerun()

        with sim_cols[1]:
            if st.button("🔍 Port Scan (T1046)", key="demo_sim_ps", use_container_width=True):
                with st.spinner("Injecting 10 network service probe events..."):
                    e_ids = simulate_port_scan()
                    st.success(f"Injected {len(e_ids)} Port Scan events (IP: 192.168.1.61).")
                    st.rerun()

            if st.button("💻 Obfuscated PowerShell (T1059)", key="demo_sim_pshell", use_container_width=True):
                with st.spinner("Injecting obfuscated PowerShell execution events..."):
                    e_ids = generate_suspicious_powershell_events()
                    st.success(f"Injected {len(e_ids)} PowerShell execution events (IP: 192.168.1.90).")
                    st.rerun()

        with sim_cols[2]:
            if st.button("🔑 Suspicious Auth (T1078)", key="demo_sim_auth", use_container_width=True):
                with st.spinner("Injecting 5 rapid successful logins..."):
                    e_ids = simulate_suspicious_authentication()
                    st.success(f"Injected {len(e_ids)} Suspicious Auth events (IP: 192.168.1.70).")
                    st.rerun()

            if st.button("🚀 Full Multi-Stage Campaign", key="demo_sim_all", type="primary", use_container_width=True):
                with st.spinner("Injecting complete multi-stage cyberattack campaign..."):
                    simulate_brute_force()
                    simulate_port_scan()
                    simulate_suspicious_authentication()
                    generate_privilege_escalation_events()
                    generate_suspicious_powershell_events()
                    st.success("Complete 5-stage attack campaign injected into SentinelX.")
                    st.rerun()

    # ----------------------------------------------
    # SECURITY POSTURE
    # ----------------------------------------------

    st.markdown("### 🛡️ Enterprise Security Posture")

    if posture_label in ["EXCELLENT", "GOOD"]:
        posture_badge_color = "#10B981"
        posture_bg = "rgba(16, 185, 129, 0.12)"
        posture_border = "rgba(16, 185, 129, 0.35)"
        posture_desc = "Systems stable under current threat load. Detection and containment defenses active."
    elif posture_label in ["MODERATE", "POOR"]:
        posture_badge_color = "#F97316"
        posture_bg = "rgba(249, 115, 22, 0.12)"
        posture_border = "rgba(249, 115, 22, 0.35)"
        posture_desc = "Elevated threat volume. Active analyst investigation and containment recommended."
    else:
        posture_badge_color = "#EF4444"
        posture_bg = "rgba(239, 68, 68, 0.12)"
        posture_border = "rgba(239, 68, 68, 0.35)"
        posture_desc = "Critical threat threshold breached. Immediate host isolation required."

    posture_html = f"""
    <div class="sx-panel" style="margin-bottom: 0.6rem; border: 1px solid {posture_border}; background: #0E1726;">
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:14px;">
            <div style="display:flex; align-items:center; gap:16px;">
                <div style="text-align:center; padding:8px 16px; background:#142032; border:1px solid #1E2E44; border-radius:5px;">
                    <div style="color:#94A3B8; font-size:0.62rem; font-weight:700; text-transform:uppercase; letter-spacing:0.7px;">POSTURE SCORE</div>
                    <div style="font-size:1.85rem; font-weight:900; color:#F1F5F9; font-family:ui-monospace, monospace; line-height:1.1; margin-top:2px;">
                        {posture_score}<span style="font-size:0.85rem; color:#64748B;">/100</span>
                    </div>
                </div>
                <div>
                    <div style="display:inline-block; padding:2px 8px; border-radius:3px; font-size:0.70rem; font-weight:800; letter-spacing:0.7px; background:{posture_bg}; color:{posture_badge_color}; border:1px solid {posture_border};">
                        STATUS: {posture_label}
                    </div>
                    <div style="color:#94A3B8; font-size:0.80rem; margin-top:4px;">
                        {posture_desc}
                    </div>
                </div>
            </div>
            <div style="display:flex; gap:10px; flex-wrap:wrap;">
                <div style="background:#142032; border:1px solid #1E2E44; border-radius:5px; padding:5px 10px; text-align:center;">
                    <div style="color:#64748B; font-size:0.60rem; font-weight:700;">ACTIVE</div>
                    <div style="color:#F1F5F9; font-size:1.0rem; font-weight:800; font-family:monospace;">{posture['details']['active_incidents']}</div>
                </div>
                <div style="background:#142032; border:1px solid #1E2E44; border-radius:5px; padding:5px 10px; text-align:center;">
                    <div style="color:#F97316; font-size:0.60rem; font-weight:700;">HIGH/CRIT</div>
                    <div style="color:#F97316; font-size:1.0rem; font-weight:800; font-family:monospace;">{posture['details']['high_critical_incidents']}</div>
                </div>
                <div style="background:#142032; border:1px solid #1E2E44; border-radius:5px; padding:5px 10px; text-align:center;">
                    <div style="color:#10B981; font-size:0.60rem; font-weight:700;">CONTAINED</div>
                    <div style="color:#10B981; font-size:1.0rem; font-weight:800; font-family:monospace;">{posture['details']['contained_incidents']}</div>
                </div>
                <div style="background:#142032; border:1px solid #1E2E44; border-radius:5px; padding:5px 10px; text-align:center;">
                    <div style="color:#38BDF8; font-size:0.60rem; font-weight:700;">RESOLVED</div>
                    <div style="color:#38BDF8; font-size:1.0rem; font-weight:800; font-family:monospace;">{posture['details']['resolved_incidents']}</div>
                </div>
            </div>
        </div>
    </div>
    """
    st.markdown(posture_html, unsafe_allow_html=True)

    norm_score = max(0.0, min(1.0, float(posture_score) / 100.0))
    st.progress(norm_score)

    # ----------------------------------------------
    # THREAT OVERVIEW
    # ----------------------------------------------

    st.divider()

    st.markdown("### 📊 Threat Landscape Overview")

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

    st.markdown("### ⚡ SentinelX Core Pipeline Health")

    st.markdown(
        """
        <div class="sx-health-grid">
            <div class="sx-health-card">
                <span class="sx-health-dot"></span>
                <div>
                    <div class="sx-health-name">Detection Engine</div>
                    <div class="sx-health-status">ONLINE (5 Detectors)</div>
                </div>
            </div>
            <div class="sx-health-card">
                <span class="sx-health-dot"></span>
                <div>
                    <div class="sx-health-name">Risk Engine</div>
                    <div class="sx-health-status">ONLINE (Enrichment)</div>
                </div>
            </div>
            <div class="sx-health-card">
                <span class="sx-health-dot"></span>
                <div>
                    <div class="sx-health-name">Database Vault</div>
                    <div class="sx-health-status">CONNECTED (SQLite)</div>
                </div>
            </div>
            <div class="sx-health-card">
                <span class="sx-health-dot"></span>
                <div>
                    <div class="sx-health-name">AI SOC Copilot</div>
                    <div class="sx-health-status">ACTIVE (Gemini / Rules)</div>
                </div>
            </div>
            <div class="sx-health-card">
                <span class="sx-health-dot"></span>
                <div>
                    <div class="sx-health-name">Safe Containment</div>
                    <div class="sx-health-status">ACTIVE (Host Isolation)</div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )



# ==================================================
# PAGE 2 — LIVE EVENTS
# ==================================================

elif selected_page == "Live Events":

    st.markdown(
        """
        <div class="sx-page-title-row">
            <div class="sx-page-title">📡 Live Security Telemetry Feed</div>
            <div class="sx-chips-row">
                <span class="sx-chip sx-chip-green"><span class="sx-chip-dot sx-dot-green"></span>STREAM ACTIVE</span>
                <span class="sx-chip sx-chip-cyan"><span class="sx-chip-dot sx-dot-cyan"></span>INGESTION ONLINE</span>
            </div>
        </div>
        <div class="sx-page-desc">
            Real-time security telemetry and host audit events ingested into the SentinelX processing pipeline.
        </div>
        """,
        unsafe_allow_html=True
    )

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
            st.markdown(
                """
                <div class="sx-empty-card">
                    <div class="sx-empty-icon">🔍</div>
                    <div class="sx-empty-title">No Matching Telemetry Events</div>
                    <div class="sx-empty-desc">
                        No security events match your current filter criteria. Try broadening your search query or selecting 'ALL' in the event type and severity filters.
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

    else:
        st.markdown(
            """
            <div class="sx-empty-card">
                <div class="sx-empty-icon">📡</div>
                <div class="sx-empty-title">No Security Telemetry Ingested</div>
                <div class="sx-empty-desc">
                    SentinelX has not received telemetry events yet. Launch an attack simulation or ingest host logs to populate the pipeline.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )



# ==================================================
# PAGE 3 — SECURITY ALERTS
# ==================================================

elif selected_page == "Security Alerts":

    st.markdown(
        """
        <div class="sx-page-title-row">
            <div class="sx-page-title">🚨 Security Alerts & Risk Detections</div>
            <div class="sx-chips-row">
                <span class="sx-chip sx-chip-cyan"><span class="sx-chip-dot sx-dot-cyan"></span>MULTI-FACTOR SCORING</span>
                <span class="sx-chip sx-chip-indigo"><span class="sx-chip-dot sx-dot-indigo"></span>CORRELATION HUB</span>
            </div>
        </div>
        <div class="sx-page-desc">
            Prioritized detections generated by SentinelX heuristic engines and enriched by dynamic multi-factor risk scoring.
        </div>
        """,
        unsafe_allow_html=True
    )

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
                    st.markdown(f"### {title}")
                    st.caption(f"Detection Engine Type: `{alert_type}`")

                with header_col2:
                    st.metric(
                        "Risk Score",
                        f"{risk_score} / 100"
                    )

                info_col1, info_col2, info_col3, info_col4 = st.columns(4)

                with info_col1:
                    st.write("**Severity Level**")
                    sev_badge = {
                        "CRITICAL": '<span class="sx-badge sx-badge-critical">CRITICAL</span>',
                        "HIGH": '<span class="sx-badge sx-badge-high">HIGH</span>',
                        "MEDIUM": '<span class="sx-badge sx-badge-medium">MEDIUM</span>',
                        "LOW": '<span class="sx-badge sx-badge-low">LOW</span>',
                    }.get(risk_level, f'<span class="sx-badge sx-badge-low">{risk_level}</span>')
                    st.markdown(sev_badge, unsafe_allow_html=True)

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
                        status_badge = {
                            "CONTAINED": '<span class="sx-badge sx-badge-success">● CONTAINED</span>',
                            "RESOLVED": '<span class="sx-badge sx-badge-success">● RESOLVED</span>',
                            "INVESTIGATING": '<span class="sx-badge sx-badge-high">● INVESTIGATING</span>',
                            "TRIAGED": '<span class="sx-badge sx-badge-medium">● TRIAGED</span>',
                            "NEW": '<span class="sx-badge sx-badge-low">● NEW</span>',
                        }.get(incident_status, f'<span class="sx-badge sx-badge-low">● {incident_status}</span>')
                        st.markdown(status_badge, unsafe_allow_html=True)

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
        st.markdown(
            """
            <div class="sx-empty-card">
                <div class="sx-empty-icon">🔍</div>
                <div class="sx-empty-title">No Security Alerts Match Filter</div>
                <div class="sx-empty-desc">
                    No detections match your current search query or severity filter. Adjust your filter criteria to view all alerts.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
    else:
        st.markdown(
            """
            <div class="sx-empty-card">
                <div class="sx-empty-icon">🛡️</div>
                <div class="sx-empty-title">Zero Active Threats Detected</div>
                <div class="sx-empty-desc">
                    The detection engine has not triggered any alerts. Ingest live telemetry or run the attack simulator to test detectors.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )



# ==================================================
# PAGE 4 — INCIDENT MANAGEMENT
# ==================================================

elif selected_page == "Incidents":

    st.markdown(
        """
        <div class="sx-page-title-row">
            <div class="sx-page-title">🛡️ Incident Management & Containment Console</div>
            <div class="sx-chips-row">
                <span class="sx-chip sx-chip-green"><span class="sx-chip-dot sx-dot-green"></span>AUTO-CONTAINMENT READY</span>
                <span class="sx-chip sx-chip-indigo"><span class="sx-chip-dot sx-dot-indigo"></span>AI ASSISTED</span>
            </div>
        </div>
        <div class="sx-page-desc">
            Investigate correlated security threats, track investigation lifecycle states, and orchestrate policy-controlled containment.
        </div>
        """,
        unsafe_allow_html=True
    )

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

                # --------------------------------------
                # INCIDENT CARD
                # --------------------------------------
                with st.container(border=True):
                    head_col1, head_col2 = st.columns([4, 1])

                    with head_col1:
                        st.markdown(f"### {status_icon} {incident_id} — {title}")
                        st.caption(f"Severity: `{severity}`  |  Workflow State: `{status}`")

                    with head_col2:
                        st.metric("Risk Score", f"{risk_score} / 100")

                    # Incident Overview
                    info_col1, info_col2, info_col3, info_col4 = st.columns(4)

                    with info_col1:
                        st.write("**Source IP Address**")
                        st.code(source_ip)

                    with info_col2:
                        st.write("**Severity**")
                        sev_badge = {
                            "CRITICAL": '<span class="sx-badge sx-badge-critical">CRITICAL</span>',
                            "HIGH": '<span class="sx-badge sx-badge-high">HIGH</span>',
                            "MEDIUM": '<span class="sx-badge sx-badge-medium">MEDIUM</span>',
                            "LOW": '<span class="sx-badge sx-badge-low">LOW</span>',
                        }.get(severity, f'<span class="sx-badge sx-badge-low">{severity}</span>')
                        st.markdown(sev_badge, unsafe_allow_html=True)

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

                    step_html_items = []
                    for idx, stage in enumerate(lifecycle):
                        if idx < lifecycle_index:
                            step_class = "sx-step sx-step-completed"
                            marker = "✓"
                        elif idx == lifecycle_index:
                            step_class = "sx-step sx-step-current"
                            marker = "●"
                        else:
                            step_class = "sx-step"
                            marker = "○"

                        step_html_items.append(
                            f'<div class="{step_class}">{marker} {stage}</div>'
                        )

                    stepper_html = f"""
                    <div class="sx-stepper">
                        {' <span class="sx-stepper-sep">→</span> '.join(step_html_items)}
                    </div>
                    """
                    st.markdown(stepper_html, unsafe_allow_html=True)

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
                        st.write("")
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
                    # SAFE & REVERSIBLE CONTAINMENT CONTROL
                    # ----------------------------------
                    st.write("**Defensive Containment & Host Isolation**")
                    is_blocked = is_source_blocked(source_ip)

                    contain_box_col1, contain_box_col2 = st.columns([3, 2])
                    with contain_box_col1:
                        if is_blocked:
                            st.markdown(
                                '<div style="display:flex; align-items:center; gap:8px; padding:6px 12px; background:rgba(16,185,129,0.12); border:1px solid rgba(16,185,129,0.35); border-radius:5px;">'
                                '<span class="sx-pulse-dot"></span>'
                                '<span style="color:#10B981; font-weight:800; font-size:0.75rem; letter-spacing:0.5px;">ACTIVE CONTAINMENT: SOURCE IP ISOLATED</span>'
                                '</div>',
                                unsafe_allow_html=True
                            )
                        else:
                            st.markdown(
                                '<div style="display:flex; align-items:center; gap:8px; padding:6px 12px; background:rgba(148,163,184,0.08); border:1px solid rgba(148,163,184,0.25); border-radius:5px;">'
                                '<span style="width:7px; height:7px; border-radius:50%; background:#64748B; display:inline-block;"></span>'
                                '<span style="color:#94A3B8; font-weight:700; font-size:0.75rem; letter-spacing:0.5px;">HOST ACTIVE: NOT CURRENTLY ISOLATED</span>'
                                '</div>',
                                unsafe_allow_html=True
                            )

                    with contain_box_col2:
                        if is_blocked:
                            if st.button("🔓 Revert Isolation (Unblock IP)", key=f"unblock_btn_{incident_id}", type="secondary", use_container_width=True):
                                unblock_res = unblock_source_ip(
                                    incident_id,
                                    source_ip,
                                    f"Analyst verified mitigation for {incident_id}"
                                )
                                if unblock_res.get("success"):
                                    if status == "CONTAINED":
                                        update_incident_status(incident_id, "INVESTIGATING")
                                    st.success(f"Source IP {source_ip} unblocked safely.")
                                    st.rerun()
                                else:
                                    st.error(unblock_res.get("message", "Failed to unblock source IP."))
                        else:
                            if st.button("🛡️ Isolate Host (Block IP)", key=f"block_btn_{incident_id}", type="primary", use_container_width=True):
                                block_res = block_source_ip(
                                    incident_id,
                                    source_ip,
                                    f"Manual analyst quarantine for {incident_id} ({title})"
                                )
                                if block_res.get("success"):
                                    update_incident_status(incident_id, "CONTAINED")
                                    st.success(f"Source IP {source_ip} quarantined safely.")
                                    st.rerun()
                                else:
                                    st.error(block_res.get("message", "Failed to isolate source IP."))

                    # Closed-loop containment telemetry verification
                    if is_blocked:
                        verif_result = verify_source_containment(source_ip, events)
                        if verif_result.get("is_verified"):
                            st.markdown(
                                f"""
                                <div style="display:flex; align-items:center; justify-content:space-between; padding:6px 12px; background:rgba(16,185,129,0.08); border:1px solid rgba(16,185,129,0.30); border-radius:5px; margin-top:8px;">
                                    <div style="display:flex; align-items:center; gap:8px;">
                                        <span style="color:#10B981; font-weight:800; font-size:0.75rem;">✓ CLOSED-LOOP VERIFICATION CONFIRMED</span>
                                        <span style="color:#94A3B8; font-size:0.72rem;">• 0 post-quarantine telemetry packets from <code>{source_ip}</code></span>
                                    </div>
                                    <span class="sx-badge sx-badge-success">THREAT NEUTRALIZED</span>
                                </div>
                                """,
                                unsafe_allow_html=True
                            )
                        else:
                            leak_count = verif_result.get("subsequent_events_count", 0)
                            st.markdown(
                                f"""
                                <div style="display:flex; align-items:center; justify-content:space-between; padding:6px 12px; background:rgba(239,68,68,0.08); border:1px solid rgba(239,68,68,0.30); border-radius:5px; margin-top:8px;">
                                    <div style="display:flex; align-items:center; gap:8px;">
                                        <span style="color:#EF4444; font-weight:800; font-size:0.75rem;">⚠️ CONTAINMENT ANOMALY DETECTED</span>
                                        <span style="color:#94A3B8; font-size:0.72rem;">• {leak_count} event(s) observed after isolation timestamp</span>
                                    </div>
                                    <span class="sx-badge sx-badge-critical">INSPECT TELEMETRY</span>
                                </div>
                                """,
                                unsafe_allow_html=True
                            )

                    st.divider()

                    # ----------------------------------
                    # OBSERVABLE THREAT INDICATORS (IOCS)
                    # ----------------------------------
                    incident_iocs = extract_incident_iocs(incident, incident_events)
                    with st.expander("🔬 Observable Threat Indicators (IOCs) & Evidence"):
                        ioc_col1, ioc_col2, ioc_col3 = st.columns(3)
                        with ioc_col1:
                            st.write("**Observed Source IP(s)**")
                            for s_ip in incident_iocs.get("source_ips", []):
                                st.code(s_ip)
                        with ioc_col2:
                            st.write("**Targeted Identities**")
                            users = incident_iocs.get("usernames", [])
                            if users:
                                for u in users:
                                    st.code(u)
                            else:
                                st.caption("No identity fields recorded.")
                        with ioc_col3:
                            st.write("**Targeted Ports**")
                            ports = incident_iocs.get("targeted_ports", [])
                            if ports:
                                st.code(", ".join(str(p) for p in ports))
                            else:
                                st.caption("No port specifications in evidence.")

                        st.caption(
                            f"Observation Window: `{incident_iocs.get('earliest_seen')}` ➔ `{incident_iocs.get('latest_seen')}`  |  "
                            f"Evidence Count: {incident_iocs.get('evidence_event_count')} Events"
                        )

                    # ----------------------------------
                    # CHRONOLOGICAL ATTACK CHAIN / THREAT TIMELINE
                    # ----------------------------------
                    incident_timeline = build_incident_timeline(incident_events)
                    with st.expander(f"🕒 Chronological Attack Timeline ({len(incident_timeline)} Sequence Steps)"):
                        if incident_timeline:
                            tl_data = [
                                {
                                    "Step": f"#{node['step']}",
                                    "Offset": node["delta_str"],
                                    "Attack Milestone": node["stage"],
                                    "Timestamp": node["timestamp"],
                                    "Identity": node["username"],
                                    "Action": node["action"],
                                    "Status": node["status"],
                                    "Details": node["message"]
                                }
                                for node in incident_timeline
                            ]
                            st.dataframe(tl_data, width="stretch", hide_index=True)
                        else:
                            st.info("No chronological milestones recorded.")

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
                    st.markdown("### 🤖 SentinelX AI SOC Copilot")
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
                        ai_source = cached_ai.get("ai_source", "AI Copilot")
                        is_gemini = "Gemini" in ai_source
                        badge_style = "background:rgba(99,102,241,0.15); color:#818CF8; border:1px solid rgba(99,102,241,0.35);" if is_gemini else "background:rgba(251,191,36,0.15); color:#FBBF24; border:1px solid rgba(251,191,36,0.35);"

                        st.markdown(
                            f"""
                            <div class="sx-ai-report">
                                <div class="sx-ai-banner">
                                    <div style="display:flex; align-items:center; gap:8px;">
                                        <span class="sx-pulse-dot" style="background:#818CF8; box-shadow:0 0 6px #818CF8;"></span>
                                        <span style="font-weight:800; font-size:0.76rem; color:#F1F5F9; letter-spacing:0.5px;">THREAT INTELLIGENCE REPORT</span>
                                    </div>
                                    <div style="display:flex; align-items:center; gap:6px;">
                                        <span style="display:inline-block; padding:2px 8px; border-radius:3px; font-size:0.68rem; font-weight:700; {badge_style}">
                                            ENGINE: {ai_source.upper()}
                                        </span>
                                        <span class="sx-badge sx-badge-success">GROUND TRUTH VERIFIED</span>
                                    </div>
                                </div>
                            </div>
                            """,
                            unsafe_allow_html=True
                        )

                        st.markdown("<div class='sx-ai-section-title'>📋 Executive Incident Summary</div>", unsafe_allow_html=True)
                        st.markdown(f"<div class='sx-ai-text'>{cached_ai.get('incident_summary', 'Not available in supplied evidence.')}</div>", unsafe_allow_html=True)

                        what_happened = cached_ai.get("what_happened")
                        if what_happened and what_happened != cached_ai.get("incident_summary"):
                            st.markdown("<div class='sx-ai-section-title'>🔎 Forensic Timeline: What Happened?</div>", unsafe_allow_html=True)
                            st.markdown(f"<div class='sx-ai-text'>{what_happened}</div>", unsafe_allow_html=True)

                        why_suspicious = cached_ai.get("why_suspicious")
                        if why_suspicious and why_suspicious != cached_ai.get("severity_explanation"):
                            st.markdown("<div class='sx-ai-section-title'>⚠️ Threat Dynamics: Why Is It Suspicious?</div>", unsafe_allow_html=True)
                            st.markdown(f"<div class='sx-ai-text'>{why_suspicious}</div>", unsafe_allow_html=True)

                        st.markdown("<div class='sx-ai-section-title'>⚖️ Severity & Threat Assessment</div>", unsafe_allow_html=True)
                        st.markdown(f"<div class='sx-ai-text'>{cached_ai.get('severity_explanation', 'Not available in supplied evidence.')}</div>", unsafe_allow_html=True)

                        st.markdown("<div class='sx-ai-section-title'>🎯 MITRE ATT&CK Context</div>", unsafe_allow_html=True)
                        st.markdown(f"<div class='sx-ai-text'>{cached_ai.get('mitre_explanation', 'Not available in supplied evidence.')}</div>", unsafe_allow_html=True)

                        st.markdown("<div class='sx-ai-section-title'>🔍 Actionable Investigation Playbook</div>", unsafe_allow_html=True)
                        steps = cached_ai.get("investigation_steps", [])
                        if isinstance(steps, list):
                            for idx, s in enumerate(steps, 1):
                                st.markdown(f"**Step {idx}:** {s}")
                        else:
                            st.write(steps)

                        st.markdown("<div class='sx-ai-section-title'>🛡️ Prescriptive Containment & Response Directives</div>", unsafe_allow_html=True)
                        recs = cached_ai.get("recommended_response", [])
                        if isinstance(recs, list):
                            for idx, r in enumerate(recs, 1):
                                st.markdown(f"**Directive {idx}:** {r}")
                        else:
                            st.write(recs)

                        verif_steps = cached_ai.get("verification_guidance", [])
                        if verif_steps:
                            st.markdown("<div class='sx-ai-section-title'>✅ Post-Action Verification & Recovery Guidance</div>", unsafe_allow_html=True)
                            if isinstance(verif_steps, list):
                                for idx, v in enumerate(verif_steps, 1):
                                    st.markdown(f"**Verification {idx}:** {v}")
                            else:
                                st.write(verif_steps)

                        st.caption(
                            f"Analyzed Security Evidence: {cached_ai.get('evidence_count', len(incident_events))} Events  |  "
                            f"Provider: SentinelX Hybrid Copilot ({ai_source}) with Deterministic Guardrails"
                        )

                    st.divider()

                    # ----------------------------------
                    # FORENSIC DOSSIER & COMPLIANCE EXPORT
                    # ----------------------------------
                    st.markdown("### 📥 Incident Forensic Dossier & Compliance Export")
                    st.caption("Generate verifiable chain-of-custody forensic reports for executive review, SIEM archival, or CSIRT handoff.")

                    current_verif = None
                    if is_blocked:
                        current_verif = verify_source_containment(source_ip, events)

                    json_dossier = generate_forensic_dossier_json(
                        incident=incident,
                        events=incident_events,
                        containment_actions=incident_containment_actions,
                        status_history=incident_status_history,
                        ai_report=cached_ai,
                        verification_status=current_verif
                    )

                    md_dossier = generate_forensic_dossier_markdown(
                        incident=incident,
                        events=incident_events,
                        containment_actions=incident_containment_actions,
                        status_history=incident_status_history,
                        ai_report=cached_ai,
                        verification_status=current_verif
                    )

                    dossier_col1, dossier_col2 = st.columns(2)
                    with dossier_col1:
                        st.download_button(
                            label="📥 Download Forensic Dossier (JSON)",
                            data=json_dossier,
                            file_name=f"{incident_id}_forensic_dossier.json",
                            mime="application/json",
                            key=f"dl_json_{incident_id}",
                            use_container_width=True
                        )
                    with dossier_col2:
                        st.download_button(
                            label="📄 Download Executive Briefing (MD)",
                            data=md_dossier,
                            file_name=f"{incident_id}_executive_briefing.md",
                            mime="text/markdown",
                            key=f"dl_md_{incident_id}",
                            use_container_width=True
                        )

                    with st.expander("👁️ Preview Executive Briefing"):
                        st.markdown(md_dossier)

        else:
            st.markdown(
                """
                <div class="sx-empty-card">
                    <div class="sx-empty-icon">🔍</div>
                    <div class="sx-empty-title">No Incidents Match Selected Filters</div>
                    <div class="sx-empty-desc">
                        No security incidents match the current workflow status or severity filters. Reset filters to view all active incidents.
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

    else:
        st.markdown(
            """
            <div class="sx-empty-card">
                <div class="sx-empty-icon">🛡️</div>
                <div class="sx-empty-title">Zero Security Incidents Created</div>
                <div class="sx-empty-desc">
                    SentinelX has not created any security incidents yet. When suspicious telemetry triggers detection thresholds, incidents will appear here automatically.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )



# ==================================================
# PAGE 5 — MITRE ATT&CK
# ==================================================

elif selected_page == "MITRE ATT&CK":

    st.markdown(
        """
        <div class="sx-page-title-row">
            <div class="sx-page-title">🎯 MITRE ATT&CK® Threat Matrix & Trace</div>
            <div class="sx-chips-row">
                <span class="sx-chip sx-chip-indigo"><span class="sx-chip-dot sx-dot-indigo"></span>ENTERPRISE MATRIX</span>
                <span class="sx-chip sx-chip-cyan"><span class="sx-chip-dot sx-dot-cyan"></span>TACTIC TRACE</span>
            </div>
        </div>
        <div class="sx-page-desc">
            Adversary Tactics, Techniques, and Common Knowledge (ATT&CK) mapping for SentinelX detection engines with verified evidence linking.
        </div>
        """,
        unsafe_allow_html=True
    )

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
    st.markdown("### 📋 Detection Engine → MITRE Matrix Mapping")

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
    st.markdown("### 🔍 Active Threat Technique Profiles")

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
                    with t_head2:
                        st.markdown(f"[Official MITRE Doc ↗]({mitre_url})")

                    matching_alerts = [a for a in risk_alerts if a.get("mitre_technique") == technique]
                    det_types = ", ".join(sorted(list(set(normalize_alert_type(a.get("alert_type")) for a in matching_alerts)))) or "RULE ENGINE"
                    evidence_count = sum(len(a.get("evidence", {}).get("event_ids", [])) for a in matching_alerts)

                    trace_html = f"""
                    <div style="display:flex; align-items:center; gap:6px; margin:8px 0 12px; overflow-x:auto;">
                        <div style="background:#142032; border:1px solid #1E2E44; border-radius:5px; padding:5px 10px; font-size:0.70rem; color:#F1F5F9;">
                            <span style="color:#94A3B8; font-size:0.60rem; font-weight:700; text-transform:uppercase;">DETECTION ENGINE</span><br><b>{det_types}</b>
                        </div>
                        <span style="color:#38BDF8; font-size:0.75rem; font-weight:bold;">→</span>
                        <div style="background:#142032; border:1px solid #1E2E44; border-radius:5px; padding:5px 10px; font-size:0.70rem; color:#38BDF8; font-family:monospace;">
                            <span style="color:#94A3B8; font-size:0.60rem; font-weight:700; text-transform:uppercase;">TECHNIQUE</span><br><b>{mapping['technique']}</b>
                        </div>
                        <span style="color:#38BDF8; font-size:0.75rem; font-weight:bold;">→</span>
                        <div style="background:#142032; border:1px solid #1E2E44; border-radius:5px; padding:5px 10px; font-size:0.70rem; color:#818CF8;">
                            <span style="color:#94A3B8; font-size:0.60rem; font-weight:700; text-transform:uppercase;">TACTIC</span><br><b>{mapping['tactic']}</b>
                        </div>
                        <span style="color:#38BDF8; font-size:0.75rem; font-weight:bold;">→</span>
                        <div style="background:#142032; border:1px solid #1E2E44; border-radius:5px; padding:5px 10px; font-size:0.70rem; color:#10B981;">
                            <span style="color:#94A3B8; font-size:0.60rem; font-weight:700; text-transform:uppercase;">CONFIRMED EVIDENCE</span><br><b>{evidence_count} Events Linked</b>
                        </div>
                    </div>
                    """
                    st.markdown(trace_html, unsafe_allow_html=True)
                    st.write(mapping["description"])
            else:
                with st.container(border=True):
                    st.code(technique)
    else:
        st.markdown(
            """
            <div class="sx-empty-card">
                <div class="sx-empty-icon">🎯</div>
                <div class="sx-empty-title">No Active ATT&CK Techniques Triggered</div>
                <div class="sx-empty-desc">
                    No MITRE ATT&CK adversary techniques have been mapped to the current telemetry buffer. As detections fire, active technique profiles will appear here with complete trace flows.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )



# ==================================================
# PAGE 6 — AUDIT LOGS
# ==================================================

elif selected_page == "Audit Logs":

    st.markdown(
        """
        <div class="sx-page-title-row">
            <div class="sx-page-title">📋 Containment & Forensics Audit Trail</div>
            <div class="sx-chips-row">
                <span class="sx-chip sx-chip-green"><span class="sx-chip-dot sx-dot-green"></span>IMMUTABLE LEDGER</span>
                <span class="sx-chip sx-chip-cyan"><span class="sx-chip-dot sx-dot-cyan"></span>COMPLIANCE READY</span>
            </div>
        </div>
        <div class="sx-page-desc">
            Forensic audit trail of all automated containment commands, policy decisions, and host isolation events.
        </div>
        """,
        unsafe_allow_html=True
    )

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
            st.markdown(
                """
                <div class="sx-empty-card">
                    <div class="sx-empty-icon">🔍</div>
                    <div class="sx-empty-title">No Audit Records Match Filter</div>
                    <div class="sx-empty-desc">
                        No containment records match your current search query or status filter. Try clearing the search query or setting the filter to 'ALL'.
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        # ----------------------------------------------
        # ACTIVE CONTAINMENT BLOCKLIST
        # ----------------------------------------------
        active_blocks = get_blocked_sources()
        with st.expander(f"🔒 Active Containment Blocklist ({len(active_blocks)} Active Host Isolations)"):
            if active_blocks:
                active_block_data = [
                    {
                        "Quarantined Host IP": b["source_ip"],
                        "Incident Link": b["incident_id"],
                        "Isolation Timestamp": b["blocked_at"],
                        "Containment Rationale": b["reason"],
                        "Status": b["status"]
                    }
                    for b in active_blocks
                ]
                st.dataframe(active_block_data, width="stretch", hide_index=True)
            else:
                st.info("No host entities are currently isolated in the active blocklist.")

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
        st.markdown(
            """
            <div class="sx-empty-card">
                <div class="sx-empty-icon">📋</div>
                <div class="sx-empty-title">Zero Containment Actions Recorded</div>
                <div class="sx-empty-desc">
                    SentinelX has not executed any host containment actions yet. When high-risk threats trigger containment policies, immutable execution logs will appear here.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )



# ==================================================
# FOOTER
# ==================================================

st.divider()

st.markdown(
    """
    <div style="text-align:center; padding:10px 0; color:#64748B; font-size:0.75rem;">
        <b style="color:#94A3B8;">SENTINELX</b> — Autonomous Security Operations Center Platform & Mini-SIEM<br>
        <span style="font-size:0.68rem; letter-spacing:0.5px; text-transform:uppercase;">Detection • Risk Scoring • MITRE ATT&CK • Gemini AI Investigation • Safe Containment • Forensic Audit</span>
    </div>
    """,
    unsafe_allow_html=True
)