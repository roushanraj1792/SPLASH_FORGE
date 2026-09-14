"""
SPLASH FORGE — Premium SOC Design System & UI Presentation Module

Provides:
- Design tokens (colors, surfaces, spacing, typography)
- Glassmorphism & technical grid styling for Streamlit
- Mobile-first responsive layout rules
- Reusable presentation components (Header, KPIs, Status Badges, Briefing Bar)
"""

# =====================================================================
# DESIGN SYSTEM TOKENS
# =====================================================================

THEME_TOKENS = {
    "bg_base": "#060A12",
    "bg_surface": "#0C1322",
    "bg_surface_alt": "#111B30",
    "bg_surface_raised": "#16233E",
    "border_subtle": "rgba(56, 189, 248, 0.12)",
    "border_active": "rgba(56, 189, 248, 0.40)",
    "border_light": "rgba(255, 255, 255, 0.06)",
    "accent_cyan": "#00E5FF",
    "accent_sky": "#38BDF8",
    "accent_indigo": "#6366F1",
    "text_primary": "#F8FAFC",
    "text_secondary": "#94A3B8",
    "text_muted": "#64748B",
    # Semantic security states
    "critical": "#EF4444",
    "high": "#F97316",
    "medium": "#FBBF24",
    "low": "#38BDF8",
    "contained": "#10B981",
    "resolved": "#6366F1",
    "success": "#10B981"
}


# =====================================================================
# MASTER CSS STYLESHEET
# =====================================================================

def get_theme_css() -> str:
    """Return the complete SentinelX CSS stylesheet."""
    return """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap');

    :root {
        --sx-bg: #060A12;
        --sx-surface: #0C1322;
        --sx-surface-alt: #111B30;
        --sx-surface-raised: #16233E;
        --sx-border: rgba(56, 189, 248, 0.14);
        --sx-border-subtle: rgba(255, 255, 255, 0.07);
        --sx-text-main: #F8FAFC;
        --sx-text-muted: #94A3B8;
        --sx-text-dim: #64748B;
        --sx-cyan: #38BDF8;
        --sx-cyan-bright: #00E5FF;
        --sx-indigo: #6366F1;
        --sx-critical: #EF4444;
        --sx-high: #F97316;
        --sx-medium: #FBBF24;
        --sx-low: #38BDF8;
        --sx-success: #10B981;
        --sx-radius-sm: 8px;
        --sx-radius-md: 14px;
        --sx-radius-lg: 18px;
    }

    /* Base Font & Shell */
    html, body, [data-testid="stAppViewContainer"] {
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif !important;
        background-color: #060A12 !important;
        background-image:
            linear-gradient(rgba(56, 189, 248, 0.035) 1px, transparent 1px),
            linear-gradient(90deg, rgba(56, 189, 248, 0.035) 1px, transparent 1px),
            radial-gradient(ellipse at 50% 0%, rgba(14, 165, 233, 0.09) 0%, transparent 65%) !important;
        background-size: 36px 36px, 36px 36px, 100% 100% !important;
        background-attachment: fixed !important;
        color: #F8FAFC !important;
    }

    [data-testid="stHeader"] {
        background: rgba(6, 10, 18, 0.85) !important;
        backdrop-filter: blur(14px) !important;
        -webkit-backdrop-filter: blur(14px) !important;
        border-bottom: 1px solid rgba(56, 189, 248, 0.08) !important;
    }

    section[data-testid="stSidebar"],
    [data-testid="collapsedControl"] {
        display: none !important;
    }

    .main .block-container {
        max-width: 1560px !important;
        width: 100% !important;
        margin: 0 auto !important;
        padding: 12px 24px 36px !important;
        color: #F8FAFC !important;
    }

    /* Headings & Typography */
    h1, h2, h3, h4, h5, h6 {
        font-family: 'Plus Jakarta Sans', sans-serif !important;
        color: #F8FAFC !important;
        font-weight: 700 !important;
        letter-spacing: -0.3px !important;
    }

    h1 { font-size: 1.40rem !important; margin-bottom: 3px !important; }
    h2, h3 { font-size: 1.15rem !important; margin-top: 8px !important; margin-bottom: 6px !important; }

    .stCaption, p, span, label, [data-testid="stMarkdownContainer"] p {
        color: #F8FAFC;
        font-family: 'Plus Jakarta Sans', sans-serif;
    }

    .stCaption {
        color: #94A3B8 !important;
        font-size: 0.80rem !important;
    }

    hr {
        border-color: rgba(56, 189, 248, 0.12) !important;
        opacity: 0.8 !important;
        margin: 16px 0 !important;
    }

    /* Monospace elements */
    code, pre, .sx-mono, [data-testid="stCodeBlock"] {
        font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace !important;
    }

    /* Global Glassmorphism Panels */
    .sx-glass-panel,
    .sx-panel,
    [data-testid="stVerticalBlockBorderWrapper"] > div {
        background: rgba(12, 19, 34, 0.75) !important;
        backdrop-filter: blur(16px) !important;
        -webkit-backdrop-filter: blur(16px) !important;
        border: 1px solid rgba(56, 189, 248, 0.13) !important;
        border-radius: var(--sx-radius-md) !important;
        padding: 16px 18px !important;
        margin-bottom: 12px !important;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.35) !important;
    }

    /* Top Command Header */
    .sx-top-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 16px;
        padding: 12px 20px;
        margin-bottom: 12px;
        border-radius: var(--sx-radius-md);
        background: rgba(12, 19, 34, 0.82) !important;
        backdrop-filter: blur(16px) !important;
        -webkit-backdrop-filter: blur(16px) !important;
        border: 1px solid rgba(56, 189, 248, 0.16) !important;
        box-shadow: 0 4px 24px rgba(0, 0, 0, 0.4), inset 0 1px 0 rgba(255, 255, 255, 0.05);
    }

    .sx-brand-wrapper {
        display: flex;
        align-items: center;
        gap: 14px;
    }

    .sx-brand-text {
        display: flex;
        flex-direction: column;
        gap: 2px;
    }

    .sx-brand-title {
        font-size: 1.35rem;
        font-weight: 900;
        letter-spacing: 2px;
        color: #F8FAFC;
        line-height: 1.1;
    }

    .sx-brand-sub {
        font-size: 0.65rem;
        font-weight: 700;
        letter-spacing: 1.4px;
        color: #94A3B8;
        text-transform: uppercase;
    }

    .sx-top-status-right {
        display: flex;
        flex-direction: column;
        align-items: flex-end;
        gap: 4px;
        text-align: right;
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
        gap: 6px;
        padding: 3px 9px;
        border-radius: 6px;
        font-size: 0.64rem;
        font-weight: 700;
        letter-spacing: 0.6px;
        text-transform: uppercase;
        background: rgba(17, 27, 48, 0.8);
        border: 1px solid rgba(56, 189, 248, 0.16);
        color: #94A3B8;
    }

    .sx-chip-green {
        background: rgba(16, 185, 129, 0.10);
        border: 1px solid rgba(16, 185, 129, 0.32);
        color: #10B981;
    }

    .sx-chip-cyan {
        background: rgba(56, 189, 248, 0.10);
        border: 1px solid rgba(56, 189, 248, 0.32);
        color: #38BDF8;
    }

    .sx-chip-indigo {
        background: rgba(99, 102, 241, 0.10);
        border: 1px solid rgba(99, 102, 241, 0.32);
        color: #818CF8;
    }

    .sx-chip-dot {
        width: 6px;
        height: 6px;
        border-radius: 50%;
        display: inline-block;
    }

    .sx-dot-green { background: #10B981; box-shadow: 0 0 6px rgba(16, 185, 129, 0.7); }
    .sx-dot-cyan { background: #38BDF8; box-shadow: 0 0 6px rgba(56, 189, 248, 0.7); }
    .sx-dot-indigo { background: #818CF8; box-shadow: 0 0 6px rgba(129, 140, 248, 0.7); }

    /* Live Pulse Animation */
    @keyframes sx-pulse {
        0% { transform: scale(0.95); opacity: 0.8; box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
        70% { transform: scale(1.05); opacity: 1; box-shadow: 0 0 0 6px rgba(16, 185, 129, 0); }
        100% { transform: scale(0.95); opacity: 0.8; box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
    }

    .sx-live-dot {
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background: #10B981;
        display: inline-block;
        animation: sx-pulse 2s infinite ease-in-out;
    }

    /* Briefing Bar */
    .sx-briefing-bar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        background: rgba(12, 19, 34, 0.75);
        backdrop-filter: blur(14px);
        -webkit-backdrop-filter: blur(14px);
        border: 1px solid rgba(56, 189, 248, 0.14);
        border-left: 3px solid #38BDF8;
        border-radius: var(--sx-radius-md);
        padding: 10px 16px;
        margin-bottom: 14px;
        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.25);
    }

    .sx-briefing-left {
        display: flex;
        align-items: center;
        gap: 10px;
        flex-wrap: wrap;
    }

    .sx-briefing-title {
        font-size: 0.72rem;
        font-weight: 800;
        letter-spacing: 0.8px;
        color: #F1F5F9;
        text-transform: uppercase;
    }

    .sx-briefing-divider {
        color: #38BDF8;
        font-size: 0.80rem;
    }

    .sx-briefing-text {
        color: #94A3B8;
        font-size: 0.80rem;
    }

    .sx-briefing-right {
        display: flex;
        align-items: center;
        gap: 8px;
        flex-wrap: wrap;
    }

    /* Premium KPI Cards */
    .sx-kpi-card {
        background: rgba(12, 19, 34, 0.75);
        backdrop-filter: blur(16px);
        -webkit-backdrop-filter: blur(16px);
        border: 1px solid rgba(56, 189, 248, 0.14);
        border-radius: var(--sx-radius-md);
        padding: 14px 16px;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        min-height: 104px;
        box-shadow: 0 4px 18px rgba(0, 0, 0, 0.3);
        transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
        position: relative;
        overflow: hidden;
    }

    .sx-kpi-card:hover {
        transform: translateY(-2px);
        border-color: rgba(56, 189, 248, 0.35);
        box-shadow: 0 6px 24px rgba(0, 0, 0, 0.4), 0 0 16px rgba(56, 189, 248, 0.12);
    }

    .sx-kpi-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 4px;
    }

    .sx-kpi-label {
        color: #94A3B8;
        font-size: 0.68rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.8px;
    }

    .sx-kpi-icon {
        width: 26px;
        height: 26px;
        border-radius: 6px;
        display: flex;
        align-items: center;
        justify-content: center;
        flex-shrink: 0;
    }

    .sx-kpi-value {
        font-size: 1.75rem;
        font-weight: 800;
        line-height: 1.1;
        font-family: 'JetBrains Mono', ui-monospace, monospace;
        margin: 4px 0 2px;
        letter-spacing: -0.5px;
    }

    .sx-kpi-meta {
        color: #64748B;
        font-size: 0.70rem;
        margin-top: 4px;
        display: flex;
        align-items: center;
        gap: 6px;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }

    /* Visual SOC Pipeline Bar */
    .sx-pipeline-row {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 4px;
        overflow-x: auto;
        padding: 4px 0;
    }

    .sx-pipe-box {
        flex: 1;
        min-width: 90px;
        background: rgba(17, 27, 48, 0.7);
        border: 1px solid rgba(56, 189, 248, 0.12);
        border-radius: var(--sx-radius-sm);
        padding: 8px 6px;
        text-align: center;
        transition: border-color 0.2s ease, background 0.2s ease;
    }

    .sx-pipe-box:hover {
        border-color: #38BDF8;
        background: rgba(22, 35, 62, 0.85);
    }

    .sx-pipe-step {
        font-size: 0.60rem;
        font-weight: 800;
        color: #38BDF8;
        font-family: 'JetBrains Mono', monospace;
        letter-spacing: 0.5px;
    }

    .sx-pipe-title {
        font-size: 0.72rem;
        font-weight: 700;
        color: #F1F5F9;
        margin: 2px 0 1px;
        white-space: nowrap;
    }

    .sx-pipe-sub {
        font-size: 0.58rem;
        color: #64748B;
        white-space: nowrap;
    }

    .sx-pipe-arrow {
        color: #38BDF8;
        font-size: 0.72rem;
        font-weight: 700;
        opacity: 0.6;
        user-select: none;
        padding: 0 2px;
    }

    /* Buttons */
    .stButton > button,
    .stDownloadButton > button {
        background: rgba(17, 27, 48, 0.85) !important;
        color: #94A3B8 !important;
        border: 1px solid rgba(56, 189, 248, 0.18) !important;
        border-radius: var(--sx-radius-sm) !important;
        padding: 8px 14px !important;
        font-weight: 600 !important;
        font-size: 0.82rem !important;
        letter-spacing: 0.2px !important;
        transition: all 0.2s ease !important;
        min-height: 38px !important;
    }

    .stButton > button:hover,
    .stDownloadButton > button:hover {
        background: rgba(22, 35, 62, 0.95) !important;
        border-color: #38BDF8 !important;
        color: #F8FAFC !important;
        box-shadow: 0 0 12px rgba(56, 189, 248, 0.22) !important;
    }

    .stButton > button[kind="primary"],
    .stDownloadButton > button[kind="primary"],
    [data-testid="baseButton-primary"] {
        background: rgba(14, 41, 66, 0.95) !important;
        border: 1px solid #38BDF8 !important;
        color: #38BDF8 !important;
        font-weight: 700 !important;
        box-shadow: 0 0 14px rgba(56, 189, 248, 0.28) !important;
    }

    /* Form Inputs */
    .stTextInput input, .stSelectbox select, div[data-baseweb="input"] {
        background: rgba(17, 27, 48, 0.8) !important;
        border: 1px solid rgba(56, 189, 248, 0.18) !important;
        border-radius: var(--sx-radius-sm) !important;
        color: #F8FAFC !important;
    }

    div[data-baseweb="input"]:focus-within {
        border-color: #38BDF8 !important;
        box-shadow: 0 0 10px rgba(56, 189, 248, 0.25) !important;
    }

    /* High-Density DataFrames & Tables */
    [data-testid="stDataFrame"], [data-testid="stTable"] {
        border: 1px solid rgba(56, 189, 248, 0.14) !important;
        border-radius: var(--sx-radius-md) !important;
        background: rgba(12, 19, 34, 0.75) !important;
        overflow-x: auto !important;
        -webkit-overflow-scrolling: touch !important;
    }

    table {
        background: transparent !important;
        color: #F1F5F9 !important;
        border-collapse: collapse !important;
        width: 100% !important;
    }

    th {
        background: rgba(17, 27, 48, 0.95) !important;
        color: #94A3B8 !important;
        font-size: 0.72rem !important;
        font-weight: 700 !important;
        text-transform: uppercase !important;
        letter-spacing: 0.8px !important;
        padding: 10px 12px !important;
        border-bottom: 1px solid rgba(56, 189, 248, 0.18) !important;
    }

    td {
        padding: 8px 12px !important;
        border-bottom: 1px solid rgba(255, 255, 255, 0.05) !important;
        font-size: 0.82rem !important;
        color: #F1F5F9 !important;
    }

    tr:hover td {
        background: rgba(22, 35, 62, 0.5) !important;
    }

    /* Semantic Badges */
    .sx-badge {
        display: inline-flex;
        align-items: center;
        gap: 5px;
        padding: 3px 8px;
        border-radius: 5px;
        font-size: 0.68rem;
        font-weight: 700;
        letter-spacing: 0.5px;
        text-transform: uppercase;
        font-family: 'JetBrains Mono', monospace;
    }

    .sx-badge-critical { background: rgba(239, 68, 68, 0.14); color: #EF4444; border: 1px solid rgba(239, 68, 68, 0.35); }
    .sx-badge-high { background: rgba(249, 115, 22, 0.14); color: #F97316; border: 1px solid rgba(249, 115, 22, 0.35); }
    .sx-badge-medium { background: rgba(251, 191, 36, 0.14); color: #FBBF24; border: 1px solid rgba(251, 191, 36, 0.35); }
    .sx-badge-low { background: rgba(56, 189, 248, 0.14); color: #38BDF8; border: 1px solid rgba(56, 189, 248, 0.35); }
    .sx-badge-success, .sx-badge-contained { background: rgba(16, 185, 129, 0.14); color: #10B981; border: 1px solid rgba(16, 185, 129, 0.35); }
    .sx-badge-resolved { background: rgba(99, 102, 241, 0.14); color: #818CF8; border: 1px solid rgba(99, 102, 241, 0.35); }

    /* Incident Lifecycle Stepper */
    .sx-stepper {
        display: flex;
        align-items: center;
        gap: 8px;
        margin: 8px 0 16px;
        overflow-x: auto;
        padding-bottom: 4px;
    }

    .sx-step {
        flex: 1;
        min-width: 95px;
        padding: 8px 10px;
        border-radius: var(--sx-radius-sm);
        text-align: center;
        font-size: 0.72rem;
        font-weight: 700;
        letter-spacing: 0.5px;
        background: rgba(17, 27, 48, 0.7);
        border: 1px solid rgba(56, 189, 248, 0.12);
        color: #64748B;
        transition: all 0.2s ease;
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
        box-shadow: 0 0 10px rgba(56, 189, 248, 0.3);
    }

    .sx-stepper-sep {
        color: rgba(56, 189, 248, 0.35);
        font-weight: bold;
        font-size: 0.80rem;
        user-select: none;
    }

    /* AI Copilot Panel */
    .sx-ai-report {
        background: rgba(12, 19, 34, 0.8);
        border: 1px solid rgba(56, 189, 248, 0.16);
        border-top: 3px solid #6366F1;
        border-radius: var(--sx-radius-md);
        padding: 18px 20px;
        margin-top: 12px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.35);
    }

    .sx-ai-banner {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding-bottom: 12px;
        margin-bottom: 14px;
        border-bottom: 1px solid rgba(56, 189, 248, 0.12);
        flex-wrap: wrap;
        gap: 8px;
    }

    .sx-ai-section-title {
        font-size: 0.76rem;
        font-weight: 800;
        color: #38BDF8;
        text-transform: uppercase;
        letter-spacing: 0.8px;
        margin-top: 12px;
        margin-bottom: 6px;
        display: flex;
        align-items: center;
        gap: 6px;
    }

    .sx-ai-text {
        color: #F1F5F9;
        font-size: 0.84rem;
        line-height: 1.6;
        background: rgba(17, 27, 48, 0.6);
        border: 1px solid rgba(56, 189, 248, 0.10);
        border-radius: var(--sx-radius-sm);
        padding: 10px 14px;
        margin-bottom: 10px;
    }

    /* Clean Scrollbars */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: #060A12; }
    ::-webkit-scrollbar-thumb { background: rgba(56, 189, 248, 0.2); border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: #38BDF8; }

    /* =================================================================
       MOBILE-FIRST RESPONSIVE MEDIA QUERIES
       ================================================================= */

    @media (max-width: 900px) {
        .sx-top-header {
            flex-direction: column !important;
            align-items: flex-start !important;
            gap: 12px !important;
            padding: 12px 16px !important;
        }
        .sx-top-status-right {
            align-items: flex-start !important;
            text-align: left !important;
            width: 100% !important;
        }
        .sx-briefing-bar {
            flex-direction: column !important;
            align-items: flex-start !important;
            gap: 8px !important;
        }
        .sx-kpi-card {
            min-height: 90px !important;
        }
    }

    @media (max-width: 640px) {
        .main .block-container {
            padding: 8px 12px 28px !important;
        }
        .sx-brand-title {
            font-size: 1.15rem !important;
        }
        .sx-brand-sub {
            font-size: 0.58rem !important;
        }
        .sx-chips-row {
            gap: 4px !important;
        }
        .sx-chip {
            font-size: 0.58rem !important;
            padding: 2px 6px !important;
        }
        .stButton > button,
        .stDownloadButton > button {
            padding: 8px 10px !important;
            font-size: 0.78rem !important;
            min-height: 42px !important;
        }
        .sx-kpi-value {
            font-size: 1.45rem !important;
        }
        .sx-stepper {
            flex-wrap: wrap !important;
        }
        .sx-step {
            min-width: 80px !important;
            font-size: 0.65rem !important;
            padding: 6px 8px !important;
        }
    }
    </style>
    """


# =====================================================================
# HTML COMPONENT RENDERERS
# =====================================================================

def render_app_header(username: str, role: str) -> str:
    """Render the SentinelX global app command header."""
    user_disp = (username or "analyst").upper()
    role_disp = (role or "ANALYST").upper()

    return f"""
    <div class="sx-top-header">
        <div class="sx-brand-wrapper">
            <svg width="44" height="44" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg" style="flex-shrink:0;">
                <path d="M24 3.5L7 10.5V22C7 33.2 14.3 43.5 24 46C33.7 43.5 41 33.2 41 22V10.5L24 3.5Z" stroke="#38BDF8" stroke-width="2.4" stroke-linejoin="round" fill="rgba(56, 189, 248, 0.08)"/>
                <path d="M24 8L11.5 13.8V22C11.5 30.5 16.8 38.3 24 40.8C31.2 38.3 36.5 30.5 36.5 22V13.8L24 8Z" stroke="rgba(99, 102, 241, 0.5)" stroke-width="1.5" stroke-linejoin="round" fill="none"/>
                <path d="M16.5 17.5L31.5 30.5M31.5 17.5L16.5 30.5" stroke="#38BDF8" stroke-width="2.8" stroke-linecap="round"/>
                <circle cx="24" cy="24" r="3.2" fill="#38BDF8" stroke="#060A12" stroke-width="1.6"/>
            </svg>
            <div class="sx-brand-text">
                <div class="sx-brand-title" data-engine="SENTINELX">SPLASH <span style="color:#38BDF8;">FORGE</span></div>
                <div class="sx-brand-sub">Autonomous Security Operations Center</div>
            </div>
        </div>
        <div class="sx-top-status-right">
            <div class="sx-chips-row" style="margin-top:0;">
                <span class="sx-chip sx-chip-green"><span class="sx-live-dot"></span>TELEMETRY ONLINE</span>
                <span class="sx-chip sx-chip-cyan"><span class="sx-chip-dot sx-dot-cyan"></span>SQLITE ENGINE</span>
                <span class="sx-chip sx-chip-indigo"><span class="sx-chip-dot sx-dot-indigo"></span>AI ASSISTED</span>
                <span class="sx-chip sx-chip-green"><span class="sx-chip-dot sx-dot-green"></span>CONTAINMENT READY</span>
                <span class="sx-chip" style="border:1px solid rgba(56,189,248,0.4); color:#38BDF8;">
                    👤 {user_disp} [{role_disp}]
                </span>
            </div>
        </div>
    </div>
    """


def render_briefing_bar(posture_label: str, active_incidents: int) -> str:
    """Render the operations briefing bar."""
    threat_bg = "rgba(239, 68, 68, 0.12)" if active_incidents > 0 else "rgba(16, 185, 129, 0.12)"
    threat_color = "#EF4444" if active_incidents > 0 else "#10B981"
    threat_border = "rgba(239, 68, 68, 0.3)" if active_incidents > 0 else "rgba(16, 185, 129, 0.3)"

    return f"""
    <div class="sx-briefing-bar">
        <div class="sx-briefing-left">
            <span class="sx-live-dot"></span>
            <span class="sx-briefing-title">LIVE SOC SITUATIONAL BRIEFING</span>
            <span class="sx-briefing-divider">•</span>
            <span class="sx-briefing-text">All 5 detection engines synchronized. Deterministic risk correlation & host containment active.</span>
        </div>
        <div class="sx-briefing-right">
            <span class="sx-badge sx-badge-success">POSTURE: {posture_label}</span>
            <span class="sx-badge" style="background:{threat_bg}; color:{threat_color}; border:1px solid {threat_border};">ACTIVE THREATS: {active_incidents}</span>
        </div>
    </div>
    """


def render_kpi_card(
    label: str,
    value,
    meta: str,
    accent_color: str = "#38BDF8",
    icon_svg: str = ""
) -> str:
    """Render a single glassmorphic KPI card with 14px border radius."""
    bg_color = f"rgba({int(accent_color[1:3], 16)}, {int(accent_color[3:5], 16)}, {int(accent_color[5:7], 16)}, 0.12)" if len(accent_color) == 7 and accent_color.startswith('#') else "rgba(56, 189, 248, 0.12)"

    return f"""
    <div class="sx-kpi-card">
        <div class="sx-kpi-header">
            <span class="sx-kpi-label">{label}</span>
            <div class="sx-kpi-icon" style="background:{bg_color}; color:{accent_color};">
                {icon_svg}
            </div>
        </div>
        <div class="sx-kpi-value" style="color:{accent_color};">{value}</div>
        <div class="sx-kpi-meta">
            <span class="sx-chip-dot" style="background:{accent_color};"></span> {meta}
        </div>
    </div>
    """


def render_login_header() -> str:
    """Render the centered brand lockup for login screen without exposing credentials."""
    return """
    <div style="max-width: 460px; margin: 40px auto 16px; text-align: center;">
        <div class="sx-brand-wrapper" style="justify-content: center; margin-bottom: 12px;">
            <svg width="60" height="60" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M24 3.5L7 10.5V22C7 33.2 14.3 43.5 24 46C33.7 43.5 41 33.2 41 22V10.5L24 3.5Z" stroke="#38BDF8" stroke-width="2.4" stroke-linejoin="round" fill="rgba(56, 189, 248, 0.08)"/>
                <path d="M24 8L11.5 13.8V22C11.5 30.5 16.8 38.3 24 40.8C31.2 38.3 36.5 30.5 36.5 22V13.8L24 8Z" stroke="rgba(99, 102, 241, 0.5)" stroke-width="1.5" stroke-linejoin="round" fill="none"/>
                <path d="M16.5 17.5L31.5 30.5M31.5 17.5L16.5 30.5" stroke="#38BDF8" stroke-width="2.8" stroke-linecap="round"/>
                <circle cx="24" cy="24" r="3.2" fill="#38BDF8" stroke="#060A12" stroke-width="1.6"/>
            </svg>
        </div>
        <div style="font-size: 1.70rem; font-weight: 900; letter-spacing: 2px; color: #F8FAFC;" data-engine="SENTINELX">
            SPLASH <span style="color: #38BDF8;">FORGE</span>
        </div>
        <div style="font-size: 0.72rem; font-weight: 700; letter-spacing: 1.4px; color: #94A3B8; text-transform: uppercase; margin-top: 4px; margin-bottom: 24px;">
            Autonomous Security Operations Center
        </div>
    </div>
    """


def render_empty_state(title: str, description: str, icon: str = "🛡️") -> str:
    """Render a clean empty state card."""
    return f"""
    <div class="sx-panel" style="text-align: center; padding: 36px 20px; border-style: dashed; margin: 12px 0;">
        <div style="font-size: 2rem; margin-bottom: 8px; opacity: 0.85;">{icon}</div>
        <div style="font-size: 0.95rem; font-weight: 700; color: #F8FAFC; margin-bottom: 4px;">{title}</div>
        <div style="font-size: 0.80rem; color: #94A3B8; max-width: 480px; margin: 0 auto;">{description}</div>
    </div>
    """
