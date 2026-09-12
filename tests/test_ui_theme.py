"""
Unit tests for SentinelX UI Theme and Design System.
"""

from services.ui_theme import (
    THEME_TOKENS,
    get_theme_css,
    render_app_header,
    render_briefing_bar,
    render_kpi_card,
    render_login_header,
    render_empty_state
)


def test_theme_tokens_presence():
    assert "bg_base" in THEME_TOKENS
    assert "accent_cyan" in THEME_TOKENS
    assert "critical" in THEME_TOKENS
    assert "high" in THEME_TOKENS
    assert "contained" in THEME_TOKENS


def test_theme_css_structure():
    css = get_theme_css()
    assert isinstance(css, str)
    assert "<style>" in css
    assert "</style>" in css
    assert "--sx-bg" in css
    assert ".sx-top-header" in css
    assert ".sx-kpi-card" in css
    assert "@media (max-width: 640px)" in css
    assert "sx-pulse" in css


def test_render_app_header():
    header_html = render_app_header("analyst", "ANALYST")
    assert "SENTINEL" in header_html
    assert "AUTONOMOUS SECURITY OPERATIONS CENTER" in header_html.upper()
    assert "TELEMETRY ONLINE" in header_html
    assert "SQLITE ENGINE" in header_html
    assert "AI ASSISTED" in header_html
    assert "CONTAINMENT READY" in header_html
    assert "ANALYST" in header_html


def test_render_kpi_card():
    card_html = render_kpi_card(
        label="Active Incidents",
        value=5,
        meta="Requiring response",
        accent_color="#EF4444",
        icon_svg="<svg></svg>"
    )
    assert "Active Incidents" in card_html
    assert "5" in card_html
    assert "Requiring response" in card_html
    assert "#EF4444" in card_html


def test_render_briefing_bar():
    bar_html = render_briefing_bar("GOOD", 2)
    assert "LIVE SOC SITUATIONAL BRIEFING" in bar_html
    assert "POSTURE: GOOD" in bar_html
    assert "ACTIVE THREATS: 2" in bar_html


def test_render_login_header_no_secrets():
    login_html = render_login_header()
    assert "SENTINEL" in login_html
    assert "Autonomous Security Operations Center" in login_html
    # Must NOT contain passwords or tokens
    assert "password" not in login_html.lower()
    assert "token" not in login_html.lower()
    assert "secret" not in login_html.lower()


def test_render_empty_state():
    empty_html = render_empty_state("No Incidents", "All clear", "🛡️")
    assert "No Incidents" in empty_html
    assert "All clear" in empty_html
    assert "🛡️" in empty_html
