# SentinelX Risk Engine

SEVERITY_SCORES = {
    "LOW": 20,
    "MEDIUM": 45,
    "HIGH": 70,
    "CRITICAL": 90
}


def calculate_risk_score(alert):
    if not alert or not isinstance(alert, dict):
        return SEVERITY_SCORES["LOW"]

    severity = str(alert.get("severity") or "LOW").strip().upper()

    score = SEVERITY_SCORES.get(
        severity,
        SEVERITY_SCORES["LOW"]
    )

    return score


def get_risk_level(score):
    try:
        score_val = float(score)
    except (ValueError, TypeError):
        score_val = 0.0

    if score_val >= 80:
        return "CRITICAL"
    elif score_val >= 60:
        return "HIGH"
    elif score_val >= 30:
        return "MEDIUM"
    else:
        return "LOW"


def enrich_alert_with_risk(alert):
    if not alert or not isinstance(alert, dict):
        alert_dict = {}
    else:
        alert_dict = dict(alert)

    score = calculate_risk_score(alert_dict)
    risk_level = get_risk_level(score)

    alert_dict["risk_score"] = score
    alert_dict["risk_level"] = risk_level

    return alert_dict
