# SentinelX Risk Engine

SEVERITY_SCORES = {
    "LOW": 20,
    "MEDIUM": 45,
    "HIGH": 70,
    "CRITICAL": 90
}


def calculate_risk_score(alert):
    severity = alert.get("severity", "LOW").upper()

    score = SEVERITY_SCORES.get(
        severity,
        SEVERITY_SCORES["LOW"]
    )

    return score


def get_risk_level(score):
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    else:
        return "LOW"


def enrich_alert_with_risk(alert):
    score = calculate_risk_score(alert)
    risk_level = get_risk_level(score)

    enriched_alert = dict(alert)

    enriched_alert["risk_score"] = score
    enriched_alert["risk_level"] = risk_level

    return enriched_alert
