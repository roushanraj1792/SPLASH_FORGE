from services.risk_engine import (
    calculate_risk_score,
    get_risk_level,
    enrich_alert_with_risk,
)


def test_risk_scores_and_levels():
    expected = {
        "LOW": (20, "LOW"),
        "MEDIUM": (45, "MEDIUM"),
        "HIGH": (70, "HIGH"),
        "CRITICAL": (90, "CRITICAL"),
    }

    for severity, (expected_score, expected_level) in expected.items():
        alert = {"severity": severity}

        score = calculate_risk_score(alert)
        level = get_risk_level(score)

        assert score == expected_score, (
            f"{severity}: expected score {expected_score}, got {score}"
        )

        assert level == expected_level, (
            f"{severity}: expected level {expected_level}, got {level}"
        )


def test_alert_risk_enrichment():
    alert = {
        "alert_type": "BRUTE_FORCE",
        "severity": "HIGH",
        "source_ip": "192.168.1.50",
    }

    enriched = enrich_alert_with_risk(alert)

    assert enriched["risk_score"] == 70
    assert enriched["risk_level"] == "HIGH"
    assert enriched["alert_type"] == "BRUTE_FORCE"
    assert enriched["source_ip"] == "192.168.1.50"
