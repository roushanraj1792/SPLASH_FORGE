from database.database import get_incidents


ACTIVE_STATUSES = {
    "NEW",
    "TRIAGED",
    "INVESTIGATING"
}


def calculate_security_posture():
    incidents = get_incidents(100)

    if not incidents:
        return {
            "score": 100,
            "label": "EXCELLENT",
            "details": {
                "active_incidents": 0,
                "high_critical_incidents": 0,
                "contained_incidents": 0,
                "resolved_incidents": 0
            }
        }

    active_incidents = [
        incident
        for incident in incidents
        if incident["status"] in ACTIVE_STATUSES
    ]

    high_critical_incidents = [
        incident
        for incident in active_incidents
        if incident["severity"] in ["HIGH", "CRITICAL"]
    ]

    contained_incidents = [
        incident
        for incident in incidents
        if incident["status"] == "CONTAINED"
    ]

    resolved_incidents = [
        incident
        for incident in incidents
        if incident["status"] == "RESOLVED"
    ]

    score = 100

    # Active high/critical threats reduce posture.
    score -= len(high_critical_incidents) * 5

    # Other active incidents reduce posture slightly.
    other_active_incidents = (
        len(active_incidents)
        - len(high_critical_incidents)
    )

    score -= other_active_incidents * 2

    # Successful containment improves posture.
    score += min(
        len(contained_incidents) * 2,
        15
    )

    # Resolved incidents provide a small positive signal.
    score += min(
        len(resolved_incidents),
        10
    )

    score = max(
        0,
        min(score, 100)
    )

    if score >= 90:
        label = "EXCELLENT"
    elif score >= 75:
        label = "GOOD"
    elif score >= 50:
        label = "MODERATE"
    elif score >= 25:
        label = "POOR"
    else:
        label = "CRITICAL"

    return {
        "score": score,
        "label": label,
        "details": {
            "active_incidents": len(active_incidents),
            "high_critical_incidents": len(
                high_critical_incidents
            ),
            "contained_incidents": len(
                contained_incidents
            ),
            "resolved_incidents": len(
                resolved_incidents
            )
        }
    }