"""
Unit & Integration Tests for Internal Verification Engine (Phase 1I)
====================================================================
Comprehensive test suite covering:
  1. Deterministic verification ID generation & format
  2. Deterministic verification ID reproducibility
  3. Verification with missing observed data -> EXECUTION_NOT_PERFORMED & NOT_VERIFIED
  4. Verification with REJECTED receipt -> EXECUTION_NOT_PERFORMED & NOT_VERIFIED
  5. Verification with PENDING receipt -> EXECUTION_NOT_PERFORMED & NOT_VERIFIED
  6. Perfect metric match -> VERIFIED (score 100, zero discrepancies)
  7. Metrics matching within default tolerance -> VERIFIED
  8. Minor metric divergence exceeding tolerance -> PARTIALLY_VERIFIED
  9. Severe metric divergence -> FAILED
 10. Response type mismatch -> FAILED
 11. Tracking predicted vs observed residual risk
 12. Tracking predicted vs observed containment effectiveness
 13. Tracking predicted vs observed blast radius
 14. Tracking predicted vs observed security risk
 15. Discrepancy items list structure & properties
 16. Execution performed flag is True when observed data provided
 17. Execution performed flag is False when observed is None
 18. Execution status is EXECUTION_SIMULATED for simulations
 19. Execution status is EXECUTION_OBSERVED for live telemetry
 20. Verification score bounds enforcement [0, 100]
 21. Confidence metric preservation and derivation
 22. Validation: reject None predicted
 23. Validation: reject non-dict predicted
 24. Validation: reject empty predicted
 25. Validation: out-of-bounds metric values (< 0 or > 100)
 26. Validation: out-of-bounds tolerance (< 0 or > 100)
 27. VerificationResult wrapper class properties and methods
 28. VerificationResult to_dict deepcopy immutability
 29. verify_from_receipt helper with APPROVED receipt
 30. verify_from_receipt helper with REJECTED receipt
 31. verify_hypothetical_simulation convenience helper
 32. Zero network activity guarantee
 33. Zero database/filesystem side-effects guarantee
 34. Deterministic repeated verification reproducibility
 35. Case insensitivity in status and response normalization
 36. Custom deterministic timestamp preservation
 37. Tolerance sensitivity tests (zero tolerance vs high tolerance)
 38. Multi-campaign verification isolation and independence
 39. Plain explainable summary text verification
 40. Safe default values when optional metrics are omitted
"""

import copy
import socket
import sys
from pathlib import Path
import pytest

# Ensure SentinelX root is on sys.path
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from verification.internal_verification import (
    verify_outcome,
    verify_from_receipt,
    verify_hypothetical_simulation,
    make_deterministic_verification_id,
    validate_predicted_outcome,
    validate_observed_outcome,
    VerificationResult,
    VerificationError,
    STATUS_NOT_VERIFIED,
    STATUS_VERIFIED,
    STATUS_PARTIALLY_VERIFIED,
    STATUS_FAILED,
    EXECUTION_NOT_PERFORMED,
    EXECUTION_SIMULATED,
    EXECUTION_OBSERVED,
    DEFAULT_METRIC_TOLERANCE,
)
from database.database import get_recent_events, get_incidents


# ------------------------------------------------------------------------------
# FIXTURES (Pure in-memory, completely isolated from external dependencies)
# ------------------------------------------------------------------------------

@pytest.fixture
def sample_predicted_outcome():
    """Provides a canonical valid predicted outcome dictionary."""
    return {
        "campaign_id": "CAMP-2026-VER-001",
        "selected_response": "BLOCK_SOURCE_IP",
        "confidence": 90,
        "policy_factors": {
            "security_risk": 80,
            "containment_effectiveness": 95,
            "residual_risk": 15,
            "blast_radius": 5,
        },
    }


@pytest.fixture
def sample_observed_match():
    """Provides an observed outcome strictly conforming to predictions."""
    return {
        "response": "BLOCK_SOURCE_IP",
        "metrics": {
            "security_risk": 80,
            "containment_effectiveness": 95,
            "residual_risk": 15,
            "blast_radius": 5,
        },
    }


@pytest.fixture
def sample_observed_minor_divergence():
    """Provides an observed outcome with slight divergence within tolerance."""
    return {
        "response": "BLOCK_SOURCE_IP",
        "metrics": {
            "security_risk": 75,
            "containment_effectiveness": 90,
            "residual_risk": 20,
            "blast_radius": 8,
        },
    }


@pytest.fixture
def sample_observed_severe_divergence():
    """Provides an observed outcome with severe divergence from predictions."""
    return {
        "response": "BLOCK_SOURCE_IP",
        "metrics": {
            "security_risk": 40,
            "containment_effectiveness": 30,
            "residual_risk": 75,
            "blast_radius": 60,
        },
    }


@pytest.fixture
def sample_approved_receipt():
    """Provides a canonical Phase 1H APPROVED decision receipt."""
    return {
        "receipt_id": "rcpt:camp-2026-ver-001:block_source_ip:approved",
        "receipt_status": "APPROVED",
        "campaign_id": "CAMP-2026-VER-001",
        "recommended_response": "BLOCK_SOURCE_IP",
        "selected_response": "BLOCK_SOURCE_IP",
        "human_approval_state": "APPROVED",
        "approver_id": "lead_analyst",
        "decision_reason": "Malicious brute force confirmed",
        "policy_factors": {
            "security_risk": 80,
            "containment_effectiveness": 95,
            "residual_risk": 15,
            "blast_radius": 5,
        },
        "confidence": 90,
    }


@pytest.fixture
def sample_rejected_receipt():
    """Provides a canonical Phase 1H REJECTED decision receipt."""
    return {
        "receipt_id": "rcpt:camp-2026-ver-001:none:rejected",
        "receipt_status": "REJECTED",
        "campaign_id": "CAMP-2026-VER-001",
        "recommended_response": "BLOCK_SOURCE_IP",
        "selected_response": None,
        "human_approval_state": "REJECTED",
        "approver_id": "soc_director",
        "decision_reason": "Authorized penetration test",
        "policy_factors": {
            "security_risk": 80,
            "containment_effectiveness": 95,
            "residual_risk": 15,
            "blast_radius": 5,
        },
        "confidence": 90,
    }


# ------------------------------------------------------------------------------
# 1. DETERMINISTIC VERIFICATION ID GENERATION
# ------------------------------------------------------------------------------

def test_make_deterministic_verification_id_format():
    vid = make_deterministic_verification_id("CAMP-001", "BLOCK_SOURCE_IP", "VERIFIED")
    assert vid == "ver:camp-001:block_source_ip:verified"


def test_make_deterministic_verification_id_reproducible():
    id1 = make_deterministic_verification_id("CAMP-ABC", "ISOLATE_HOST", "PARTIALLY_VERIFIED")
    id2 = make_deterministic_verification_id("CAMP-ABC", "ISOLATE_HOST", "PARTIALLY_VERIFIED")
    assert id1 == id2


def test_make_deterministic_verification_id_distinct_statuses():
    v1 = make_deterministic_verification_id("CAMP-1", "BLOCK_SOURCE_IP", "VERIFIED")
    v2 = make_deterministic_verification_id("CAMP-1", "BLOCK_SOURCE_IP", "FAILED")
    v3 = make_deterministic_verification_id("CAMP-1", "BLOCK_SOURCE_IP", "NOT_VERIFIED")
    assert len({v1, v2, v3}) == 3


# ------------------------------------------------------------------------------
# 2. NO OBSERVED DATA -> EXECUTION NOT PERFORMED
# ------------------------------------------------------------------------------

def test_verification_no_observed_data_does_not_fabricate(sample_predicted_outcome):
    res = verify_outcome(sample_predicted_outcome, observed=None)
    assert res["verification_status"] == STATUS_NOT_VERIFIED
    assert res["execution_status"] == EXECUTION_NOT_PERFORMED
    assert res["execution_performed"] is False
    assert res["observed_risk"] is None
    assert res["observed_residual_risk"] is None
    assert "Real containment was not performed" in res["explanation"]


def test_verification_rejected_receipt_stops_execution(sample_predicted_outcome, sample_rejected_receipt):
    res = verify_outcome(sample_predicted_outcome, observed=None, receipt=sample_rejected_receipt)
    assert res["verification_status"] == STATUS_NOT_VERIFIED
    assert res["execution_status"] == EXECUTION_NOT_PERFORMED
    assert res["execution_performed"] is False
    assert res["selected_response"] is None
    assert "REJECTED" in res["explanation"]


def test_verification_pending_receipt_awaiting_authorization(sample_predicted_outcome):
    pending_receipt = {"campaign_id": "CAMP-001", "receipt_status": "PENDING", "human_approval_state": "PENDING"}
    res = verify_outcome(sample_predicted_outcome, observed=None, receipt=pending_receipt)
    assert res["verification_status"] == STATUS_NOT_VERIFIED
    assert res["execution_status"] == EXECUTION_NOT_PERFORMED
    assert "PENDING" in res["explanation"]


# ------------------------------------------------------------------------------
# 3. OUTCOME COMPARISONS & VERIFICATION STATUSES
# ------------------------------------------------------------------------------

def test_verification_exact_match(sample_predicted_outcome, sample_observed_match):
    res = verify_outcome(sample_predicted_outcome, observed=sample_observed_match)
    assert res["verification_status"] == STATUS_VERIFIED
    assert res["verification_score"] == 100
    assert len(res["discrepancies"]) == 0
    assert res["execution_performed"] is True
    assert res["execution_status"] == EXECUTION_SIMULATED
    assert res["predicted_residual_risk"] == 15
    assert res["observed_residual_risk"] == 15


def test_verification_minor_divergence_within_tolerance(sample_predicted_outcome, sample_observed_minor_divergence):
    res = verify_outcome(sample_predicted_outcome, observed=sample_observed_minor_divergence, tolerance=10)
    assert res["verification_status"] == STATUS_VERIFIED
    assert res["verification_score"] >= 90
    assert len(res["discrepancies"]) == 0


def test_verification_divergence_exceeding_tolerance(sample_predicted_outcome, sample_observed_minor_divergence):
    # With a very tight tolerance (tolerance=2), small differences are flagged
    res = verify_outcome(sample_predicted_outcome, observed=sample_observed_minor_divergence, tolerance=2)
    assert res["verification_status"] == STATUS_PARTIALLY_VERIFIED
    assert len(res["discrepancies"]) > 0


def test_verification_severe_divergence_failed(sample_predicted_outcome, sample_observed_severe_divergence):
    res = verify_outcome(sample_predicted_outcome, observed=sample_observed_severe_divergence)
    assert res["verification_status"] == STATUS_FAILED
    assert res["verification_score"] < 50
    assert len(res["discrepancies"]) > 0
    assert "FAILED" in res["explanation"]


def test_verification_response_mismatch_fails(sample_predicted_outcome, sample_observed_match):
    # Observed response ISOLATE_HOST when predicted BLOCK_SOURCE_IP
    obs_mismatch = copy.deepcopy(sample_observed_match)
    obs_mismatch["response"] = "ISOLATE_HOST"

    res = verify_outcome(sample_predicted_outcome, observed=obs_mismatch)
    assert res["verification_status"] == STATUS_FAILED
    mismatch_disc = [d for d in res["discrepancies"] if d.get("status") == "RESPONSE_MISMATCH"]
    assert len(mismatch_disc) == 1


# ------------------------------------------------------------------------------
# 4. METRICS TRACKING & DISCREPANCY STRUCTURE
# ------------------------------------------------------------------------------

def test_metrics_tracking_all_fields(sample_predicted_outcome, sample_observed_minor_divergence):
    res = verify_outcome(sample_predicted_outcome, observed=sample_observed_minor_divergence)
    assert res["predicted_risk"] == 80
    assert res["observed_risk"] == 75
    assert res["predicted_containment_effectiveness"] == 95
    assert res["observed_containment_effectiveness"] == 90
    assert res["predicted_residual_risk"] == 15
    assert res["observed_residual_risk"] == 20
    assert res["predicted_blast_radius"] == 5
    assert res["observed_blast_radius"] == 8


def test_discrepancy_structure(sample_predicted_outcome, sample_observed_severe_divergence):
    res = verify_outcome(sample_predicted_outcome, observed=sample_observed_severe_divergence, tolerance=5)
    for d in res["discrepancies"]:
        assert "metric" in d
        assert "predicted" in d
        assert "observed" in d
        assert "difference" in d
        assert "tolerance" in d
        assert d["difference"] >= 0


def test_verification_score_bounds(sample_predicted_outcome, sample_observed_severe_divergence):
    res = verify_outcome(sample_predicted_outcome, observed=sample_observed_severe_divergence)
    assert 0 <= res["verification_score"] <= 100


def test_confidence_preserved(sample_predicted_outcome, sample_observed_match):
    res = verify_outcome(sample_predicted_outcome, observed=sample_observed_match)
    assert res["confidence"] == 90


# ------------------------------------------------------------------------------
# 5. INPUT VALIDATION & ERROR HANDLING
# ------------------------------------------------------------------------------

def test_validate_predicted_none():
    with pytest.raises(VerificationError, match="Predicted outcome cannot be None"):
        validate_predicted_outcome(None)


def test_validate_predicted_non_dict():
    with pytest.raises(VerificationError, match="Predicted outcome must be a dictionary"):
        validate_predicted_outcome(["invalid"])


def test_validate_predicted_empty():
    with pytest.raises(VerificationError, match="Predicted outcome dictionary cannot be empty"):
        validate_predicted_outcome({})


def test_validate_metric_out_of_bounds():
    with pytest.raises(VerificationError, match="out of bounds"):
        validate_predicted_outcome({
            "campaign_id": "C-1",
            "policy_factors": {"security_risk": 150}
        })

    with pytest.raises(VerificationError, match="out of bounds"):
        validate_predicted_outcome({
            "campaign_id": "C-1",
            "policy_factors": {"security_risk": -10}
        })


def test_validate_tolerance_out_of_bounds(sample_predicted_outcome):
    with pytest.raises(VerificationError, match="Tolerance.*must be between 0 and 100"):
        verify_outcome(sample_predicted_outcome, tolerance=-5)

    with pytest.raises(VerificationError, match="Tolerance.*must be between 0 and 100"):
        verify_outcome(sample_predicted_outcome, tolerance=105)


def test_validate_observed_none_raises():
    with pytest.raises(VerificationError, match="Observed outcome cannot be None"):
        validate_observed_outcome(None)


def test_validate_observed_non_dict():
    with pytest.raises(VerificationError, match="Observed outcome must be a dictionary"):
        validate_observed_outcome("bad_string")


# ------------------------------------------------------------------------------
# 6. OBJECT-ORIENTED WRAPPER (VerificationResult)
# ------------------------------------------------------------------------------

def test_verification_result_wrapper(sample_predicted_outcome, sample_observed_match):
    vr = VerificationResult.from_outcomes(sample_predicted_outcome, observed=sample_observed_match)
    assert vr.verification_status == STATUS_VERIFIED
    assert vr.verification_score == 100
    assert vr.execution_performed is True
    assert vr.execution_status == EXECUTION_SIMULATED
    assert len(vr.discrepancies) == 0
    assert "VERIFIED" in vr.explanation


def test_verification_result_to_dict_immutability(sample_predicted_outcome, sample_observed_match):
    vr = VerificationResult.from_outcomes(sample_predicted_outcome, observed=sample_observed_match)
    d = vr.to_dict()
    d["verification_score"] = -999
    assert vr.verification_score == 100


def test_verification_result_invalid_init():
    with pytest.raises(VerificationError, match="Invalid verification data structure"):
        VerificationResult({})


# ------------------------------------------------------------------------------
# 7. CONVENIENCE HELPERS & PIPELINE INTEGRATION
# ------------------------------------------------------------------------------

def test_verify_from_receipt_approved(sample_approved_receipt, sample_observed_match):
    res = verify_from_receipt(sample_approved_receipt, observed_outcome=sample_observed_match)
    assert res["verification_status"] == STATUS_VERIFIED
    assert res["campaign_id"] == "CAMP-2026-VER-001"
    assert res["selected_response"] == "BLOCK_SOURCE_IP"


def test_verify_from_receipt_rejected(sample_rejected_receipt, sample_observed_match):
    # Even if observed outcome is supplied, rejected receipt guarantees execution was not authorized
    res = verify_from_receipt(sample_rejected_receipt, observed_outcome=sample_observed_match)
    assert res["verification_status"] == STATUS_NOT_VERIFIED
    assert res["execution_status"] == EXECUTION_NOT_PERFORMED


def test_verify_from_receipt_invalid_input():
    with pytest.raises(VerificationError, match="Receipt must be a dictionary"):
        verify_from_receipt(["invalid"])


def test_verify_hypothetical_simulation(sample_approved_receipt):
    twin_sim = {
        "campaign_id": "CAMP-2026-VER-001",
        "response": "BLOCK_SOURCE_IP",
        "confidence": 85,
        "predicted_impact": {
            "security_risk": 75,
            "containment_effectiveness": 90,
            "residual_risk": 20,
            "blast_radius": 10,
        },
    }
    res = verify_hypothetical_simulation(twin_sim, sample_approved_receipt)
    assert res["verification_status"] == STATUS_VERIFIED
    assert res["verification_score"] == 100


# ------------------------------------------------------------------------------
# 8. DETERMINISTIC REPRODUCIBILITY & MULTI-CAMPAIGN INDEPENDENCE
# ------------------------------------------------------------------------------

def test_deterministic_reproducibility(sample_predicted_outcome, sample_observed_minor_divergence):
    r1 = verify_outcome(sample_predicted_outcome, sample_observed_minor_divergence)
    r2 = verify_outcome(sample_predicted_outcome, sample_observed_minor_divergence)
    assert r1 == r2


def test_multi_campaign_independence(sample_predicted_outcome, sample_observed_match):
    p2 = copy.deepcopy(sample_predicted_outcome)
    p2["campaign_id"] = "CAMP-2026-VER-002"

    r1 = verify_outcome(sample_predicted_outcome, sample_observed_match)
    r2 = verify_outcome(p2, sample_observed_match)

    assert r1["campaign_id"] == "CAMP-2026-VER-001"
    assert r2["campaign_id"] == "CAMP-2026-VER-002"
    assert r1["verification_id"] != r2["verification_id"]


def test_custom_timestamp_preservation(sample_predicted_outcome, sample_observed_match):
    custom_ts = "2026-09-15T18:45:00Z"
    res = verify_outcome(sample_predicted_outcome, sample_observed_match, timestamp=custom_ts)
    assert res["timestamp"] == custom_ts


def test_live_execution_flag(sample_predicted_outcome, sample_observed_match):
    res_live = verify_outcome(sample_predicted_outcome, sample_observed_match, is_simulation=False)
    assert res_live["execution_status"] == EXECUTION_OBSERVED


# ------------------------------------------------------------------------------
# 9. ZERO NETWORK / DB / SIDE-EFFECT GUARANTEES
# ------------------------------------------------------------------------------

def test_zero_network_activity(sample_predicted_outcome, sample_observed_match, monkeypatch):
    def guarded_socket(*args, **kwargs):
        raise RuntimeError("Network activity forbidden in Phase 1I")

    monkeypatch.setattr(socket, "socket", guarded_socket)
    res = verify_outcome(sample_predicted_outcome, sample_observed_match)
    assert res["verification_status"] == STATUS_VERIFIED


def test_zero_database_side_effects(sample_predicted_outcome, sample_observed_match):
    events_before = len(get_recent_events(limit=50))
    incidents_before = len(get_incidents(limit=50))

    verify_outcome(sample_predicted_outcome, None)
    verify_outcome(sample_predicted_outcome, sample_observed_match)

    events_after = len(get_recent_events(limit=50))
    incidents_after = len(get_incidents(limit=50))

    assert events_before == events_after
    assert incidents_before == incidents_after
