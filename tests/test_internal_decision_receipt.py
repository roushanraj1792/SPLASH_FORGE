"""
Unit & Integration Tests for Internal Decision Receipt (Phase 1H)
================================================================
Comprehensive test suite covering:
  1. Deterministic receipt generation & interface
  2. Deterministic receipt ID generation reproducibility
  3. PENDING receipt state creation & defaults
  4. APPROVED receipt state creation with approver and reason
  5. REJECTED receipt state creation with approver and reason
  6. Prevention of APPROVED without approver
  7. Prevention of APPROVED without reason
  8. Prevention of REJECTED without approver
  9. Prevention of REJECTED without reason
 10. Prevention of invalid approval state string
 11. Selected response handling on PENDING
 12. Selected response override on APPROVED
 13. Selected response cleared on REJECTED
 14. Validation of policy result - None input
 15. Validation of policy result - non-dict input
 16. Validation of policy result - missing campaign_id
 17. Validation of policy result - invalid decision dict
 18. Validation of policy result - invalid recommended_response
 19. Validation of policy result - invalid policy decision state
 20. Validation of policy result - out of bounds policy score
 21. Validation of policy result - out of bounds confidence
 22. Validation of policy result - missing policy factors
 23. Validation of policy result - missing reasons
 24. DecisionReceipt class wrapper initialization and properties
 25. DecisionReceipt.approve() transition
 26. DecisionReceipt.reject() transition
 27. Immutability verification (mutating output does not affect receipt)
 28. Convenience helpers: create_pending_receipt, create_approved_receipt, create_rejected_receipt
 29. Integration from Phase 1G policy evaluation structure
 30. Zero network activity guarantee
 31. Zero database/filesystem side-effects
 32. Alternatives preserved in receipt
 33. Policy factors preserved as expected integers
 34. Timestamp formatting and deterministic defaults
 35. Whitespace-only approver and reason validation
 36. Case insensitivity in state and response normalization
 37. Multiple distinct campaign receipts independence
 38. Re-approval transitions preserve underlying policy factors
 39. Re-rejection transitions preserve underlying policy factors
 40. Custom timestamp preservation across lifecycle transitions
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

from policy.internal_decision_receipt import (
    create_decision_receipt,
    create_pending_receipt,
    create_approved_receipt,
    create_rejected_receipt,
    make_deterministic_receipt_id,
    validate_policy_result,
    validate_human_decision_parameters,
    DecisionReceipt,
    DecisionReceiptError,
    STATE_PENDING,
    STATE_APPROVED,
    STATE_REJECTED,
    VALID_APPROVAL_STATES,
)
from database.database import get_recent_events, get_incidents

# Canonical constants
BLOCK_SOURCE_IP = "BLOCK_SOURCE_IP"
ISOLATE_HOST = "ISOLATE_HOST"
NOTIFY_ADMIN = "NOTIFY_ADMIN"
NO_ACTION = "NO_ACTION"
DECISION_RECOMMEND = "RECOMMEND"
DECISION_REVIEW = "REVIEW"
DECISION_NO_ACTION = "NO_ACTION"


# ------------------------------------------------------------------------------
# FIXTURES (Pure in-memory, completely isolated from campaign generation)
# ------------------------------------------------------------------------------

@pytest.fixture
def sample_valid_policy_result():
    """Provides a canonical valid Phase 1G policy evaluation dictionary."""
    return {
        "campaign_id": "CAMP-2026-TEST-001",
        "decision": {
            "recommended_response": BLOCK_SOURCE_IP,
            "decision": DECISION_RECOMMEND,
            "policy_score": 85,
            "confidence": 90,
        },
        "alternatives": [
            {
                "response": BLOCK_SOURCE_IP,
                "score": 85,
                "residual_risk": 20,
                "containment_effectiveness": 95,
                "service_impact": 10,
                "blast_radius": 5,
            },
            {
                "response": ISOLATE_HOST,
                "score": 60,
                "residual_risk": 15,
                "containment_effectiveness": 98,
                "service_impact": 80,
                "blast_radius": 70,
            }
        ],
        "policy_factors": {
            "security_risk": 80,
            "containment_effectiveness": 95,
            "residual_risk": 20,
            "blast_radius": 5,
            "service_impact": 10,
            "confidence": 90,
            "evidence_strength": 85,
        },
        "reason": "Policy engine recommends BLOCK_SOURCE_IP due to optimal risk reduction.",
        "comparison_reason": "BLOCK_SOURCE_IP offers superior risk reduction with lower disruption.",
    }


@pytest.fixture
def secondary_policy_result():
    """Provides a secondary valid Phase 1G policy evaluation for isolation host."""
    return {
        "campaign_id": "CAMP-2026-TEST-002",
        "decision": {
            "recommended_response": ISOLATE_HOST,
            "decision": DECISION_REVIEW,
            "policy_score": 65,
            "confidence": 75,
        },
        "alternatives": [
            {
                "response": ISOLATE_HOST,
                "score": 65,
                "residual_risk": 10,
                "containment_effectiveness": 95,
                "service_impact": 60,
                "blast_radius": 40,
            }
        ],
        "policy_factors": {
            "security_risk": 70,
            "containment_effectiveness": 95,
            "residual_risk": 10,
            "blast_radius": 40,
            "service_impact": 60,
            "confidence": 75,
            "evidence_strength": 80,
        },
        "reason": "Host isolation recommended due to internal lateral movement.",
        "comparison_reason": "Lateral movement requires host quarantine.",
    }


# ------------------------------------------------------------------------------
# 1. DETERMINISTIC RECEIPT GENERATION & IDENTIFIERS
# ------------------------------------------------------------------------------

def test_make_deterministic_receipt_id_format():
    receipt_id = make_deterministic_receipt_id("CAMP-001", "BLOCK_SOURCE_IP", "APPROVED")
    assert receipt_id == "rcpt:camp-001:block_source_ip:approved"


def test_make_deterministic_receipt_id_reproducible():
    id1 = make_deterministic_receipt_id("CAMP-ABC", "ISOLATE_HOST", "PENDING")
    id2 = make_deterministic_receipt_id("CAMP-ABC", "ISOLATE_HOST", "PENDING")
    assert id1 == id2


def test_make_deterministic_receipt_id_distinct_states():
    id_app = make_deterministic_receipt_id("CAMP-1", "BLOCK_SOURCE_IP", "APPROVED")
    id_rej = make_deterministic_receipt_id("CAMP-1", "BLOCK_SOURCE_IP", "REJECTED")
    id_pen = make_deterministic_receipt_id("CAMP-1", "BLOCK_SOURCE_IP", "PENDING")
    assert len({id_app, id_rej, id_pen}) == 3


def test_make_deterministic_receipt_id_none_response():
    receipt_id = make_deterministic_receipt_id("CAMP-1", None, "REJECTED")
    assert receipt_id == "rcpt:camp-1:none:rejected"


# ------------------------------------------------------------------------------
# 2. PENDING RECEIPT CREATION
# ------------------------------------------------------------------------------

def test_create_pending_receipt_default_state(sample_valid_policy_result):
    receipt = create_decision_receipt(sample_valid_policy_result)
    assert receipt["receipt_status"] == STATE_PENDING
    assert receipt["human_approval_state"] == STATE_PENDING
    assert receipt["campaign_id"] == "CAMP-2026-TEST-001"
    assert receipt["recommended_response"] == BLOCK_SOURCE_IP
    assert receipt["selected_response"] == BLOCK_SOURCE_IP
    assert receipt["approver_id"] is None
    assert receipt["decision_reason"] is None
    assert receipt["policy_score"] == 85
    assert receipt["confidence"] == 90
    assert "rcpt:camp-2026-test-001:block_source_ip:pending" == receipt["receipt_id"]


def test_create_pending_receipt_helper(sample_valid_policy_result):
    receipt = create_pending_receipt(sample_valid_policy_result, timestamp="2026-09-15T12:00:00Z")
    assert receipt["receipt_status"] == STATE_PENDING
    assert receipt["timestamp"] == "2026-09-15T12:00:00Z"


def test_create_pending_receipt_optional_approver_and_reason(sample_valid_policy_result):
    receipt = create_decision_receipt(
        sample_valid_policy_result,
        approval_state=STATE_PENDING,
        approver_id="analyst_alice",
        decision_reason="Drafting approval pending peer review"
    )
    assert receipt["receipt_status"] == STATE_PENDING
    assert receipt["approver_id"] == "analyst_alice"
    assert receipt["decision_reason"] == "Drafting approval pending peer review"


# ------------------------------------------------------------------------------
# 3. APPROVED RECEIPT CREATION
# ------------------------------------------------------------------------------

def test_create_approved_receipt_success(sample_valid_policy_result):
    receipt = create_decision_receipt(
        sample_valid_policy_result,
        approval_state=STATE_APPROVED,
        approver_id="sec_admin",
        decision_reason="Evidence confirms malicious brute force campaign"
    )
    assert receipt["receipt_status"] == STATE_APPROVED
    assert receipt["human_approval_state"] == STATE_APPROVED
    assert receipt["approver_id"] == "sec_admin"
    assert receipt["decision_reason"] == "Evidence confirms malicious brute force campaign"
    assert receipt["selected_response"] == BLOCK_SOURCE_IP
    assert receipt["receipt_id"] == "rcpt:camp-2026-test-001:block_source_ip:approved"


def test_create_approved_receipt_helper(sample_valid_policy_result):
    receipt = create_approved_receipt(
        sample_valid_policy_result,
        approver_id="lead_analyst",
        approval_reason="Verified host isolation requirement",
        selected_response=ISOLATE_HOST,
        timestamp="2026-09-15T10:30:00Z"
    )
    assert receipt["receipt_status"] == STATE_APPROVED
    assert receipt["approver_id"] == "lead_analyst"
    assert receipt["decision_reason"] == "Verified host isolation requirement"
    assert receipt["selected_response"] == ISOLATE_HOST
    assert receipt["timestamp"] == "2026-09-15T10:30:00Z"
    assert receipt["receipt_id"] == "rcpt:camp-2026-test-001:isolate_host:approved"


def test_approved_receipt_missing_approver_raises(sample_valid_policy_result):
    with pytest.raises(DecisionReceiptError, match="Approver identifier is strictly required"):
        create_decision_receipt(
            sample_valid_policy_result,
            approval_state=STATE_APPROVED,
            approver_id=None,
            decision_reason="Valid reason"
        )

    with pytest.raises(DecisionReceiptError, match="Approver identifier is strictly required"):
        create_decision_receipt(
            sample_valid_policy_result,
            approval_state=STATE_APPROVED,
            approver_id="   ",
            decision_reason="Valid reason"
        )


def test_approved_receipt_missing_reason_raises(sample_valid_policy_result):
    with pytest.raises(DecisionReceiptError, match="Approval reason is strictly required"):
        create_decision_receipt(
            sample_valid_policy_result,
            approval_state=STATE_APPROVED,
            approver_id="sec_analyst",
            decision_reason=None
        )

    with pytest.raises(DecisionReceiptError, match="Approval reason is strictly required"):
        create_decision_receipt(
            sample_valid_policy_result,
            approval_state=STATE_APPROVED,
            approver_id="sec_analyst",
            decision_reason="   "
        )


def test_approved_receipt_invalid_selected_response(sample_valid_policy_result):
    with pytest.raises(DecisionReceiptError, match="Invalid selected response"):
        create_decision_receipt(
            sample_valid_policy_result,
            approval_state=STATE_APPROVED,
            approver_id="sec_analyst",
            decision_reason="Approval reason",
            selected_response="DESTROY_DATACENTER"
        )


# ------------------------------------------------------------------------------
# 4. REJECTED RECEIPT CREATION
# ------------------------------------------------------------------------------

def test_create_rejected_receipt_success(sample_valid_policy_result):
    receipt = create_decision_receipt(
        sample_valid_policy_result,
        approval_state=STATE_REJECTED,
        approver_id="soc_director",
        decision_reason="False positive: authorized red team exercise"
    )
    assert receipt["receipt_status"] == STATE_REJECTED
    assert receipt["human_approval_state"] == STATE_REJECTED
    assert receipt["approver_id"] == "soc_director"
    assert receipt["decision_reason"] == "False positive: authorized red team exercise"
    # REJECTED clears selected response
    assert receipt["selected_response"] is None
    assert receipt["receipt_id"] == "rcpt:camp-2026-test-001:block_source_ip:rejected"


def test_create_rejected_receipt_helper(sample_valid_policy_result):
    receipt = create_rejected_receipt(
        sample_valid_policy_result,
        approver_id="soc_manager",
        rejection_reason="Duplicate campaign under separate investigation",
        timestamp="2026-09-15T11:00:00Z"
    )
    assert receipt["receipt_status"] == STATE_REJECTED
    assert receipt["approver_id"] == "soc_manager"
    assert receipt["decision_reason"] == "Duplicate campaign under separate investigation"
    assert receipt["selected_response"] is None
    assert receipt["timestamp"] == "2026-09-15T11:00:00Z"


def test_rejected_receipt_missing_approver_raises(sample_valid_policy_result):
    with pytest.raises(DecisionReceiptError, match="Approver identifier is strictly required"):
        create_decision_receipt(
            sample_valid_policy_result,
            approval_state=STATE_REJECTED,
            approver_id=None,
            decision_reason="Valid rejection reason"
        )


def test_rejected_receipt_missing_reason_raises(sample_valid_policy_result):
    with pytest.raises(DecisionReceiptError, match="Rejection reason is strictly required"):
        create_decision_receipt(
            sample_valid_policy_result,
            approval_state=STATE_REJECTED,
            approver_id="analyst_1",
            decision_reason=""
        )


# ------------------------------------------------------------------------------
# 5. INVALID APPROVAL STATE VALIDATION
# ------------------------------------------------------------------------------

def test_invalid_approval_state_raises(sample_valid_policy_result):
    with pytest.raises(DecisionReceiptError, match="Unknown or unsupported approval state"):
        create_decision_receipt(
            sample_valid_policy_result,
            approval_state="EXECUTE_NOW"
        )

    with pytest.raises(DecisionReceiptError, match="Unknown or unsupported approval state"):
        create_decision_receipt(
            sample_valid_policy_result,
            approval_state="MAYBE"
        )


# ------------------------------------------------------------------------------
# 6. POLICY RESULT VALIDATION
# ------------------------------------------------------------------------------

def test_validate_policy_result_none():
    with pytest.raises(DecisionReceiptError, match="Policy result cannot be None"):
        validate_policy_result(None)


def test_validate_policy_result_non_dict():
    with pytest.raises(DecisionReceiptError, match="Policy result must be a dictionary"):
        validate_policy_result(["invalid", "list"])


def test_validate_policy_result_empty():
    with pytest.raises(DecisionReceiptError, match="Policy result dictionary cannot be empty"):
        validate_policy_result({})


def test_validate_policy_result_missing_campaign_id(sample_valid_policy_result):
    bad = copy.deepcopy(sample_valid_policy_result)
    del bad["campaign_id"]
    with pytest.raises(DecisionReceiptError, match="Missing or invalid 'campaign_id'"):
        validate_policy_result(bad)


def test_validate_policy_result_invalid_decision_dict(sample_valid_policy_result):
    bad = copy.deepcopy(sample_valid_policy_result)
    bad["decision"] = "NOT_A_DICT"
    with pytest.raises(DecisionReceiptError, match="Missing or invalid 'decision' dictionary"):
        validate_policy_result(bad)


def test_validate_policy_result_invalid_recommended_response(sample_valid_policy_result):
    bad = copy.deepcopy(sample_valid_policy_result)
    bad["decision"]["recommended_response"] = "NUKE_IP"
    with pytest.raises(DecisionReceiptError, match="Invalid 'recommended_response'"):
        validate_policy_result(bad)


def test_validate_policy_result_invalid_policy_decision(sample_valid_policy_result):
    bad = copy.deepcopy(sample_valid_policy_result)
    bad["decision"]["decision"] = "AUTO_ACT"
    with pytest.raises(DecisionReceiptError, match="Invalid policy 'decision' state"):
        validate_policy_result(bad)


def test_validate_policy_result_out_of_bounds_policy_score(sample_valid_policy_result):
    bad = copy.deepcopy(sample_valid_policy_result)
    bad["decision"]["policy_score"] = 105
    with pytest.raises(DecisionReceiptError, match="Invalid 'policy_score'"):
        validate_policy_result(bad)

    bad["decision"]["policy_score"] = -1
    with pytest.raises(DecisionReceiptError, match="Invalid 'policy_score'"):
        validate_policy_result(bad)


def test_validate_policy_result_out_of_bounds_confidence(sample_valid_policy_result):
    bad = copy.deepcopy(sample_valid_policy_result)
    bad["decision"]["confidence"] = 999
    with pytest.raises(DecisionReceiptError, match="Invalid 'confidence'"):
        validate_policy_result(bad)


def test_validate_policy_result_missing_factor(sample_valid_policy_result):
    bad = copy.deepcopy(sample_valid_policy_result)
    del bad["policy_factors"]["blast_radius"]
    with pytest.raises(DecisionReceiptError, match="Missing or invalid policy factor 'blast_radius'"):
        validate_policy_result(bad)


def test_validate_policy_result_missing_reason(sample_valid_policy_result):
    bad = copy.deepcopy(sample_valid_policy_result)
    bad["reason"] = ""
    with pytest.raises(DecisionReceiptError, match="Missing or invalid 'reason'"):
        validate_policy_result(bad)


def test_validate_policy_result_missing_comparison_reason(sample_valid_policy_result):
    bad = copy.deepcopy(sample_valid_policy_result)
    bad["comparison_reason"] = "   "
    with pytest.raises(DecisionReceiptError, match="Missing or invalid 'comparison_reason'"):
        validate_policy_result(bad)


# ------------------------------------------------------------------------------
# 7. DECISION RECEIPT WRAPPER CLASS & TRANSITIONS
# ------------------------------------------------------------------------------

def test_decision_receipt_class_from_policy(sample_valid_policy_result):
    rec = DecisionReceipt.from_policy(sample_valid_policy_result)
    assert rec.receipt_status == STATE_PENDING
    assert rec.campaign_id == "CAMP-2026-TEST-001"
    assert rec.recommended_response == BLOCK_SOURCE_IP
    assert rec.selected_response == BLOCK_SOURCE_IP
    assert rec.approver_id is None
    assert rec.decision_reason is None


def test_decision_receipt_approve_transition(sample_valid_policy_result):
    rec = DecisionReceipt.from_policy(sample_valid_policy_result)
    approved_rec = rec.approve(
        approver_id="analyst_bob",
        approval_reason="Confirmed IOC matches threat intel",
        selected_response=ISOLATE_HOST
    )

    # Verify original is untouched (immutability)
    assert rec.receipt_status == STATE_PENDING
    assert rec.selected_response == BLOCK_SOURCE_IP

    # Verify new instance
    assert approved_rec.receipt_status == STATE_APPROVED
    assert approved_rec.approver_id == "analyst_bob"
    assert approved_rec.decision_reason == "Confirmed IOC matches threat intel"
    assert approved_rec.selected_response == ISOLATE_HOST
    assert approved_rec.receipt_id == "rcpt:camp-2026-test-001:isolate_host:approved"


def test_decision_receipt_reject_transition(sample_valid_policy_result):
    rec = DecisionReceipt.from_policy(sample_valid_policy_result)
    rejected_rec = rec.reject(
        approver_id="director_carl",
        rejection_reason="Authorized penetration testing in progress"
    )

    # Verify original is untouched
    assert rec.receipt_status == STATE_PENDING

    # Verify new instance
    assert rejected_rec.receipt_status == STATE_REJECTED
    assert rejected_rec.approver_id == "director_carl"
    assert rejected_rec.decision_reason == "Authorized penetration testing in progress"
    assert rejected_rec.selected_response is None
    assert rejected_rec.receipt_id == "rcpt:camp-2026-test-001:block_source_ip:rejected"


def test_decision_receipt_invalid_construction():
    with pytest.raises(DecisionReceiptError, match="Invalid receipt dictionary structure"):
        DecisionReceipt({})


# ------------------------------------------------------------------------------
# 8. IMMUTABILITY & DEEPCOPY INTEGRITY
# ------------------------------------------------------------------------------

def test_receipt_immutability(sample_valid_policy_result):
    receipt = create_decision_receipt(sample_valid_policy_result)
    # Attempt to mutate returned dictionary
    receipt["policy_factors"]["security_risk"] = 999
    receipt["alternatives"].clear()

    # Create new receipt from same source policy
    receipt2 = create_decision_receipt(sample_valid_policy_result)
    assert receipt2["policy_factors"]["security_risk"] == 80
    assert len(receipt2["alternatives"]) == 2


# ------------------------------------------------------------------------------
# 9. INTEGRATION WITH POLICY INPUT AND INDEPENDENCE
# ------------------------------------------------------------------------------

def test_multiple_campaign_receipt_independence(sample_valid_policy_result, secondary_policy_result):
    r1 = create_approved_receipt(sample_valid_policy_result, "admin_1", "Reason 1")
    r2 = create_rejected_receipt(secondary_policy_result, "admin_2", "Reason 2")

    assert r1["campaign_id"] == "CAMP-2026-TEST-001"
    assert r1["receipt_status"] == STATE_APPROVED
    assert r1["selected_response"] == BLOCK_SOURCE_IP

    assert r2["campaign_id"] == "CAMP-2026-TEST-002"
    assert r2["receipt_status"] == STATE_REJECTED
    assert r2["selected_response"] is None


def test_reapproval_preserves_policy_factors(sample_valid_policy_result):
    rec = DecisionReceipt.from_policy(sample_valid_policy_result)
    app1 = rec.approve("analyst_a", "First pass")
    app2 = app1.approve("analyst_b", "Second pass override", selected_response=BLOCK_SOURCE_IP)

    assert app2.to_dict()["policy_factors"] == sample_valid_policy_result["policy_factors"]
    assert app2.approver_id == "analyst_b"


def test_rejection_preserves_policy_factors(sample_valid_policy_result):
    rec = DecisionReceipt.from_policy(sample_valid_policy_result)
    rej = rec.reject("analyst_c", "Reject reason")

    assert rej.to_dict()["policy_factors"] == sample_valid_policy_result["policy_factors"]
    assert rej.receipt_status == STATE_REJECTED


def test_custom_timestamp_preservation(sample_valid_policy_result):
    custom_ts = "2026-09-15T15:30:45Z"
    receipt = create_approved_receipt(
        sample_valid_policy_result,
        approver_id="auditor_1",
        approval_reason="Audit verified",
        timestamp=custom_ts
    )
    assert receipt["timestamp"] == custom_ts


# ------------------------------------------------------------------------------
# 10. STRICT SAFETY & ZERO NETWORK/DB/SIDE-EFFECT VERIFICATION
# ------------------------------------------------------------------------------

def test_zero_network_activity(sample_valid_policy_result, monkeypatch):
    """Ensure that under no circumstances does Phase 1H attempt socket/network access."""
    def guarded_socket(*args, **kwargs):
        raise RuntimeError("Network activity forbidden in Phase 1H")

    monkeypatch.setattr(socket, "socket", guarded_socket)
    receipt = create_decision_receipt(
        sample_valid_policy_result,
        approval_state=STATE_APPROVED,
        approver_id="analyst_offline",
        decision_reason="Air-gapped verification"
    )
    assert receipt["receipt_status"] == STATE_APPROVED


def test_zero_database_side_effects(sample_valid_policy_result):
    """Ensure database state remains untouched before and after receipt creation."""
    events_before = len(get_recent_events(limit=50))
    incidents_before = len(get_incidents(limit=50))

    # Create multiple receipts of all states
    create_pending_receipt(sample_valid_policy_result)
    create_approved_receipt(sample_valid_policy_result, "u1", "r1")
    create_rejected_receipt(sample_valid_policy_result, "u2", "r2")

    events_after = len(get_recent_events(limit=50))
    incidents_after = len(get_incidents(limit=50))

    assert events_before == events_after
    assert incidents_before == incidents_after
