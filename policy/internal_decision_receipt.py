"""
Internal Decision Receipt — Deterministic Human Approval & Audit Record Layer
=============================================================================
Part of the SentinelX Detection & Incident Response Platform (Phase 1H).

Role:
  Consumes the Phase 1G Internal Policy & Decision Engine output and represents
  a deterministic, immutable, in-memory human approval/rejection decision record
  (Decision Receipt) without executing any containment action.

Pipeline Context:
  Synthetic Telemetry (1A)
           ↓
  Correlated Campaign (1B)
           ↓
  Structured Attack Story (1C)
           ↓
  Evidence Knowledge Graph (1D)
           ↓
  Internal Response Lab (1E)
           ↓
  Cyber Twin Impact Simulation (1F)
           ↓
  Deterministic Policy & Decision Engine (1G)
           ↓
  Internal Decision Receipt (1H)
           ↓
  Immutable Decision Record:
    - campaign_id
    - recommended_response
    - policy_decision (RECOMMEND / REVIEW / NO_ACTION)
    - policy_score & confidence
    - policy_factors
    - reason & comparison_reason
    - selected_response
    - human_approval_state (PENDING / APPROVED / REJECTED)
    - approver_id & approval_reason
    - receipt_status
    - deterministic receipt identifier

Safety & Boundary Rules:
  - DECISION RECORDING ONLY: Never executes real containment or system actions.
  - Strict human decision constraints: Impossible to represent APPROVED/REJECTED
    without non-empty approver and approval/rejection reason.
  - ZERO network traffic: No sockets, no HTTP, no external connections.
  - ZERO database modifications: Purely in-memory audit receipts.
  - ZERO containment layer invocation: Does NOT import services.containment.
  - ZERO external service calls: No Telegram, no Gemini, no third-party APIs.
  - Strictly deterministic: Identical inputs yield identical receipt identifiers.
  - No randomness, no datetime.now() dependency, no UUIDs.
"""

import copy
import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

# Optional pipeline helpers
try:
    from policy.internal_policy_engine import (
        evaluate_policy,
        evaluate_policy_from_graph,
        evaluate_policy_from_story,
        evaluate_policy_from_campaign,
        evaluate_policy_from_events,
        BLOCK_SOURCE_IP,
        ISOLATE_HOST,
        NOTIFY_ADMIN,
        NO_ACTION,
        DECISION_RECOMMEND,
        DECISION_REVIEW,
        DECISION_NO_ACTION,
        SUPPORTED_RESPONSE_OPTIONS,
    )
except ImportError:
    BLOCK_SOURCE_IP = "BLOCK_SOURCE_IP"
    ISOLATE_HOST = "ISOLATE_HOST"
    NOTIFY_ADMIN = "NOTIFY_ADMIN"
    NO_ACTION = "NO_ACTION"
    DECISION_RECOMMEND = "RECOMMEND"
    DECISION_REVIEW = "REVIEW"
    DECISION_NO_ACTION = "NO_ACTION"
    SUPPORTED_RESPONSE_OPTIONS = (
        BLOCK_SOURCE_IP,
        ISOLATE_HOST,
        NOTIFY_ADMIN,
        NO_ACTION,
    )
    evaluate_policy = None  # type: ignore
    evaluate_policy_from_graph = None  # type: ignore
    evaluate_policy_from_story = None  # type: ignore
    evaluate_policy_from_campaign = None  # type: ignore
    evaluate_policy_from_events = None  # type: ignore


# ------------------------------------------------------------------------------
# CONSTANTS & CONSTRAINTS
# ------------------------------------------------------------------------------

STATE_PENDING = "PENDING"
STATE_APPROVED = "APPROVED"
STATE_REJECTED = "REJECTED"

VALID_APPROVAL_STATES = {
    STATE_PENDING,
    STATE_APPROVED,
    STATE_REJECTED,
}

VALID_RESPONSE_TYPES = set(SUPPORTED_RESPONSE_OPTIONS)

VALID_POLICY_DECISIONS = {
    DECISION_RECOMMEND,
    DECISION_REVIEW,
    DECISION_NO_ACTION,
}

REQUIRED_POLICY_FACTORS = {
    "security_risk",
    "containment_effectiveness",
    "residual_risk",
    "blast_radius",
    "service_impact",
    "confidence",
    "evidence_strength",
}

DEFAULT_DETERMINISTIC_TIMESTAMP = "2026-09-15T00:00:00Z"


# ------------------------------------------------------------------------------
# EXCEPTIONS
# ------------------------------------------------------------------------------

class DecisionReceiptError(ValueError):
    """Raised when decision receipt input is malformed, invalid, or missing required fields."""
    pass


# ------------------------------------------------------------------------------
# DETERMINISTIC IDENTIFIERS
# ------------------------------------------------------------------------------

def make_deterministic_receipt_id(
    campaign_id: str,
    response_type: Optional[str],
    approval_state: str
) -> str:
    """
    Generate a deterministic receipt identifier without UUIDs or randomness.
    Format: rcpt:<campaign_id>:<response_type>:<state>
    """
    clean_camp = campaign_id.strip().lower()
    clean_state = approval_state.strip().lower()
    clean_resp = (response_type.strip().lower() if response_type else "none")
    return f"rcpt:{clean_camp}:{clean_resp}:{clean_state}"


# ------------------------------------------------------------------------------
# VALIDATION UTILITIES
# ------------------------------------------------------------------------------

def validate_policy_result(policy_result: Any) -> Dict[str, Any]:
    """
    Strictly validate that the input dictionary conforms to the Phase 1G Policy Engine schema.
    """
    if policy_result is None:
        raise DecisionReceiptError("Policy result cannot be None.")
    if not isinstance(policy_result, dict):
        raise DecisionReceiptError(f"Policy result must be a dictionary, got: {type(policy_result).__name__}")
    if not policy_result:
        raise DecisionReceiptError("Policy result dictionary cannot be empty.")

    # 1. Campaign ID
    campaign_id = policy_result.get("campaign_id")
    if not isinstance(campaign_id, str) or not campaign_id.strip():
        raise DecisionReceiptError(f"Missing or invalid 'campaign_id' in policy result: {repr(campaign_id)}")

    # 2. Decision Dictionary
    decision = policy_result.get("decision")
    if not isinstance(decision, dict) or not decision:
        raise DecisionReceiptError("Missing or invalid 'decision' dictionary in policy result.")

    rec_resp = decision.get("recommended_response")
    if not isinstance(rec_resp, str) or rec_resp.strip().upper() not in VALID_RESPONSE_TYPES:
        raise DecisionReceiptError(f"Invalid 'recommended_response' in policy decision: {repr(rec_resp)}")

    pol_dec = decision.get("decision")
    if not isinstance(pol_dec, str) or pol_dec.strip().upper() not in VALID_POLICY_DECISIONS:
        raise DecisionReceiptError(f"Invalid policy 'decision' state: {repr(pol_dec)}")

    pol_score = decision.get("policy_score")
    if not isinstance(pol_score, (int, float)) or not (0 <= pol_score <= 100):
        raise DecisionReceiptError(f"Invalid 'policy_score' ({pol_score}) in policy decision; must be 0-100.")

    conf = decision.get("confidence")
    if not isinstance(conf, (int, float)) or not (0 <= conf <= 100):
        raise DecisionReceiptError(f"Invalid 'confidence' ({conf}) in policy decision; must be 0-100.")

    # 3. Policy Factors
    factors = policy_result.get("policy_factors")
    if not isinstance(factors, dict) or not factors:
        raise DecisionReceiptError("Missing or invalid 'policy_factors' dictionary in policy result.")

    for k in REQUIRED_POLICY_FACTORS:
        val = factors.get(k)
        if val is None or not isinstance(val, (int, float)) or not (0 <= val <= 100):
            raise DecisionReceiptError(f"Missing or invalid policy factor '{k}': {repr(val)}; must be 0-100.")

    # 4. Reasons
    reason = policy_result.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise DecisionReceiptError("Missing or invalid 'reason' in policy result.")

    comp_reason = policy_result.get("comparison_reason")
    if not isinstance(comp_reason, str) or not comp_reason.strip():
        raise DecisionReceiptError("Missing or invalid 'comparison_reason' in policy result.")

    return {
        "campaign_id": campaign_id.strip(),
        "decision": {
            "recommended_response": rec_resp.strip().upper(),
            "decision": pol_dec.strip().upper(),
            "policy_score": int(pol_score),
            "confidence": int(conf),
        },
        "alternatives": list(policy_result.get("alternatives") or []),
        "policy_factors": {k: int(factors[k]) for k in REQUIRED_POLICY_FACTORS},
        "reason": reason.strip(),
        "comparison_reason": comp_reason.strip(),
    }


def validate_human_decision_parameters(
    approval_state: str,
    approver_id: Optional[str],
    decision_reason: Optional[str],
    selected_response: Optional[str],
    recommended_response: str
) -> Tuple[str, Optional[str], Optional[str], Optional[str]]:
    """
    Validate human decision parameters.
    Enforces that APPROVED and REJECTED states CANNOT be created without
    a non-empty approver and decision reason.
    """
    if not isinstance(approval_state, str):
        raise DecisionReceiptError(f"Approval state must be a string, got: {type(approval_state).__name__}")

    norm_state = approval_state.strip().upper()
    if norm_state not in VALID_APPROVAL_STATES:
        raise DecisionReceiptError(f"Unknown or unsupported approval state: {repr(approval_state)}")

    clean_approver: Optional[str] = None
    clean_reason: Optional[str] = None
    clean_selected: Optional[str] = None

    if norm_state == STATE_PENDING:
        # For PENDING, approver and reason are optional
        if approver_id and isinstance(approver_id, str) and approver_id.strip():
            clean_approver = approver_id.strip()
        else:
            clean_approver = None

        if decision_reason and isinstance(decision_reason, str) and decision_reason.strip():
            clean_reason = decision_reason.strip()
        else:
            clean_reason = None

        # PENDING defaults selected_response to recommended_response or caller override
        if selected_response:
            norm_resp = selected_response.strip().upper()
            if norm_resp not in VALID_RESPONSE_TYPES:
                raise DecisionReceiptError(f"Invalid selected response: {repr(selected_response)}")
            clean_selected = norm_resp
        else:
            clean_selected = recommended_response

    elif norm_state == STATE_APPROVED:
        # Required approver
        if not approver_id or not isinstance(approver_id, str) or not approver_id.strip():
            raise DecisionReceiptError("Approver identifier is strictly required when approval_state is APPROVED.")
        clean_approver = approver_id.strip()

        # Required reason
        if not decision_reason or not isinstance(decision_reason, str) or not decision_reason.strip():
            raise DecisionReceiptError("Approval reason is strictly required when approval_state is APPROVED.")
        clean_reason = decision_reason.strip()

        # Selected response
        chosen = selected_response if selected_response is not None else recommended_response
        if not isinstance(chosen, str) or chosen.strip().upper() not in VALID_RESPONSE_TYPES:
            raise DecisionReceiptError(f"Invalid selected response for APPROVED receipt: {repr(chosen)}")
        clean_selected = chosen.strip().upper()

    elif norm_state == STATE_REJECTED:
        # Required approver
        if not approver_id or not isinstance(approver_id, str) or not approver_id.strip():
            raise DecisionReceiptError("Approver identifier is strictly required when approval_state is REJECTED.")
        clean_approver = approver_id.strip()

        # Required reason
        if not decision_reason or not isinstance(decision_reason, str) or not decision_reason.strip():
            raise DecisionReceiptError("Rejection reason is strictly required when approval_state is REJECTED.")
        clean_reason = decision_reason.strip()

        # When REJECTED, no response is selected for execution
        clean_selected = None

    return norm_state, clean_approver, clean_reason, clean_selected


# ------------------------------------------------------------------------------
# CORE DECISION RECEIPT CREATION
# ------------------------------------------------------------------------------

def create_decision_receipt(
    policy_result: Dict[str, Any],
    approval_state: str = STATE_PENDING,
    approver_id: Optional[str] = None,
    decision_reason: Optional[str] = None,
    selected_response: Optional[str] = None,
    timestamp: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create a deterministic Decision Receipt from a Phase 1G policy evaluation.

    Parameters:
      policy_result: Validated Phase 1G policy evaluation dictionary.
      approval_state: PENDING | APPROVED | REJECTED (defaults to PENDING).
      approver_id: Human approver username/identifier (required for APPROVED/REJECTED).
      decision_reason: Explanation of the human approval/rejection (required for APPROVED/REJECTED).
      selected_response: The response chosen for containment (defaults to recommended_response when approved).
      timestamp: Optional deterministic ISO timestamp string.

    Returns:
      Immutable, deterministic Decision Receipt dictionary.
    """
    valid_pol = validate_policy_result(policy_result)
    camp_id = valid_pol["campaign_id"]
    rec_resp = valid_pol["decision"]["recommended_response"]
    pol_dec = valid_pol["decision"]["decision"]
    pol_score = valid_pol["decision"]["policy_score"]
    conf = valid_pol["decision"]["confidence"]
    factors = copy.deepcopy(valid_pol["policy_factors"])
    reason = valid_pol["reason"]
    comp_reason = valid_pol["comparison_reason"]

    norm_state, clean_approver, clean_reason, clean_selected = validate_human_decision_parameters(
        approval_state=approval_state,
        approver_id=approver_id,
        decision_reason=decision_reason,
        selected_response=selected_response,
        recommended_response=rec_resp
    )

    clean_ts = timestamp.strip() if (timestamp and isinstance(timestamp, str) and timestamp.strip()) else DEFAULT_DETERMINISTIC_TIMESTAMP
    receipt_id = make_deterministic_receipt_id(
        campaign_id=camp_id,
        response_type=clean_selected or rec_resp,
        approval_state=norm_state
    )

    receipt = {
        "receipt_id": receipt_id,
        "receipt_status": norm_state,
        "campaign_id": camp_id,
        "recommended_response": rec_resp,
        "policy_decision": pol_dec,
        "policy_score": pol_score,
        "confidence": conf,
        "policy_factors": factors,
        "reason": reason,
        "comparison_reason": comp_reason,
        "selected_response": clean_selected,
        "human_approval_state": norm_state,
        "approval_state": norm_state,  # Convenient alias
        "approver_id": clean_approver,
        "approver": clean_approver,  # Convenient alias
        "decision_reason": clean_reason,
        "approval_reason": clean_reason,  # Convenient alias
        "timestamp": clean_ts,
        "alternatives": copy.deepcopy(valid_pol.get("alternatives", [])),
    }

    # Return deepcopy to ensure immutability
    return copy.deepcopy(receipt)


def create_pending_receipt(
    policy_result: Dict[str, Any],
    timestamp: Optional[str] = None
) -> Dict[str, Any]:
    """Convenience helper to create a PENDING decision receipt awaiting human review."""
    return create_decision_receipt(
        policy_result=policy_result,
        approval_state=STATE_PENDING,
        timestamp=timestamp
    )


def create_approved_receipt(
    policy_result: Dict[str, Any],
    approver_id: str,
    approval_reason: str,
    selected_response: Optional[str] = None,
    timestamp: Optional[str] = None
) -> Dict[str, Any]:
    """Convenience helper to create an APPROVED decision receipt."""
    return create_decision_receipt(
        policy_result=policy_result,
        approval_state=STATE_APPROVED,
        approver_id=approver_id,
        decision_reason=approval_reason,
        selected_response=selected_response,
        timestamp=timestamp
    )


def create_rejected_receipt(
    policy_result: Dict[str, Any],
    approver_id: str,
    rejection_reason: str,
    timestamp: Optional[str] = None
) -> Dict[str, Any]:
    """Convenience helper to create a REJECTED decision receipt."""
    return create_decision_receipt(
        policy_result=policy_result,
        approval_state=STATE_REJECTED,
        approver_id=approver_id,
        decision_reason=rejection_reason,
        timestamp=timestamp
    )


# ------------------------------------------------------------------------------
# OBJECT-ORIENTED WRAPPER
# ------------------------------------------------------------------------------

class DecisionReceipt:
    """
    Object-oriented wrapper representing an immutable Decision Receipt.
    """

    def __init__(self, receipt_dict: Dict[str, Any]) -> None:
        # Validate internal structure
        if not isinstance(receipt_dict, dict) or "receipt_id" not in receipt_dict:
            raise DecisionReceiptError("Invalid receipt dictionary structure.")
        self._data = copy.deepcopy(receipt_dict)

    @classmethod
    def from_policy(
        cls,
        policy_result: Dict[str, Any],
        approval_state: str = STATE_PENDING,
        approver_id: Optional[str] = None,
        decision_reason: Optional[str] = None,
        selected_response: Optional[str] = None,
        timestamp: Optional[str] = None
    ) -> "DecisionReceipt":
        """Construct a DecisionReceipt from a Phase 1G policy result."""
        data = create_decision_receipt(
            policy_result=policy_result,
            approval_state=approval_state,
            approver_id=approver_id,
            decision_reason=decision_reason,
            selected_response=selected_response,
            timestamp=timestamp
        )
        return cls(data)

    def to_dict(self) -> Dict[str, Any]:
        """Export receipt as a dictionary copy."""
        return copy.deepcopy(self._data)

    @property
    def receipt_id(self) -> str:
        return self._data["receipt_id"]

    @property
    def receipt_status(self) -> str:
        return self._data["receipt_status"]

    @property
    def campaign_id(self) -> str:
        return self._data["campaign_id"]

    @property
    def recommended_response(self) -> str:
        return self._data["recommended_response"]

    @property
    def selected_response(self) -> Optional[str]:
        return self._data["selected_response"]

    @property
    def human_approval_state(self) -> str:
        return self._data["human_approval_state"]

    @property
    def approver_id(self) -> Optional[str]:
        return self._data["approver_id"]

    @property
    def decision_reason(self) -> Optional[str]:
        return self._data["decision_reason"]

    def approve(
        self,
        approver_id: str,
        approval_reason: str,
        selected_response: Optional[str] = None,
        timestamp: Optional[str] = None
    ) -> "DecisionReceipt":
        """Transition receipt to APPROVED, returning a new immutable DecisionReceipt instance."""
        # Recreate receipt using existing policy data
        policy_data = {
            "campaign_id": self._data["campaign_id"],
            "decision": {
                "recommended_response": self._data["recommended_response"],
                "decision": self._data["policy_decision"],
                "policy_score": self._data["policy_score"],
                "confidence": self._data["confidence"],
            },
            "alternatives": self._data.get("alternatives", []),
            "policy_factors": self._data["policy_factors"],
            "reason": self._data["reason"],
            "comparison_reason": self._data["comparison_reason"],
        }
        return DecisionReceipt.from_policy(
            policy_result=policy_data,
            approval_state=STATE_APPROVED,
            approver_id=approver_id,
            decision_reason=approval_reason,
            selected_response=selected_response or self._data["recommended_response"],
            timestamp=timestamp or self._data.get("timestamp")
        )

    def reject(
        self,
        approver_id: str,
        rejection_reason: str,
        timestamp: Optional[str] = None
    ) -> "DecisionReceipt":
        """Transition receipt to REJECTED, returning a new immutable DecisionReceipt instance."""
        policy_data = {
            "campaign_id": self._data["campaign_id"],
            "decision": {
                "recommended_response": self._data["recommended_response"],
                "decision": self._data["policy_decision"],
                "policy_score": self._data["policy_score"],
                "confidence": self._data["confidence"],
            },
            "alternatives": self._data.get("alternatives", []),
            "policy_factors": self._data["policy_factors"],
            "reason": self._data["reason"],
            "comparison_reason": self._data["comparison_reason"],
        }
        return DecisionReceipt.from_policy(
            policy_result=policy_data,
            approval_state=STATE_REJECTED,
            approver_id=approver_id,
            decision_reason=rejection_reason,
            timestamp=timestamp or self._data.get("timestamp")
        )


# ------------------------------------------------------------------------------
# CONVENIENCE PIPELINE HELPERS
# ------------------------------------------------------------------------------

def create_receipt_from_graph(
    graph: Dict[str, Any],
    approval_state: str = STATE_PENDING,
    approver_id: Optional[str] = None,
    decision_reason: Optional[str] = None,
    selected_response: Optional[str] = None,
    timestamp: Optional[str] = None
) -> Dict[str, Any]:
    """
    Convenience helper executing:
    Phase 1D Graph -> 1E Lab -> 1F Twin -> 1G Policy -> 1H Decision Receipt.
    """
    if evaluate_policy_from_graph is None:
        raise DecisionReceiptError("Phase 1G evaluate_policy_from_graph is not available.")
    pol_result = evaluate_policy_from_graph(graph)
    return create_decision_receipt(
        policy_result=pol_result,
        approval_state=approval_state,
        approver_id=approver_id,
        decision_reason=decision_reason,
        selected_response=selected_response,
        timestamp=timestamp
    )


def create_receipt_from_events(
    events: Sequence[Dict[str, Any]],
    time_window_minutes: float = 30.0,
    campaign_id_prefix: Optional[str] = None,
    approval_state: str = STATE_PENDING,
    approver_id: Optional[str] = None,
    decision_reason: Optional[str] = None,
    selected_response: Optional[str] = None,
    timestamp: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Convenience helper executing full Phase 1 pipeline:
    1A Events -> 1B Campaign -> 1C Story -> 1D Graph -> 1E Lab -> 1F Twin -> 1G Policy -> 1H Decision Receipt.
    """
    if evaluate_policy_from_events is None:
        raise DecisionReceiptError("Phase 1G evaluate_policy_from_events is not available.")
    pol_result = evaluate_policy_from_events(
        events=events,
        time_window_minutes=time_window_minutes,
        campaign_id_prefix=campaign_id_prefix
    )
    if not pol_result:
        return None
    return create_decision_receipt(
        policy_result=pol_result,
        approval_state=approval_state,
        approver_id=approver_id,
        decision_reason=decision_reason,
        selected_response=selected_response,
        timestamp=timestamp
    )
