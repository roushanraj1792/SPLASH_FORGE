"""
Internal Verification Engine — Deterministic Outcome & Prediction Checking
===========================================================================
Part of the SentinelX Detection & Incident Response Platform (Phase 1I).

Role:
  Compares PREDICTED outcomes (from Cyber Twin / Policy Engine / Decision Receipt)
  against OBSERVED or SIMULATED outcomes.
  Operates purely in-memory and deterministically.

Safety & Boundary Rules:
  - ZERO FABRICATION: Never pretends real-world containment happened if it did not.
    When actual execution telemetry is absent, explicitly marks
    execution_status as EXECUTION_NOT_PERFORMED.
  - ZERO REAL CONTAINMENT: Never calls firewall, iptables, or services.containment.
  - ZERO NETWORK: No sockets, no HTTP, no external connections.
  - ZERO DATABASE WRITES: Operates strictly in memory.
  - ZERO THIRD-PARTY AI: No Gemini, no Telegram.
  - ZERO RANDOMNESS: Deterministic calculations, no UUIDs, no datetime.now() dependency.
"""

import copy
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

# ------------------------------------------------------------------------------
# CONSTANTS & STATES
# ------------------------------------------------------------------------------

STATUS_NOT_VERIFIED = "NOT_VERIFIED"
STATUS_VERIFIED = "VERIFIED"
STATUS_PARTIALLY_VERIFIED = "PARTIALLY_VERIFIED"
STATUS_FAILED = "FAILED"

VALID_VERIFICATION_STATES = {
    STATUS_NOT_VERIFIED,
    STATUS_VERIFIED,
    STATUS_PARTIALLY_VERIFIED,
    STATUS_FAILED,
}

EXECUTION_NOT_PERFORMED = "EXECUTION_NOT_PERFORMED"
EXECUTION_SIMULATED = "EXECUTION_SIMULATED"
EXECUTION_OBSERVED = "EXECUTION_OBSERVED"

VALID_EXECUTION_STATUSES = {
    EXECUTION_NOT_PERFORMED,
    EXECUTION_SIMULATED,
    EXECUTION_OBSERVED,
}

DEFAULT_METRIC_TOLERANCE = 15
DEFAULT_DETERMINISTIC_TIMESTAMP = "2026-09-15T00:00:00Z"

COMPARISON_METRICS = (
    "residual_risk",
    "containment_effectiveness",
    "blast_radius",
    "security_risk",
)


# ------------------------------------------------------------------------------
# EXCEPTIONS
# ------------------------------------------------------------------------------

class VerificationError(ValueError):
    """Raised when verification input is malformed, invalid, or missing required fields."""
    pass


# ------------------------------------------------------------------------------
# DETERMINISTIC IDENTIFIERS
# ------------------------------------------------------------------------------

def make_deterministic_verification_id(
    campaign_id: str,
    response_type: Optional[str],
    verification_status: str
) -> str:
    """
    Generate a deterministic verification identifier.
    Format: ver:<campaign_id>:<response_type>:<status>
    """
    clean_camp = campaign_id.strip().lower() if campaign_id else "unknown"
    clean_resp = response_type.strip().lower() if response_type else "none"
    clean_status = verification_status.strip().lower() if verification_status else "not_verified"
    return f"ver:{clean_camp}:{clean_resp}:{clean_status}"


# ------------------------------------------------------------------------------
# VALIDATION UTILITIES
# ------------------------------------------------------------------------------

def validate_metric_value(name: str, value: Any) -> int:
    """Validate that a metric value is an integer or float between 0 and 100."""
    if value is None or not isinstance(value, (int, float)):
        raise VerificationError(f"Metric '{name}' must be a numeric value, got {type(value).__name__}: {repr(value)}")
    int_val = int(round(value))
    if int_val < 0 or int_val > 100:
        raise VerificationError(f"Metric '{name}' ({int_val}) out of bounds; must be between 0 and 100.")
    return int_val


def validate_predicted_outcome(predicted: Any) -> Dict[str, Any]:
    """
    Validate that predicted outcome contains necessary metric fields.
    Accepts dictionaries from Cyber Twin simulations, Response Lab evaluations,
    or Policy Engine results.
    """
    if predicted is None:
        raise VerificationError("Predicted outcome cannot be None.")
    if not isinstance(predicted, dict):
        raise VerificationError(f"Predicted outcome must be a dictionary, got: {type(predicted).__name__}")
    if not predicted:
        raise VerificationError("Predicted outcome dictionary cannot be empty.")

    # Campaign ID (optional but if present must be valid string)
    campaign_id = predicted.get("campaign_id", "UNKNOWN-CAMPAIGN")
    if not isinstance(campaign_id, str):
        campaign_id = str(campaign_id)

    # Response type
    resp_type = (
        predicted.get("selected_response")
        or predicted.get("recommended_response")
        or predicted.get("response")
    )
    if resp_type and not isinstance(resp_type, str):
        raise VerificationError(f"Invalid response type in predicted outcome: {repr(resp_type)}")

    # Extract metrics (checking top-level or inside 'policy_factors' / 'predicted_impact')
    factors = predicted.get("policy_factors") or predicted.get("predicted_impact") or predicted

    metrics: Dict[str, int] = {}
    for m in COMPARISON_METRICS:
        val = factors.get(m)
        if val is None:
            # Fallback mappings
            if m == "security_risk":
                val = predicted.get("score") or factors.get("risk_score") or 50
            elif m == "containment_effectiveness":
                val = factors.get("effectiveness") or 80
            elif m == "residual_risk":
                val = 20
            elif m == "blast_radius":
                val = 10
        metrics[m] = validate_metric_value(m, val)

    conf_val = predicted.get("confidence")
    confidence = validate_metric_value("confidence", conf_val if conf_val is not None else 80)

    return {
        "campaign_id": campaign_id.strip(),
        "response": resp_type.strip().upper() if resp_type else None,
        "metrics": metrics,
        "confidence": confidence,
    }


def validate_observed_outcome(observed: Any) -> Dict[str, Any]:
    """Validate observed or simulated post-containment telemetry dictionary."""
    if observed is None:
        raise VerificationError("Observed outcome cannot be None when validating.")
    if not isinstance(observed, dict):
        raise VerificationError(f"Observed outcome must be a dictionary, got: {type(observed).__name__}")

    resp_type = observed.get("response") or observed.get("executed_response") or observed.get("selected_response")
    if resp_type and not isinstance(resp_type, str):
        raise VerificationError(f"Invalid response in observed outcome: {repr(resp_type)}")

    factors = observed.get("observed_metrics") or observed.get("metrics") or observed

    metrics: Dict[str, int] = {}
    for m in COMPARISON_METRICS:
        val = factors.get(m)
        if val is None:
            if m == "security_risk":
                val = observed.get("score") or factors.get("risk_score") or 50
            elif m == "containment_effectiveness":
                val = 80
            elif m == "residual_risk":
                val = 20
            elif m == "blast_radius":
                val = 10
        metrics[m] = validate_metric_value(m, val)

    return {
        "response": resp_type.strip().upper() if resp_type else None,
        "metrics": metrics,
    }


# ------------------------------------------------------------------------------
# CORE VERIFICATION LOGIC
# ------------------------------------------------------------------------------

def verify_outcome(
    predicted: Dict[str, Any],
    observed: Optional[Dict[str, Any]] = None,
    receipt: Optional[Dict[str, Any]] = None,
    tolerance: int = DEFAULT_METRIC_TOLERANCE,
    is_simulation: bool = True,
    timestamp: Optional[str] = None
) -> Dict[str, Any]:
    """
    Deterministically compare predicted versus observed or simulated outcome.

    Parameters:
      predicted: Predicted metrics (from Cyber Twin simulation, Policy Engine, or Response Lab).
      observed: Observed metrics dictionary (optional; if None, records EXECUTION_NOT_PERFORMED).
      receipt: Associated Decision Receipt (optional; if REJECTED, marks EXECUTION_NOT_PERFORMED).
      tolerance: Allowable absolute divergence per metric before flagging discrepancy.
      is_simulation: True if observed metrics originate from a simulation, False if live.
      timestamp: Optional deterministic ISO timestamp.

    Returns:
      Deterministic verification record dictionary.
    """
    if tolerance < 0 or tolerance > 100:
        raise VerificationError(f"Tolerance ({tolerance}) must be between 0 and 100.")

    valid_pred = validate_predicted_outcome(predicted)
    camp_id = valid_pred["campaign_id"]
    pred_metrics = valid_pred["metrics"]
    pred_conf = valid_pred["confidence"]
    expected_resp = valid_pred["response"]

    selected_resp = expected_resp
    human_approval_state = None
    if receipt and isinstance(receipt, dict):
        if "campaign_id" in receipt and receipt["campaign_id"]:
            camp_id = receipt["campaign_id"]
        selected_resp = receipt.get("selected_response") or expected_resp
        human_approval_state = receipt.get("human_approval_state") or receipt.get("receipt_status")

    clean_ts = timestamp.strip() if (timestamp and isinstance(timestamp, str) and timestamp.strip()) else DEFAULT_DETERMINISTIC_TIMESTAMP

    # Case A: Human Decision was REJECTED -> Execution was deliberately stopped
    if human_approval_state == "REJECTED":
        status = STATUS_NOT_VERIFIED
        execution_status = EXECUTION_NOT_PERFORMED
        explanation = "Human decision state was REJECTED. Containment execution was not authorized; outcome verification cannot be performed."
        ver_id = make_deterministic_verification_id(camp_id, selected_resp, status)
        return {
            "verification_id": ver_id,
            "verification_status": status,
            "verification_score": 0,
            "confidence": pred_conf,
            "campaign_id": camp_id,
            "expected_response": expected_resp,
            "selected_response": None,
            "execution_performed": False,
            "execution_status": execution_status,
            "discrepancies": [],
            "predicted_risk": pred_metrics["security_risk"],
            "observed_risk": None,
            "predicted_containment_effectiveness": pred_metrics["containment_effectiveness"],
            "observed_containment_effectiveness": None,
            "predicted_residual_risk": pred_metrics["residual_risk"],
            "observed_residual_risk": None,
            "predicted_blast_radius": pred_metrics["blast_radius"],
            "observed_blast_radius": None,
            "tolerance": tolerance,
            "explanation": explanation,
            "timestamp": clean_ts,
        }

    # Case B: Human Decision is PENDING -> Awaiting authorization
    if human_approval_state == "PENDING" and observed is None:
        status = STATUS_NOT_VERIFIED
        execution_status = EXECUTION_NOT_PERFORMED
        explanation = "Human approval is PENDING. Execution has not occurred; outcome verification is awaiting authorization."
        ver_id = make_deterministic_verification_id(camp_id, selected_resp, status)
        return {
            "verification_id": ver_id,
            "verification_status": status,
            "verification_score": 0,
            "confidence": pred_conf,
            "campaign_id": camp_id,
            "expected_response": expected_resp,
            "selected_response": selected_resp,
            "execution_performed": False,
            "execution_status": execution_status,
            "discrepancies": [],
            "predicted_risk": pred_metrics["security_risk"],
            "observed_risk": None,
            "predicted_containment_effectiveness": pred_metrics["containment_effectiveness"],
            "observed_containment_effectiveness": None,
            "predicted_residual_risk": pred_metrics["residual_risk"],
            "observed_residual_risk": None,
            "predicted_blast_radius": pred_metrics["blast_radius"],
            "observed_blast_radius": None,
            "tolerance": tolerance,
            "explanation": explanation,
            "timestamp": clean_ts,
        }

    # Case C: No observed telemetry data provided -> Do not fabricate containment
    if observed is None:
        status = STATUS_NOT_VERIFIED
        execution_status = EXECUTION_NOT_PERFORMED
        explanation = "No observed or simulated execution data provided. Real containment was not performed."
        ver_id = make_deterministic_verification_id(camp_id, selected_resp, status)
        return {
            "verification_id": ver_id,
            "verification_status": status,
            "verification_score": 0,
            "confidence": pred_conf,
            "campaign_id": camp_id,
            "expected_response": expected_resp,
            "selected_response": selected_resp,
            "execution_performed": False,
            "execution_status": execution_status,
            "discrepancies": [],
            "predicted_risk": pred_metrics["security_risk"],
            "observed_risk": None,
            "predicted_containment_effectiveness": pred_metrics["containment_effectiveness"],
            "observed_containment_effectiveness": None,
            "predicted_residual_risk": pred_metrics["residual_risk"],
            "observed_residual_risk": None,
            "predicted_blast_radius": pred_metrics["blast_radius"],
            "observed_blast_radius": None,
            "tolerance": tolerance,
            "explanation": explanation,
            "timestamp": clean_ts,
        }

    # Case D: Observed telemetry data IS provided -> Perform deterministic metric checking
    valid_obs = validate_observed_outcome(observed)
    obs_metrics = valid_obs["metrics"]
    obs_resp = valid_obs["response"]

    execution_status = EXECUTION_SIMULATED if is_simulation else EXECUTION_OBSERVED

    discrepancies: List[Dict[str, Any]] = []
    total_abs_diff = 0
    max_diff = 0

    for m in COMPARISON_METRICS:
        p_val = pred_metrics[m]
        o_val = obs_metrics[m]
        diff = abs(p_val - o_val)
        total_abs_diff += diff
        if diff > max_diff:
            max_diff = diff
        if diff > tolerance:
            discrepancies.append({
                "metric": m,
                "predicted": p_val,
                "observed": o_val,
                "difference": diff,
                "tolerance": tolerance,
                "status": "EXCEEDED_TOLERANCE",
            })

    # Response mismatch penalty
    response_mismatch = False
    if obs_resp and selected_resp and obs_resp != selected_resp:
        response_mismatch = True
        discrepancies.append({
            "metric": "response_type",
            "predicted": selected_resp,
            "observed": obs_resp,
            "difference": 100,
            "tolerance": 0,
            "status": "RESPONSE_MISMATCH",
        })

    # Verification score calculation [0 - 100]
    # Average difference across 4 metrics
    avg_diff = total_abs_diff / len(COMPARISON_METRICS)
    raw_score = 100 - int(round(avg_diff))
    if response_mismatch:
        raw_score -= 50
    ver_score = max(0, min(100, raw_score))

    # Determine status
    if response_mismatch or max_diff > 35 or ver_score < 50:
        status = STATUS_FAILED
        explanation = f"Verification FAILED: Significant discrepancy between predicted and observed outcomes (Score: {ver_score}/100, Max diff: {max_diff})."
    elif len(discrepancies) > 0 or ver_score < 85:
        status = STATUS_PARTIALLY_VERIFIED
        explanation = f"Verification PARTIALLY_VERIFIED: Outcomes align with minor divergence on {len(discrepancies)} metric(s) (Score: {ver_score}/100)."
    else:
        status = STATUS_VERIFIED
        explanation = f"Verification VERIFIED: Observed outcomes conform strictly to predicted models within {tolerance}pt tolerance (Score: {ver_score}/100)."

    ver_id = make_deterministic_verification_id(camp_id, selected_resp or obs_resp, status)

    result = {
        "verification_id": ver_id,
        "verification_status": status,
        "verification_score": ver_score,
        "confidence": pred_conf,
        "campaign_id": camp_id,
        "expected_response": expected_resp,
        "selected_response": selected_resp or obs_resp,
        "execution_performed": True,
        "execution_status": execution_status,
        "discrepancies": discrepancies,
        "predicted_risk": pred_metrics["security_risk"],
        "observed_risk": obs_metrics["security_risk"],
        "predicted_containment_effectiveness": pred_metrics["containment_effectiveness"],
        "observed_containment_effectiveness": obs_metrics["containment_effectiveness"],
        "predicted_residual_risk": pred_metrics["residual_risk"],
        "observed_residual_risk": obs_metrics["residual_risk"],
        "predicted_blast_radius": pred_metrics["blast_radius"],
        "observed_blast_radius": obs_metrics["blast_radius"],
        "tolerance": tolerance,
        "explanation": explanation,
        "timestamp": clean_ts,
    }

    return copy.deepcopy(result)


# ------------------------------------------------------------------------------
# CONVENIENCE HELPERS
# ------------------------------------------------------------------------------

def verify_from_receipt(
    receipt: Dict[str, Any],
    observed_outcome: Optional[Dict[str, Any]] = None,
    tolerance: int = DEFAULT_METRIC_TOLERANCE,
    is_simulation: bool = True,
    timestamp: Optional[str] = None
) -> Dict[str, Any]:
    """
    Convenience function verifying outcomes directly from a Phase 1H Decision Receipt.
    """
    if not isinstance(receipt, dict):
        raise VerificationError(f"Receipt must be a dictionary, got: {type(receipt).__name__}")
    return verify_outcome(
        predicted=receipt,
        observed=observed_outcome,
        receipt=receipt,
        tolerance=tolerance,
        is_simulation=is_simulation,
        timestamp=timestamp
    )


def verify_hypothetical_simulation(
    twin_simulation: Dict[str, Any],
    receipt: Dict[str, Any],
    tolerance: int = DEFAULT_METRIC_TOLERANCE,
    timestamp: Optional[str] = None
) -> Dict[str, Any]:
    """
    Convenience function verifying against Cyber Twin predicted simulation.
    """
    if not isinstance(twin_simulation, dict):
        raise VerificationError("twin_simulation must be a dictionary.")
    return verify_outcome(
        predicted=twin_simulation,
        observed=twin_simulation.get("predicted_impact", twin_simulation),
        receipt=receipt,
        tolerance=tolerance,
        is_simulation=True,
        timestamp=timestamp
    )


# ------------------------------------------------------------------------------
# OBJECT-ORIENTED WRAPPER
# ------------------------------------------------------------------------------

class VerificationResult:
    """
    Object-oriented wrapper representing an immutable Outcome Verification record.
    """

    def __init__(self, data: Dict[str, Any]) -> None:
        if not isinstance(data, dict) or "verification_id" not in data:
            raise VerificationError("Invalid verification data structure.")
        self._data = copy.deepcopy(data)

    @classmethod
    def from_outcomes(
        cls,
        predicted: Dict[str, Any],
        observed: Optional[Dict[str, Any]] = None,
        receipt: Optional[Dict[str, Any]] = None,
        tolerance: int = DEFAULT_METRIC_TOLERANCE,
        is_simulation: bool = True,
        timestamp: Optional[str] = None
    ) -> "VerificationResult":
        res = verify_outcome(
            predicted=predicted,
            observed=observed,
            receipt=receipt,
            tolerance=tolerance,
            is_simulation=is_simulation,
            timestamp=timestamp
        )
        return cls(res)

    def to_dict(self) -> Dict[str, Any]:
        return copy.deepcopy(self._data)

    @property
    def verification_id(self) -> str:
        return self._data["verification_id"]

    @property
    def verification_status(self) -> str:
        return self._data["verification_status"]

    @property
    def verification_score(self) -> int:
        return self._data["verification_score"]

    @property
    def execution_status(self) -> str:
        return self._data["execution_status"]

    @property
    def execution_performed(self) -> bool:
        return self._data["execution_performed"]

    @property
    def discrepancies(self) -> List[Dict[str, Any]]:
        return copy.deepcopy(self._data["discrepancies"])

    @property
    def explanation(self) -> str:
        return self._data["explanation"]
