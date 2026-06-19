"""
Risk Scoring Agent
───────────────────
Formula:
  risk_score = 0.4 × threat_severity_score
             + 0.4 × cvss_average
             + 0.2 × confidence_average

Severity mapping: Low=25, Medium=50, High=75, Critical=100
"""
import logging
from typing import List

logger = logging.getLogger(__name__)

SEVERITY_MAP = {"Low": 25.0, "Medium": 50.0, "High": 75.0, "Critical": 100.0}
WEIGHT_THREAT = 0.4
WEIGHT_CVSS = 0.4
WEIGHT_CONF = 0.2


def _risk_level(score: float) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def _avg_threat_severity(threats: List[dict]) -> float:
    if not threats:
        return 0.0
    values = [SEVERITY_MAP.get(t.get("severity", "Low"), 25.0) for t in threats]
    return sum(values) / len(values)


def _avg_cvss(vulnerabilities: List[dict]) -> float:
    if not vulnerabilities:
        return 0.0
    scores = [v.get("cvss", 0.0) for v in vulnerabilities]
    # Normalise CVSS 0–10 → 0–100
    return (sum(scores) / len(scores)) * 10


def _avg_confidence(threats: List[dict]) -> float:
    if not threats:
        return 0.0
    confs = [t.get("confidence", 0.5) for t in threats]
    return (sum(confs) / len(confs)) * 100  # → 0–100


def run_risk_scoring(state: dict) -> dict:
    """
    LangGraph node: risk_scoring_agent.
    Reads state["threats"] and state["vulnerabilities"].
    Updates state["risk_score"] and state["risk_level"].
    """
    logger.info("[RiskScoring] Computing risk score…")
    threats: List[dict] = state.get("threats", [])
    vulnerabilities: List[dict] = state.get("vulnerabilities", [])

    threat_sev = _avg_threat_severity(threats)
    cvss_avg = _avg_cvss(vulnerabilities)
    conf_avg = _avg_confidence(threats)

    risk_score = (
        WEIGHT_THREAT * threat_sev
        + WEIGHT_CVSS * cvss_avg
        + WEIGHT_CONF * conf_avg
    )
    risk_score = round(min(100.0, max(0.0, risk_score)), 1)
    level = _risk_level(risk_score)

    explanation = (
        f"Risk score breakdown — "
        f"Threat severity component: {threat_sev:.1f}×{WEIGHT_THREAT} = {threat_sev*WEIGHT_THREAT:.1f}; "
        f"CVSS component: {cvss_avg:.1f}×{WEIGHT_CVSS} = {cvss_avg*WEIGHT_CVSS:.1f}; "
        f"Confidence component: {conf_avg:.1f}×{WEIGHT_CONF} = {conf_avg*WEIGHT_CONF:.1f}; "
        f"Total = {risk_score}. "
        f"Based on {len(threats)} threat(s) and {len(vulnerabilities)} CVE(s)."
    )

    logger.info("[RiskScoring] Score: %.1f (%s)", risk_score, level)
    state["risk_score"] = risk_score
    state["risk_level"] = level
    state["risk_explanation"] = explanation
    state["risk_components"] = {
        "threat_severity_score": round(threat_sev, 2),
        "cvss_average": round(cvss_avg, 2),
        "confidence_average": round(conf_avg, 2),
    }
    state["processing_steps"].append(
        f"risk_scoring: score={risk_score} level={level}"
    )
    return state
