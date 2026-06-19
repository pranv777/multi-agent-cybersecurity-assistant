"""
Recommendation Agent
─────────────────────
Generates actionable mitigation advice using:
  1. Rule-based recommendations (always run, instant)
  2. Ollama LLM for context-aware, enriched recommendations
"""
import logging
from typing import List

from app.services.llm_service import generate_recommendations

logger = logging.getLogger(__name__)

# ── Static rule-based recommendations ────────────────────────────────────────

_THREAT_RULES: dict = {
    "Brute Force": [
        "Enable account lockout policy after 5 failed attempts.",
        "Implement Multi-Factor Authentication (MFA) on all authentication endpoints.",
        "Rate-limit login attempts per IP using fail2ban or equivalent.",
        "Review and block offending IP addresses in your firewall.",
    ],
    "Port Scan": [
        "Restrict inbound connections to only required ports (principle of least privilege).",
        "Deploy an Intrusion Detection System (IDS) such as Snort or Suricata.",
        "Enable port-scan detection on your edge firewall.",
        "Conduct a network surface review and close unused services.",
    ],
    "Malware Indicator": [
        "Isolate affected systems from the network immediately.",
        "Run a full anti-malware scan using up-to-date signatures.",
        "Review and revoke compromised credentials.",
        "Preserve forensic evidence before remediation.",
    ],
    "Suspicious Tool Usage": [
        "Identify and quarantine the source of the attack tool activity.",
        "Audit user and service accounts for unauthorised access.",
        "Enable detailed audit logging and SIEM alerting.",
    ],
    "Authentication Anomaly": [
        "Review access logs for the suspicious IP range.",
        "Enforce strong password policies and rotate compromised credentials.",
        "Enable adaptive authentication / anomaly-based MFA triggers.",
    ],
    "Statistical Anomaly": [
        "Investigate the anomalous log pattern manually.",
        "Correlate with network traffic captures for confirmation.",
        "Increase logging verbosity temporarily to gather more evidence.",
    ],
}

_CVE_RULES: dict = {
    "Critical": [
        "Apply vendor patches for all Critical CVEs immediately (zero-day window).",
        "Consider temporary mitigation (WAF rules, service disable) until patch is deployed.",
    ],
    "High": [
        "Schedule patching of High-severity CVEs within 7 days.",
        "Review vendor security advisories for available workarounds.",
    ],
    "Medium": [
        "Plan patching of Medium CVEs in the next maintenance window.",
        "Monitor vendor advisories for escalation of severity.",
    ],
    "Low": [
        "Track Low CVEs in your vulnerability management backlog.",
    ],
}

_GENERAL: List[str] = [
    "Maintain a current asset inventory with software versions.",
    "Implement a vulnerability management program with regular scanning.",
    "Enforce network segmentation to limit lateral movement.",
    "Ensure all security logs are centralised and retained for at least 90 days.",
    "Conduct periodic penetration tests and red-team exercises.",
]


def _rule_based_recommendations(threats: List[dict], vulnerabilities: List[dict]) -> List[str]:
    recs: List[str] = []
    seen: set = set()

    for threat in threats:
        t_type = threat.get("type", "")
        for rule_key, rule_recs in _THREAT_RULES.items():
            if rule_key.lower() in t_type.lower():
                for r in rule_recs:
                    if r not in seen:
                        seen.add(r)
                        recs.append(r)

    cve_severities = {v.get("severity", "Low") for v in vulnerabilities}
    for sev in ("Critical", "High", "Medium", "Low"):
        if sev in cve_severities:
            for r in _CVE_RULES.get(sev, []):
                if r not in seen:
                    seen.add(r)
                    recs.append(r)

    for r in _GENERAL:
        if r not in seen:
            seen.add(r)
            recs.append(r)

    return recs


def _priority_actions(threats: List[dict], vulnerabilities: List[dict], risk_level: str) -> List[str]:
    actions: List[str] = []
    if risk_level in ("Critical", "High"):
        actions.append("IMMEDIATE: Escalate to security incident response team.")
    for v in vulnerabilities:
        if v.get("severity") == "Critical":
            actions.append(f"PATCH NOW: {v.get('cve')} in {v.get('software')} (CVSS {v.get('cvss')}).")
    for t in threats:
        if t.get("severity") == "Critical":
            actions.append(f"ISOLATE: Address critical threat — {t.get('type')}.")
    if not actions:
        actions.append("Schedule a security review within 30 days.")
    return actions[:6]


def run_recommendation(state: dict) -> dict:
    """
    LangGraph node: recommendation_agent.
    Reads threats, vulnerabilities, risk_score, risk_level.
    Updates state["recommendations"] and state["priority_actions"].
    """
    logger.info("[Recommendation] Generating recommendations…")
    threats: List[dict] = state.get("threats", [])
    vulnerabilities: List[dict] = state.get("vulnerabilities", [])
    risk_level: str = state.get("risk_level", "Low")

    # Rule-based base
    rule_recs = _rule_based_recommendations(threats, vulnerabilities)
    priority = _priority_actions(threats, vulnerabilities, risk_level)

    # LLM enrichment
    llm_result = generate_recommendations(
        {
            "threats": threats,
            "vulnerabilities": vulnerabilities,
            "risk_score": state.get("risk_score", 0),
            "risk_level": risk_level,
        }
    )
    llm_recs: List[str] = llm_result.get("recommendations", [])
    llm_priority: List[str] = llm_result.get("priority_actions", [])

    # Merge — LLM recs first (more contextual), then rule-based for completeness
    final_recs: List[str] = []
    seen: set = set()
    for r in llm_recs + rule_recs:
        if r.strip() and r not in seen:
            seen.add(r)
            final_recs.append(r)

    final_priority: List[str] = []
    seen_p: set = set()
    for p in llm_priority + priority:
        if p.strip() and p not in seen_p:
            seen_p.add(p)
            final_priority.append(p)

    logger.info(
        "[Recommendation] %d recommendations, %d priority actions.",
        len(final_recs),
        len(final_priority),
    )
    state["recommendations"] = final_recs[:15]
    state["priority_actions"] = final_priority[:6]
    state["processing_steps"].append(
        f"recommendation: {len(final_recs)} recommendations generated"
    )
    return state
