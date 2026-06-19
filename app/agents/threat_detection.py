"""
Threat Detection Agent
─────────────────────
Phase 1 : Regex / rule-based detection
Phase 2 : Isolation Forest anomaly detection (scikit-learn)
Phase 3 : LLM-assisted interpretation (Ollama)
"""
import re
import logging
import numpy as np
from typing import List, Dict, Any

from app.parsers.log_parser import parse_log_file
from app.services.llm_service import analyze_security_logs

logger = logging.getLogger(__name__)


# ── Severity helpers ──────────────────────────────────────────────────────────

def _compute_confidence(evidence_count: int, base: float = 0.6) -> float:
    boost = min(0.35, evidence_count * 0.05)
    return round(min(0.99, base + boost), 2)


def _severity_from_count(count: int) -> str:
    if count >= 50:
        return "Critical"
    if count >= 20:
        return "High"
    if count >= 5:
        return "Medium"
    return "Low"


# ── Rule-based detection ──────────────────────────────────────────────────────

def _detect_brute_force(log_stats: dict, raw_content: str) -> List[dict]:
    threats = []
    failed = log_stats.get("failed_logins", [])
    brute = log_stats.get("brute_force_events", [])
    total = len(failed) + len(brute)

    # Group by IP
    ip_fail: Dict[str, int] = {}
    for ev in failed:
        for ip in ev.get("ips", []):
            ip_fail[ip] = ip_fail.get(ip, 0) + 1

    for ip, count in ip_fail.items():
        if count >= 5:
            threats.append(
                {
                    "type": "Brute Force",
                    "severity": _severity_from_count(count),
                    "confidence": _compute_confidence(count, 0.70),
                    "evidence": [
                        f"{count} failed login attempts from IP {ip}",
                        f"Matches rule: repeated auth failure threshold",
                    ],
                    "source_ip": ip,
                }
            )

    if total >= 3 and not threats:
        threats.append(
            {
                "type": "Brute Force",
                "severity": _severity_from_count(total),
                "confidence": _compute_confidence(total, 0.60),
                "evidence": [f"{total} failed authentication events detected"],
                "source_ip": None,
            }
        )
    return threats


def _detect_port_scan(log_stats: dict, raw_content: str) -> List[dict]:
    threats = []
    scans = log_stats.get("port_scans", [])
    if len(scans) >= 1:
        # Also check for many unique destination ports in a short window
        ports_mentioned = re.findall(r":(\d{2,5})\b", raw_content)
        unique_ports = len(set(ports_mentioned))
        evidence = [f"Port scan indicators found: {len(scans)} event(s)"]
        if unique_ports > 20:
            evidence.append(f"{unique_ports} unique ports referenced — consistent with scan activity")
        threats.append(
            {
                "type": "Port Scan",
                "severity": "High" if len(scans) > 5 else "Medium",
                "confidence": _compute_confidence(len(scans), 0.65),
                "evidence": evidence,
                "source_ip": None,
            }
        )
    return threats


def _detect_malware(log_stats: dict) -> List[dict]:
    threats = []
    events = log_stats.get("malware_events", [])
    if events:
        threats.append(
            {
                "type": "Malware Indicator",
                "severity": "Critical",
                "confidence": _compute_confidence(len(events), 0.75),
                "evidence": [
                    "Malware-related keywords detected in logs",
                    f"Affected lines: {', '.join(str(e['line']) for e in events[:5])}",
                ],
                "source_ip": None,
            }
        )
    return threats


def _detect_suspicious_tools(log_stats: dict) -> List[dict]:
    threats = []
    events = log_stats.get("suspicious_tools", [])
    if events:
        threats.append(
            {
                "type": "Suspicious Tool Usage",
                "severity": "High",
                "confidence": _compute_confidence(len(events), 0.80),
                "evidence": [
                    f"Known attack tool signatures found ({len(events)} occurrence(s))",
                    *[e["raw"][:120] for e in events[:3]],
                ],
                "source_ip": None,
            }
        )
    return threats


def _detect_auth_anomalies(log_stats: dict) -> List[dict]:
    threats = []
    top_ips = log_stats.get("top_ips", [])
    # An IP with >100 total log occurrences is suspicious
    for entry in top_ips:
        if entry["occurrences"] > 100:
            threats.append(
                {
                    "type": "Authentication Anomaly",
                    "severity": "Medium",
                    "confidence": 0.65,
                    "evidence": [
                        f"IP {entry['ip']} appears {entry['occurrences']} times in logs",
                        "High frequency may indicate automated activity",
                    ],
                    "source_ip": entry["ip"],
                }
            )
    return threats


# ── Isolation Forest (Phase 2) ────────────────────────────────────────────────

def _isolation_forest_detect(log_stats: dict) -> bool:
    """
    Build a simple feature vector from log stats and apply Isolation Forest.
    Returns True if the log profile is anomalous.
    """
    try:
        from sklearn.ensemble import IsolationForest

        # Feature vector: [failed_logins, port_scans, malware, errors, unique_ips]
        features = np.array(
            [
                [
                    len(log_stats.get("failed_logins", [])),
                    len(log_stats.get("port_scans", [])),
                    len(log_stats.get("malware_events", [])),
                    log_stats.get("error_count", 0),
                    len(log_stats.get("top_ips", [])),
                ]
            ],
            dtype=float,
        )

        # For single-sample detection we compare against a benign baseline
        baseline = np.zeros((20, 5), dtype=float)
        # Inject a mild normal distribution representing typical traffic
        rng = np.random.default_rng(42)
        baseline += rng.normal(loc=[2, 0, 0, 10, 3], scale=[1, 0.5, 0.1, 5, 1], size=(20, 5))
        baseline = np.abs(baseline)

        X = np.vstack([baseline, features])
        clf = IsolationForest(contamination=0.1, random_state=42)
        clf.fit(X)
        pred = clf.predict(features)
        return bool(pred[0] == -1)
    except Exception as e:
        logger.warning("Isolation Forest skipped: %s", e)
        return False


# ── Public entry point ────────────────────────────────────────────────────────

def run_threat_detection(state: dict) -> dict:
    """
    LangGraph node: threat_detection_agent.
    Reads state["parsed_content"] and state["raw_logs"].
    Updates state["threats"] and appends to state["processing_steps"].
    """
    logger.info("[ThreatDetection] Starting analysis…")
    content = state.get("parsed_content", "") or state.get("raw_logs", "")
    if not content:
        logger.warning("[ThreatDetection] No content to analyse.")
        state["threats"] = []
        state["processing_steps"].append("threat_detection: no content")
        return state

    # Phase 1 — rule-based
    log_stats = parse_log_file(content)
    threats: List[dict] = []
    threats.extend(_detect_brute_force(log_stats, content))
    threats.extend(_detect_port_scan(log_stats, content))
    threats.extend(_detect_malware(log_stats))
    threats.extend(_detect_suspicious_tools(log_stats))
    threats.extend(_detect_auth_anomalies(log_stats))

    # Phase 2 — anomaly detection
    anomaly = _isolation_forest_detect(log_stats)
    if anomaly:
        logger.info("[ThreatDetection] Isolation Forest flagged anomalous log profile.")
        threats.append(
            {
                "type": "Statistical Anomaly",
                "severity": "Medium",
                "confidence": 0.70,
                "evidence": ["Isolation Forest detected unusual log distribution"],
                "source_ip": None,
            }
        )

    # Phase 3 — LLM interpretation
    llm_result = analyze_security_logs(content)
    llm_threats = llm_result.get("threats", [])
    for lt in llm_threats:
        # Avoid duplicates (same type already found by rules)
        existing_types = {t["type"].lower() for t in threats}
        if lt.get("type", "").lower() not in existing_types:
            threats.append(lt)

    logger.info("[ThreatDetection] Found %d threat(s).", len(threats))
    state["threats"] = threats
    state["processing_steps"].append(f"threat_detection: {len(threats)} threats found")
    return state
