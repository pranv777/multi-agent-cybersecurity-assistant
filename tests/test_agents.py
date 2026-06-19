"""
Unit tests — agents
"""
import pytest
from app.agents.threat_detection import run_threat_detection
from app.agents.cve_retrieval import run_cve_retrieval
from app.agents.risk_scoring import run_risk_scoring
from app.agents.recommendation import run_recommendation
from app.agents.coordinator_agent import run_coordinator, build_execution_summary


def _base_state(**kwargs) -> dict:
    state = {
        "job_id": "test-job-001",
        "files": [],
        "parsed_content": "",
        "raw_logs": "",
        "software_versions": [],
        "threats": [],
        "vulnerabilities": [],
        "risk_score": None,
        "risk_level": "",
        "risk_explanation": "",
        "risk_components": {},
        "recommendations": [],
        "priority_actions": [],
        "final_report": {},
        "errors": [],
        "processing_steps": [],
    }
    state.update(kwargs)
    return state


BRUTE_FORCE_LOG = "\n".join(
    [f"2024-01-15 08:23:0{i} sshd: Failed password for root from 192.168.1.100 port 22" for i in range(9)]
    + ["2024-01-15 08:23:10 kernel: nmap scan detected from 10.10.10.1",
       "2024-01-15 08:23:11 app: malware detected in upload"]
)


# ── Coordinator ────────────────────────────────────────────────────────────────

class TestCoordinatorAgent:
    def test_initialises_state_keys(self):
        state = run_coordinator(_base_state())
        assert "processing_steps" in state
        assert any("coordinator" in s for s in state["processing_steps"])

    def test_adds_missing_keys(self):
        minimal = {"job_id": "x"}
        result = run_coordinator(minimal)
        assert "files" in result
        assert "processing_steps" in result

    def test_execution_summary(self):
        state = _base_state(
            threats=[{"type": "BF", "severity": "High"}],
            risk_score=75.0,
            risk_level="High",
        )
        summary = build_execution_summary(state)
        assert "Risk score" in summary
        assert "75" in summary


# ── Threat Detection ──────────────────────────────────────────────────────────

class TestThreatDetectionAgent:
    def test_detects_brute_force(self):
        state = _base_state(parsed_content=BRUTE_FORCE_LOG)
        result = run_threat_detection(state)
        types = [t["type"] for t in result["threats"]]
        assert any("Brute" in t for t in types)

    def test_detects_port_scan(self):
        state = _base_state(parsed_content=BRUTE_FORCE_LOG)
        result = run_threat_detection(state)
        types = [t["type"] for t in result["threats"]]
        assert any("Port" in t or "Scan" in t for t in types)

    def test_detects_malware(self):
        state = _base_state(parsed_content=BRUTE_FORCE_LOG)
        result = run_threat_detection(state)
        types = [t["type"] for t in result["threats"]]
        assert any("Malware" in t for t in types)

    def test_empty_content_returns_empty_threats(self):
        state = _base_state(parsed_content="")
        result = run_threat_detection(state)
        assert result["threats"] == []

    def test_threats_have_required_fields(self):
        state = _base_state(parsed_content=BRUTE_FORCE_LOG)
        result = run_threat_detection(state)
        for threat in result["threats"]:
            assert "type" in threat
            assert "severity" in threat
            assert "confidence" in threat
            assert 0.0 <= threat["confidence"] <= 1.0

    def test_severity_values_valid(self):
        state = _base_state(parsed_content=BRUTE_FORCE_LOG)
        result = run_threat_detection(state)
        valid = {"Low", "Medium", "High", "Critical"}
        for t in result["threats"]:
            assert t["severity"] in valid


# ── CVE Retrieval ─────────────────────────────────────────────────────────────

class TestCVERetrievalAgent:
    def test_returns_vulnerabilities_list(self):
        state = _base_state(
            parsed_content="Server running Apache 2.4.49",
            software_versions=[{"software": "Apache", "version": "2.4.49"}],
        )
        result = run_cve_retrieval(state)
        assert isinstance(result["vulnerabilities"], list)

    def test_no_software_yields_empty(self):
        state = _base_state(parsed_content="just some random text with no versions")
        result = run_cve_retrieval(state)
        assert result["vulnerabilities"] == []

    def test_cve_fields_present(self):
        state = _base_state(
            software_versions=[{"software": "Log4j", "version": "2.14.0"}],
        )
        result = run_cve_retrieval(state)
        for vuln in result["vulnerabilities"]:
            assert "cve" in vuln
            assert "cvss" in vuln
            assert "severity" in vuln
            assert "description" in vuln


# ── Risk Scoring ──────────────────────────────────────────────────────────────

class TestRiskScoringAgent:
    def test_score_range(self):
        state = _base_state(
            threats=[
                {"type": "BF", "severity": "High", "confidence": 0.8},
                {"type": "Malware", "severity": "Critical", "confidence": 0.9},
            ],
            vulnerabilities=[
                {"cve": "CVE-2021-41773", "cvss": 9.8, "severity": "Critical"},
            ],
        )
        result = run_risk_scoring(state)
        assert 0.0 <= result["risk_score"] <= 100.0

    def test_risk_level_critical_for_high_score(self):
        state = _base_state(
            threats=[{"type": "BF", "severity": "Critical", "confidence": 0.99}],
            vulnerabilities=[{"cve": "CVE-X", "cvss": 10.0, "severity": "Critical"}],
        )
        result = run_risk_scoring(state)
        assert result["risk_level"] == "Critical"

    def test_zero_for_empty_inputs(self):
        state = _base_state()
        result = run_risk_scoring(state)
        assert result["risk_score"] == 0.0
        assert result["risk_level"] == "Low"

    def test_explanation_present(self):
        state = _base_state(
            threats=[{"type": "BF", "severity": "High", "confidence": 0.7}],
        )
        result = run_risk_scoring(state)
        assert len(result.get("risk_explanation", "")) > 10

    def test_components_present(self):
        state = _base_state(
            threats=[{"type": "BF", "severity": "High", "confidence": 0.8}],
        )
        result = run_risk_scoring(state)
        comps = result.get("risk_components", {})
        assert "threat_severity_score" in comps
        assert "cvss_average" in comps
        assert "confidence_average" in comps


# ── Recommendation ────────────────────────────────────────────────────────────

class TestRecommendationAgent:
    def test_returns_recommendations_list(self):
        state = _base_state(
            threats=[{"type": "Brute Force", "severity": "High", "confidence": 0.8}],
            vulnerabilities=[{"cve": "CVE-X", "cvss": 9.0, "severity": "Critical"}],
            risk_level="High",
            risk_score=80.0,
        )
        result = run_recommendation(state)
        assert isinstance(result["recommendations"], list)
        assert len(result["recommendations"]) > 0

    def test_returns_priority_actions(self):
        state = _base_state(
            threats=[{"type": "Brute Force", "severity": "Critical", "confidence": 0.9}],
            vulnerabilities=[{"cve": "CVE-2021-44228", "cvss": 10.0, "severity": "Critical", "software": "Log4j"}],
            risk_level="Critical",
            risk_score=95.0,
        )
        result = run_recommendation(state)
        assert len(result["priority_actions"]) > 0

    def test_brute_force_recommends_mfa(self):
        state = _base_state(
            threats=[{"type": "Brute Force", "severity": "High", "confidence": 0.8}],
            risk_level="High",
            risk_score=75.0,
        )
        result = run_recommendation(state)
        all_recs = " ".join(result["recommendations"] + result["priority_actions"]).lower()
        assert "mfa" in all_recs or "multi-factor" in all_recs or "lockout" in all_recs

    def test_empty_threats_still_has_general_recs(self):
        state = _base_state(risk_level="Low", risk_score=10.0)
        result = run_recommendation(state)
        assert len(result["recommendations"]) > 0
