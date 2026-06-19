"""
Integration tests — LangGraph workflow
"""
import os
import uuid
import tempfile
import pytest

from app.graph.workflow import run_analysis, build_workflow


SAMPLE_LOG_CONTENT = """
2024-01-15 08:23:01 sshd: Failed password for root from 192.168.1.100 port 22
2024-01-15 08:23:02 sshd: Failed password for root from 192.168.1.100 port 22
2024-01-15 08:23:03 sshd: Failed password for admin from 192.168.1.100 port 22
2024-01-15 08:23:04 sshd: Failed password for test from 192.168.1.100 port 22
2024-01-15 08:23:05 sshd: Failed password for user from 192.168.1.100 port 22
2024-01-15 08:23:06 kernel: nmap scan detected from 10.10.10.100
2024-01-15 08:23:07 app: brute force detected from 192.168.1.100
2024-01-15 08:23:08 ids: port scan activity from 10.10.10.100
Server running Apache 2.4.49 on port 80
OpenSSH 8.2 service active
"""


@pytest.fixture
def sample_log_file():
    """Create a temporary .log file and return its path."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".log", delete=False, encoding="utf-8"
    ) as f:
        f.write(SAMPLE_LOG_CONTENT)
        path = f.name
    yield path
    if os.path.exists(path):
        os.remove(path)


class TestWorkflow:
    def test_build_workflow_returns_compiled_graph(self):
        wf = build_workflow()
        assert wf is not None

    def test_run_analysis_returns_dict(self, sample_log_file):
        job_id = str(uuid.uuid4())
        report = run_analysis(job_id, [sample_log_file])
        assert isinstance(report, dict)

    def test_report_has_required_keys(self, sample_log_file):
        job_id = str(uuid.uuid4())
        report = run_analysis(job_id, [sample_log_file])
        required = [
            "job_id", "summary", "threats", "vulnerabilities",
            "risk_score", "risk_level", "recommendations",
            "generated_at",
        ]
        for key in required:
            assert key in report, f"Missing key: {key}"

    def test_report_job_id_matches(self, sample_log_file):
        job_id = str(uuid.uuid4())
        report = run_analysis(job_id, [sample_log_file])
        assert report["job_id"] == job_id

    def test_threats_detected_in_brute_force_log(self, sample_log_file):
        job_id = str(uuid.uuid4())
        report = run_analysis(job_id, [sample_log_file])
        assert isinstance(report["threats"], list)
        assert len(report["threats"]) > 0

    def test_risk_score_is_numeric(self, sample_log_file):
        job_id = str(uuid.uuid4())
        report = run_analysis(job_id, [sample_log_file])
        assert isinstance(report["risk_score"], (int, float))
        assert 0.0 <= report["risk_score"] <= 100.0

    def test_risk_level_is_valid_string(self, sample_log_file):
        job_id = str(uuid.uuid4())
        report = run_analysis(job_id, [sample_log_file])
        valid = {"Low", "Medium", "High", "Critical"}
        assert report["risk_level"] in valid

    def test_recommendations_not_empty(self, sample_log_file):
        job_id = str(uuid.uuid4())
        report = run_analysis(job_id, [sample_log_file])
        assert isinstance(report["recommendations"], list)
        assert len(report["recommendations"]) > 0

    def test_empty_file_list_graceful(self):
        job_id = str(uuid.uuid4())
        report = run_analysis(job_id, [])
        assert isinstance(report, dict)
        assert "risk_score" in report

    def test_report_saved_to_disk(self, sample_log_file, tmp_path, monkeypatch):
        monkeypatch.setenv("REPORTS_DIR", str(tmp_path))
        import app.graph.workflow as wf_mod
        wf_mod.REPORTS_DIR = str(tmp_path)
        job_id = str(uuid.uuid4())
        run_analysis(job_id, [sample_log_file])
        json_file = tmp_path / f"{job_id}.json"
        assert json_file.exists()
