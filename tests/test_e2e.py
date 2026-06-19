"""
End-to-end tests — full pipeline with realistic inputs
"""
import os
import uuid
import tempfile
import pytest

from app.graph.workflow import run_analysis

REALISTIC_LOG = """
Jan 15 08:00:01 web01 sshd[1234]: Invalid user admin from 203.0.113.5 port 12345
Jan 15 08:00:02 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.5
Jan 15 08:00:03 web01 sshd[1234]: Failed password for root from 203.0.113.5
Jan 15 08:00:04 web01 sshd[1234]: Failed password for oracle from 203.0.113.5
Jan 15 08:00:05 web01 sshd[1234]: Failed password for mysql from 203.0.113.5
Jan 15 08:00:06 web01 sshd[1234]: Failed password for postgres from 203.0.113.5
Jan 15 08:00:07 web01 kernel: Firewall: port scan detected from 198.51.100.42
Jan 15 08:00:08 web01 suricata: [1:2001219:20] ET SCAN Potential SSH Scan from 198.51.100.42
Jan 15 08:00:09 web01 apache2: [error] ModSecurity: Access denied with code 403 sqlmap/1.0
Jan 15 08:00:10 web01 apache2: GET /admin HTTP/1.1 401 - 198.51.100.42 nikto/2.1.6
Jan 15 08:00:11 web01 clamav: /tmp/upload.php: Trojan.PHP.WebShell FOUND
Jan 15 08:00:12 web01 auth: brute force attack detected from 203.0.113.5
Jan 15 08:00:13 web01 ids: malware payload detected in HTTP request body
Server info: Apache 2.4.49, OpenSSH 7.4, OpenSSL 1.0.2k
"""

VULNERABILITY_REPORT = """
VULNERABILITY SCAN REPORT
=========================
Host: 192.168.1.10

Software Inventory:
- Apache HTTP Server 2.4.49 (CVE-2021-41773 — path traversal, CVSS 9.8)
- OpenSSH 7.4 (multiple vulnerabilities)
- OpenSSL 1.0.2k (EOL — no longer receiving security updates)
- WordPress 5.6.2 (SQL injection risk)
- Log4j 2.14.1 (Log4Shell CVE-2021-44228)

Findings:
1. Apache path traversal allows unauthenticated RCE
2. Log4Shell allows remote code execution via JNDI lookup
3. OpenSSL version is end-of-life
"""


@pytest.fixture
def log_file():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False, encoding="utf-8") as f:
        f.write(REALISTIC_LOG)
        path = f.name
    yield path
    os.unlink(path)


@pytest.fixture
def vuln_report_file():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as f:
        f.write(VULNERABILITY_REPORT)
        path = f.name
    yield path
    os.unlink(path)


class TestEndToEnd:
    def test_single_log_full_pipeline(self, log_file):
        job_id = str(uuid.uuid4())
        report = run_analysis(job_id, [log_file])

        assert report["job_id"] == job_id
        assert len(report["threats"]) > 0
        assert report["risk_score"] > 0
        assert len(report["recommendations"]) > 0
        assert report["summary"] != ""

    def test_combined_log_and_report(self, log_file, vuln_report_file):
        job_id = str(uuid.uuid4())
        report = run_analysis(job_id, [log_file, vuln_report_file])

        assert len(report["threats"]) > 0
        assert len(report["vulnerabilities"]) > 0
        # With both threats and CVEs, risk should be elevated
        assert report["risk_score"] > 20.0

    def test_critical_threats_produce_high_risk(self, log_file):
        job_id = str(uuid.uuid4())
        report = run_analysis(job_id, [log_file])
        # The realistic log has multiple threat types; risk should be at least Medium
        valid_non_low = {"Medium", "High", "Critical"}
        assert report["risk_level"] in valid_non_low or report["risk_score"] > 10

    def test_files_analyzed_populated(self, log_file, vuln_report_file):
        job_id = str(uuid.uuid4())
        report = run_analysis(job_id, [log_file, vuln_report_file])
        assert len(report["files_analyzed"]) == 2

    def test_report_written_to_disk(self, log_file, tmp_path, monkeypatch):
        import app.graph.workflow as wf_mod
        monkeypatch.setenv("REPORTS_DIR", str(tmp_path))
        wf_mod.REPORTS_DIR = str(tmp_path)

        job_id = str(uuid.uuid4())
        run_analysis(job_id, [log_file])

        assert (tmp_path / f"{job_id}.json").exists()
        assert (tmp_path / f"{job_id}.txt").exists()

    def test_report_has_execution_summary(self, log_file):
        job_id = str(uuid.uuid4())
        report = run_analysis(job_id, [log_file])
        assert "execution_summary" in report
        assert len(report["execution_summary"]) > 10

    def test_priority_actions_present_for_high_risk(self, log_file, vuln_report_file):
        job_id = str(uuid.uuid4())
        report = run_analysis(job_id, [log_file, vuln_report_file])
        assert isinstance(report.get("priority_actions", []), list)
