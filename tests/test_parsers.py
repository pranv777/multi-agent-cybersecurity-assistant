"""
Unit tests — parsers
"""
import pytest
from app.parsers.log_parser import parse_log_file, extract_ips, extract_login_attempts
from app.parsers.pdf_parser import extract_software_versions, extract_cve_ids


SAMPLE_LOG = """
2024-01-15 08:23:01 sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
2024-01-15 08:23:02 sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
2024-01-15 08:23:03 sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2
2024-01-15 08:23:04 sshd[1234]: Failed password for admin from 10.0.0.5 port 22 ssh2
2024-01-15 08:23:05 sshd[1234]: Failed password for test from 192.168.1.100 port 22 ssh2
2024-01-15 08:23:06 kernel: nmap scan detected from 192.168.1.200
2024-01-15 08:23:07 apache: malware payload detected in request
2024-01-15 08:23:08 apache: brute force attack from 10.10.10.5
2024-01-15 08:23:09 sshd[1234]: sqlmap user agent detected
"""

SAMPLE_VERSION_TEXT = """
Server is running Apache 2.4.49 on port 80.
OpenSSH 8.2p1 is the SSH daemon.
Nginx 1.18.0 serves static content.
OpenSSL 1.1.1 is used for TLS.
"""


# ── log_parser tests ───────────────────────────────────────────────────────────

class TestLogParser:
    def test_parse_returns_dict(self):
        result = parse_log_file(SAMPLE_LOG)
        assert isinstance(result, dict)

    def test_total_lines(self):
        result = parse_log_file(SAMPLE_LOG)
        assert result["total_lines"] > 0

    def test_detects_failed_logins(self):
        result = parse_log_file(SAMPLE_LOG)
        assert len(result["failed_logins"]) >= 5

    def test_detects_port_scans(self):
        result = parse_log_file(SAMPLE_LOG)
        assert len(result["port_scans"]) >= 1

    def test_detects_malware_events(self):
        result = parse_log_file(SAMPLE_LOG)
        assert len(result["malware_events"]) >= 1

    def test_detects_brute_force(self):
        result = parse_log_file(SAMPLE_LOG)
        assert len(result["brute_force_events"]) >= 1

    def test_detects_suspicious_tools(self):
        result = parse_log_file(SAMPLE_LOG)
        assert len(result["suspicious_tools"]) >= 1

    def test_top_ips(self):
        result = parse_log_file(SAMPLE_LOG)
        assert len(result["top_ips"]) > 0
        # 192.168.1.100 should be the most frequent
        top_ip = result["top_ips"][0]["ip"]
        assert top_ip == "192.168.1.100"

    def test_extract_ips(self):
        ips = extract_ips(SAMPLE_LOG)
        assert "192.168.1.100" in ips
        assert "10.0.0.5" in ips

    def test_extract_login_attempts(self):
        attempts = extract_login_attempts(SAMPLE_LOG)
        assert len(attempts) >= 5

    def test_empty_log(self):
        result = parse_log_file("")
        assert result["total_lines"] == 0
        assert result["failed_logins"] == []


# ── pdf_parser tests ──────────────────────────────────────────────────────────

class TestPdfParser:
    def test_extract_software_versions(self):
        versions = extract_software_versions(SAMPLE_VERSION_TEXT)
        names = [v["software"].lower() for v in versions]
        assert any("apache" in n for n in names)
        assert any("openssh" in n or "ssh" in n.lower() for n in names)

    def test_extract_cve_ids(self):
        text = "System vulnerable to CVE-2021-41773 and CVE-2022-0778."
        cves = extract_cve_ids(text)
        assert "CVE-2021-41773" in cves
        assert "CVE-2022-0778" in cves

    def test_extract_cve_ids_empty(self):
        cves = extract_cve_ids("No CVEs here.")
        assert cves == []

    def test_software_versions_dedup(self):
        text = "Apache 2.4.49 Apache 2.4.49 Nginx 1.18.0"
        versions = extract_software_versions(text)
        names = [v["software"].lower() for v in versions]
        assert names.count("apache") <= 1
