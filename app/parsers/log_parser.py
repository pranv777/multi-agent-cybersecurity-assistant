"""
Log Parser — extracts structured events from .log and .txt files.
"""
import re
import logging
from typing import List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# ── Regex patterns ─────────────────────────────────────────────────────────────
IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
FAILED_LOGIN = re.compile(
    r"(?i)(failed|invalid|failure|rejected).{0,40}(login|password|auth|ssh|user)",
    re.IGNORECASE,
)
PORT_SCAN = re.compile(
    r"(?i)(port.?scan|nmap|masscan|syn.flood|connection.refused)",
    re.IGNORECASE,
)
MALWARE_INDICATORS = re.compile(
    r"(?i)(malware|ransomware|trojan|virus|exploit|payload|backdoor|c2|command.and.control|meterpreter)",
    re.IGNORECASE,
)
BRUTE_FORCE = re.compile(
    r"(?i)(brute.?force|dictionary.attack|credential.stuffing|rate.limit)",
    re.IGNORECASE,
)
SUSPICIOUS_USER_AGENTS = re.compile(
    r"(?i)(sqlmap|nikto|metasploit|hydra|medusa|burpsuite|dirb|gobuster|nessus)",
    re.IGNORECASE,
)
ERROR_PATTERN = re.compile(r"(?i)(error|critical|alert|warning|denied|forbidden|unauthorized)")
TIMESTAMP_PATTERN = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
    r"|\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}"
    r"|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
)


@dataclass
class LogEvent:
    raw_line: str
    ips: List[str] = field(default_factory=list)
    timestamp: Optional[str] = None
    is_failed_login: bool = False
    is_port_scan: bool = False
    is_malware: bool = False
    is_brute_force: bool = False
    is_suspicious_tool: bool = False
    is_error: bool = False
    line_number: int = 0


def parse_log_file(content: str) -> dict:
    """
    Parse raw log content into structured events.
    Returns summary dict with event lists and IP counts.
    """
    lines = content.splitlines()
    events: List[LogEvent] = []
    ip_counter: dict = {}

    for i, line in enumerate(lines, 1):
        if not line.strip():
            continue
        event = LogEvent(raw_line=line, line_number=i)

        # IPs
        event.ips = IP_PATTERN.findall(line)
        for ip in event.ips:
            ip_counter[ip] = ip_counter.get(ip, 0) + 1

        # Timestamp
        ts_match = TIMESTAMP_PATTERN.search(line)
        if ts_match:
            event.timestamp = ts_match.group()

        # Category flags
        event.is_failed_login = bool(FAILED_LOGIN.search(line))
        event.is_port_scan = bool(PORT_SCAN.search(line))
        event.is_malware = bool(MALWARE_INDICATORS.search(line))
        event.is_brute_force = bool(BRUTE_FORCE.search(line))
        event.is_suspicious_tool = bool(SUSPICIOUS_USER_AGENTS.search(line))
        event.is_error = bool(ERROR_PATTERN.search(line))

        events.append(event)

    # Summarise
    failed_logins = [e for e in events if e.is_failed_login]
    port_scans = [e for e in events if e.is_port_scan]
    malware_events = [e for e in events if e.is_malware]
    brute_force_events = [e for e in events if e.is_brute_force]
    suspicious_tools = [e for e in events if e.is_suspicious_tool]

    # Top IPs (by frequency)
    top_ips = sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "total_lines": len(lines),
        "total_events": len(events),
        "failed_logins": [{"line": e.line_number, "raw": e.raw_line[:200], "ips": e.ips} for e in failed_logins[:20]],
        "port_scans": [{"line": e.line_number, "raw": e.raw_line[:200]} for e in port_scans[:20]],
        "malware_events": [{"line": e.line_number, "raw": e.raw_line[:200]} for e in malware_events[:20]],
        "brute_force_events": [{"line": e.line_number, "raw": e.raw_line[:200]} for e in brute_force_events[:20]],
        "suspicious_tools": [{"line": e.line_number, "raw": e.raw_line[:200]} for e in suspicious_tools[:20]],
        "top_ips": [{"ip": ip, "occurrences": count} for ip, count in top_ips],
        "ip_counter": ip_counter,
        "error_count": sum(1 for e in events if e.is_error),
    }


def extract_ips(content: str) -> List[str]:
    """Return unique IPs found in content."""
    return list(set(IP_PATTERN.findall(content)))


def extract_login_attempts(content: str) -> List[str]:
    """Return lines containing login attempts."""
    return [
        line for line in content.splitlines()
        if FAILED_LOGIN.search(line) and line.strip()
    ]
