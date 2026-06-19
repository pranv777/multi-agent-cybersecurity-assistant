"""
NVD Service — queries the NIST National Vulnerability Database API v2.
Falls back to a curated local dataset when the API is unreachable.
"""
import os
import logging
import requests
from typing import List, Optional

logger = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

# ── Curated fallback CVE dataset for common software ──────────────────────────
FALLBACK_CVES: dict = {
    "apache": [
        {
            "cve": "CVE-2021-41773",
            "cvss": 9.8,
            "severity": "Critical",
            "description": "Path traversal and RCE in Apache HTTP Server 2.4.49.",
            "published_date": "2021-10-05",
        },
        {
            "cve": "CVE-2021-42013",
            "cvss": 9.8,
            "severity": "Critical",
            "description": "Path traversal in Apache HTTP Server 2.4.49–2.4.50.",
            "published_date": "2021-10-07",
        },
    ],
    "openssh": [
        {
            "cve": "CVE-2023-38408",
            "cvss": 9.8,
            "severity": "Critical",
            "description": "Remote code execution via ssh-agent in OpenSSH before 9.3p2.",
            "published_date": "2023-07-19",
        },
    ],
    "nginx": [
        {
            "cve": "CVE-2021-23017",
            "cvss": 7.7,
            "severity": "High",
            "description": "One-byte buffer overwrite in nginx resolver.",
            "published_date": "2021-05-25",
        },
    ],
    "openssl": [
        {
            "cve": "CVE-2022-0778",
            "cvss": 7.5,
            "severity": "High",
            "description": "Infinite loop in BN_mod_sqrt() in OpenSSL.",
            "published_date": "2022-03-15",
        },
    ],
    "log4j": [
        {
            "cve": "CVE-2021-44228",
            "cvss": 10.0,
            "severity": "Critical",
            "description": "Log4Shell — JNDI injection RCE in Apache Log4j 2.",
            "published_date": "2021-12-10",
        },
    ],
    "wordpress": [
        {
            "cve": "CVE-2022-21661",
            "cvss": 7.5,
            "severity": "High",
            "description": "SQL injection via WP_Query in WordPress before 5.8.3.",
            "published_date": "2022-01-06",
        },
    ],
    "mysql": [
        {
            "cve": "CVE-2022-21417",
            "cvss": 4.9,
            "severity": "Medium",
            "description": "MySQL Server InnoDB vulnerability allowing DoS.",
            "published_date": "2022-04-19",
        },
    ],
    "python": [
        {
            "cve": "CVE-2023-24329",
            "cvss": 7.5,
            "severity": "High",
            "description": "urllib.parse URL parsing bypass in Python < 3.11.4.",
            "published_date": "2023-02-17",
        },
    ],
}


def _nvd_api_query(keyword: str) -> List[dict]:
    """Query NVD API v2 for CVEs matching a keyword."""
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    params = {"keywordSearch": keyword, "resultsPerPage": 5}
    try:
        resp = requests.get(NVD_API_BASE, headers=headers, params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        results = []
        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id", "UNKNOWN")
            desc = ""
            for d in cve_data.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            metrics = cve_data.get("metrics", {})
            cvss_score = 0.0
            severity = "Unknown"
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    m = metrics[key][0]
                    cvss_score = m.get("cvssData", {}).get("baseScore", 0.0)
                    severity = m.get("cvssData", {}).get("baseSeverity", "Unknown")
                    break
            results.append(
                {
                    "cve": cve_id,
                    "cvss": cvss_score,
                    "severity": severity.capitalize(),
                    "description": desc[:300],
                    "published_date": cve_data.get("published", "")[:10],
                }
            )
        return results
    except Exception as e:
        logger.warning("NVD API query failed for '%s': %s", keyword, e)
        return []


def _fallback_lookup(software_name: str) -> List[dict]:
    """Look up known CVEs from the local fallback dataset."""
    name_lower = software_name.lower()
    for key, cves in FALLBACK_CVES.items():
        if key in name_lower:
            return cves
    return []


def query_cves_for_software(software: str, version: Optional[str] = None) -> List[dict]:
    """
    Public entry point: returns CVEs for a given software (and optional version).
    Tries NVD API first; falls back to local dataset.
    """
    keyword = f"{software} {version}" if version else software
    results = _nvd_api_query(keyword)
    if not results:
        logger.info("Using fallback CVE data for '%s'.", software)
        results = _fallback_lookup(software)
    return results
