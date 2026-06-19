"""
CVE Retrieval Agent
────────────────────
1. Extracts software names + versions from parsed content.
2. Queries NVD API (with local fallback).
3. Deduplicates and enriches results.
"""
import re
import logging
from typing import List, Dict

from app.services.nvd_service import query_cves_for_software

logger = logging.getLogger(__name__)

SOFTWARE_VERSION_RE = re.compile(
    r"\b(Apache|Nginx|OpenSSH|OpenSSL|WordPress|MySQL|PostgreSQL|Redis|"
    r"MongoDB|Tomcat|PHP|Python|Node\.js|Java|Log4j|Jenkins|Kubernetes|"
    r"Docker|Linux|Windows\s+Server|Ubuntu|CentOS|Debian|Spring|Rails)"
    r"[\s/v]*([\d]+\.[\d]+\.?[\d]*[\w\-]*)?",
    re.IGNORECASE,
)

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}


def _extract_software(content: str, pre_extracted: List[dict]) -> List[dict]:
    """Merge pre-extracted software with any additional hits from raw content."""
    seen: set = set()
    results: List[dict] = []

    for item in pre_extracted:
        key = item["software"].lower()
        if key not in seen:
            seen.add(key)
            results.append(item)

    for name, version in SOFTWARE_VERSION_RE.findall(content):
        key = name.lower()
        if key not in seen:
            seen.add(key)
            results.append({"software": name.strip(), "version": version.strip() or None})

    return results


def _severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "Unknown"


def run_cve_retrieval(state: dict) -> dict:
    """
    LangGraph node: cve_retrieval_agent.
    Reads state["parsed_content"] + state.get("software_versions", []).
    Updates state["vulnerabilities"].
    """
    logger.info("[CVERetrieval] Starting CVE lookup…")
    content = state.get("parsed_content", "")
    pre_extracted: List[dict] = state.get("software_versions", [])

    software_list = _extract_software(content, pre_extracted)

    if not software_list:
        logger.info("[CVERetrieval] No software versions detected — skipping NVD query.")
        state["vulnerabilities"] = []
        state["processing_steps"].append("cve_retrieval: no software detected")
        return state

    logger.info("[CVERetrieval] Querying CVEs for %d software entries…", len(software_list))
    vulnerabilities: List[dict] = []
    seen_cves: set = set()

    for sw in software_list[:10]:  # cap to avoid rate-limit hammering
        name = sw["software"]
        version = sw.get("version")
        cves = query_cves_for_software(name, version)

        for cve in cves:
            cve_id = cve.get("cve", "")
            if cve_id in seen_cves:
                continue
            seen_cves.add(cve_id)

            cvss = float(cve.get("cvss", 0.0))
            severity = cve.get("severity") or _severity_from_cvss(cvss)

            vulnerabilities.append(
                {
                    "software": f"{name} {version}".strip() if version else name,
                    "version": version,
                    "cve": cve_id,
                    "cvss": cvss,
                    "severity": severity,
                    "description": cve.get("description", "")[:300],
                    "published_date": cve.get("published_date", ""),
                    "references": cve.get("references", []),
                }
            )

    # Sort by CVSS descending
    vulnerabilities.sort(key=lambda x: x["cvss"], reverse=True)

    logger.info("[CVERetrieval] Retrieved %d CVE(s).", len(vulnerabilities))
    state["vulnerabilities"] = vulnerabilities
    state["processing_steps"].append(
        f"cve_retrieval: {len(vulnerabilities)} CVEs for {len(software_list)} software entries"
    )
    return state
