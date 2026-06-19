"""
PDF Parser — extracts text from PDF security reports using PyMuPDF.
"""
import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Software version patterns (e.g. "Apache 2.4.49", "OpenSSH 8.2p1")
SOFTWARE_VERSION_PATTERN = re.compile(
    r"\b(Apache|Nginx|OpenSSH|OpenSSL|WordPress|MySQL|PostgreSQL|Redis|"
    r"MongoDB|Tomcat|PHP|Python|Node\.js|Java|Log4j|Jenkins|Kubernetes|"
    r"Docker|Linux|Windows\s+Server|Ubuntu|CentOS|Debian|Spring|Rails)"
    r"[\s/v]*([\d]+\.[\d]+\.?[\d]*[\w\-]*)",
    re.IGNORECASE,
)

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def extract_text_from_pdf(file_path: str) -> str:
    """
    Extract all text from a PDF file using PyMuPDF.
    Returns empty string on failure.
    """
    try:
        import fitz  # PyMuPDF

        doc = fitz.open(file_path)
        texts = []
        for page in doc:
            texts.append(page.get_text("text"))
        doc.close()
        return "\n".join(texts)
    except ImportError:
        logger.error("PyMuPDF (fitz) not installed. Cannot parse PDF.")
        return ""
    except Exception as e:
        logger.error("PDF parsing failed for %s: %s", file_path, e)
        return ""


def extract_software_versions(text: str) -> list:
    """
    Extract software name/version pairs from text.
    Returns list of dicts: [{"software": str, "version": str}]
    """
    matches = SOFTWARE_VERSION_PATTERN.findall(text)
    seen = set()
    results = []
    for name, version in matches:
        key = f"{name.lower()}-{version}"
        if key not in seen:
            seen.add(key)
            results.append({"software": name.strip(), "version": version.strip()})
    return results


def extract_cve_ids(text: str) -> list:
    """Extract all CVE IDs mentioned in text."""
    return list(set(CVE_PATTERN.findall(text.upper())))


def parse_pdf(file_path: str) -> dict:
    """
    Full PDF parse: extract text, software versions, and embedded CVE IDs.
    """
    text = extract_text_from_pdf(file_path)
    if not text:
        return {
            "raw_text": "",
            "software_versions": [],
            "embedded_cves": [],
            "page_count": 0,
        }

    software_versions = extract_software_versions(text)
    embedded_cves = extract_cve_ids(text)

    # Quick summary stats
    try:
        import fitz
        doc = fitz.open(file_path)
        page_count = len(doc)
        doc.close()
    except Exception:
        page_count = 0

    logger.info(
        "PDF parsed: %d pages, %d software entries, %d embedded CVEs",
        page_count,
        len(software_versions),
        len(embedded_cves),
    )
    return {
        "raw_text": text,
        "software_versions": software_versions,
        "embedded_cves": embedded_cves,
        "page_count": page_count,
    }
