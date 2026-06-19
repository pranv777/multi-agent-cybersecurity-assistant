"""
Report Parser — normalises content from all supported file types
into a unified string for downstream agents.
"""
import os
import re
import logging
import pandas as pd
from typing import Tuple

from app.parsers.log_parser import parse_log_file
from app.parsers.pdf_parser import parse_pdf, extract_software_versions

logger = logging.getLogger(__name__)

SUPPORTED_EXTENSIONS = {".log", ".txt", ".csv", ".pdf"}

SOFTWARE_VERSION_PATTERN = re.compile(
    r"\b(Apache|Nginx|OpenSSH|OpenSSL|WordPress|MySQL|PostgreSQL|Redis|"
    r"MongoDB|Tomcat|PHP|Python|Node\.js|Java|Log4j|Jenkins|Kubernetes|"
    r"Docker|Linux|Windows\s+Server|Ubuntu|CentOS|Debian|Spring|Rails)"
    r"[\s/v]*([\d]+\.[\d]+\.?[\d]*[\w\-]*)",
    re.IGNORECASE,
)


def parse_file(file_path: str) -> Tuple[str, dict]:
    """
    Parse a file and return:
      - normalised text content (str)
      - metadata dict (file type, software versions, log stats, etc.)
    """
    ext = os.path.splitext(file_path)[1].lower()
    filename = os.path.basename(file_path)

    if ext not in SUPPORTED_EXTENSIONS:
        logger.warning("Unsupported file extension: %s", ext)
        return "", {"error": f"Unsupported extension {ext}", "filename": filename}

    if ext == ".pdf":
        result = parse_pdf(file_path)
        return result["raw_text"], {
            "filename": filename,
            "file_type": "pdf",
            "page_count": result["page_count"],
            "software_versions": result["software_versions"],
            "embedded_cves": result["embedded_cves"],
        }

    # Plain text / log / csv
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            raw_content = f.read()
    except Exception as e:
        logger.error("Cannot read file %s: %s", file_path, e)
        return "", {"error": str(e), "filename": filename}

    if ext == ".csv":
        try:
            df = pd.read_csv(file_path, dtype=str, nrows=5000)
            raw_content = df.to_string(index=False)
        except Exception as e:
            logger.warning("CSV parse with pandas failed, using raw text: %s", e)

    log_stats = parse_log_file(raw_content)
    software_versions = extract_software_versions(raw_content)

    return raw_content, {
        "filename": filename,
        "file_type": ext.lstrip("."),
        "software_versions": software_versions,
        "log_stats": log_stats,
    }


def merge_parsed_content(file_results: list) -> Tuple[str, list]:
    """
    Merge content from multiple parsed files.
    Returns merged text and combined software version list.
    """
    all_text_parts = []
    all_software: list = []
    seen_sw = set()

    for content, meta in file_results:
        filename = meta.get("filename", "unknown")
        if content:
            all_text_parts.append(f"=== FILE: {filename} ===\n{content[:8000]}\n")
        for sw in meta.get("software_versions", []):
            key = f"{sw['software'].lower()}-{sw.get('version', '')}"
            if key not in seen_sw:
                seen_sw.add(key)
                all_software.append(sw)

    return "\n".join(all_text_parts), all_software
