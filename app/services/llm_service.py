"""
LLM Service — wraps Ollama for all agent inference calls.
"""
import os
import json
import logging
import requests
from typing import Optional

logger = logging.getLogger(__name__)

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")


def _post_ollama(payload: dict, timeout: int = 120) -> Optional[str]:
    """
    Raw POST to Ollama /api/generate.
    Returns the response text or None on failure.
    """
    try:
        response = requests.post(
            f"{OLLAMA_BASE_URL}/api/generate",
            json=payload,
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json()
        return data.get("response", "").strip()
    except requests.exceptions.ConnectionError:
        logger.error(
            "Cannot connect to Ollama at %s. Ensure Ollama is running.", OLLAMA_BASE_URL
        )
        return None
    except requests.exceptions.Timeout:
        logger.error("Ollama request timed out after %ds.", timeout)
        return None
    except Exception as e:
        logger.error("Ollama error: %s", e)
        return None


def generate_response(prompt: str, system: str = "") -> str:
    """
    General-purpose text generation via Ollama.
    """
    full_prompt = f"{system}\n\n{prompt}" if system else prompt
    result = _post_ollama(
        {
            "model": OLLAMA_MODEL,
            "prompt": full_prompt,
            "stream": False,
            "options": {"temperature": 0.2, "num_predict": 1024},
        }
    )
    if result is None:
        return "[LLM unavailable — Ollama not reachable]"
    return result


def analyze_security_logs(logs: str) -> dict:
    """
    Ask the LLM to interpret raw security logs and surface threats.
    Returns a dict with keys: threats (list), summary (str).
    """
    system = (
        "You are an expert cybersecurity analyst. "
        "Analyze the provided logs and identify security threats. "
        "Respond ONLY with a valid JSON object — no markdown, no preamble. "
        "Schema: {\"threats\": [{\"type\": str, \"severity\": str, "
        "\"confidence\": float, \"evidence\": [str]}], \"summary\": str}"
    )
    prompt = f"Analyze these security logs:\n\n{logs[:4000]}"

    raw = _post_ollama(
        {
            "model": OLLAMA_MODEL,
            "prompt": f"{system}\n\n{prompt}",
            "stream": False,
            "options": {"temperature": 0.1, "num_predict": 1500},
        }
    )
    if not raw:
        return {"threats": [], "summary": "LLM unavailable"}

    try:
        # Strip markdown fences if present
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            cleaned = "\n".join(cleaned.split("\n")[1:])
            cleaned = cleaned.rsplit("```", 1)[0].strip()
        return json.loads(cleaned)
    except json.JSONDecodeError:
        logger.warning("LLM returned non-JSON for log analysis; using empty result.")
        return {"threats": [], "summary": raw[:500]}


def generate_recommendations(context: dict) -> dict:
    """
    Generate context-aware security recommendations via Ollama.
    Returns a dict with keys: recommendations (list[str]), priority_actions (list[str]).
    """
    system = (
        "You are a senior cybersecurity consultant. "
        "Given threat findings, CVE data, and a risk score, "
        "produce a concrete remediation plan. "
        "Respond ONLY with a valid JSON object — no markdown, no preamble. "
        "Schema: {\"recommendations\": [str], \"priority_actions\": [str]}"
    )

    threats_summary = json.dumps(context.get("threats", [])[:5], indent=2)
    cves_summary = json.dumps(context.get("vulnerabilities", [])[:5], indent=2)
    risk = context.get("risk_score", "unknown")
    risk_level = context.get("risk_level", "unknown")

    prompt = (
        f"Risk Level: {risk_level} (score: {risk})\n\n"
        f"Detected Threats:\n{threats_summary}\n\n"
        f"Known CVEs:\n{cves_summary}\n\n"
        "Generate prioritised recommendations."
    )

    raw = _post_ollama(
        {
            "model": OLLAMA_MODEL,
            "prompt": f"{system}\n\n{prompt}",
            "stream": False,
            "options": {"temperature": 0.3, "num_predict": 1500},
        }
    )
    if not raw:
        return {
            "recommendations": ["Enable MFA", "Apply latest security patches"],
            "priority_actions": ["Patch critical CVEs immediately"],
        }

    try:
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            cleaned = "\n".join(cleaned.split("\n")[1:])
            cleaned = cleaned.rsplit("```", 1)[0].strip()
        return json.loads(cleaned)
    except json.JSONDecodeError:
        logger.warning("LLM returned non-JSON for recommendations.")
        return {
            "recommendations": [raw[:300]],
            "priority_actions": [],
        }


def check_ollama_health() -> bool:
    """Returns True if Ollama is reachable."""
    try:
        r = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=5)
        return r.status_code == 200
    except Exception:
        return False
