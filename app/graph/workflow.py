"""
LangGraph Workflow
───────────────────
Defines the StateGraph that orchestrates all agents:

  parse_input → coordinator_agent → threat_detection_agent
      → cve_retrieval_agent → risk_scoring_agent
      → recommendation_agent → report_generator → END
"""
import os
import json
import logging
import uuid
from datetime import datetime
from typing import TypedDict, List, Optional, Any

from langgraph.graph import StateGraph, END

from app.agents.coordinator_agent import run_coordinator, build_execution_summary
from app.agents.threat_detection import run_threat_detection
from app.agents.cve_retrieval import run_cve_retrieval
from app.agents.risk_scoring import run_risk_scoring
from app.agents.recommendation import run_recommendation
from app.parsers.report_parser import parse_file, merge_parsed_content
from app.services.llm_service import generate_response

logger = logging.getLogger(__name__)

REPORTS_DIR = os.getenv("REPORTS_DIR", "./reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


# ── LangGraph state schema ─────────────────────────────────────────────────────

class CybersecState(TypedDict):
    job_id: str
    files: List[str]
    parsed_content: str
    raw_logs: str
    software_versions: List[dict]
    threats: List[dict]
    vulnerabilities: List[dict]
    risk_score: Optional[float]
    risk_level: str
    risk_explanation: str
    risk_components: dict
    recommendations: List[str]
    priority_actions: List[str]
    final_report: dict
    errors: List[str]
    processing_steps: List[str]


# ── Node implementations ───────────────────────────────────────────────────────

def parse_input_node(state: CybersecState) -> CybersecState:
    """Read and normalise all uploaded files into parsed_content."""
    logger.info("[ParseInput] Parsing %d file(s)…", len(state.get("files", [])))
    file_paths: List[str] = state.get("files", [])

    if not file_paths:
        state["parsed_content"] = ""
        state["software_versions"] = []
        state["processing_steps"].append("parse_input: no files")
        return state

    results = []
    for path in file_paths:
        content, meta = parse_file(path)
        results.append((content, meta))

    merged_content, all_software = merge_parsed_content(results)
    state["parsed_content"] = merged_content
    state["raw_logs"] = merged_content
    state["software_versions"] = all_software

    logger.info(
        "[ParseInput] Merged %d chars, %d software versions detected.",
        len(merged_content),
        len(all_software),
    )
    state["processing_steps"].append(
        f"parse_input: {len(file_paths)} file(s) parsed, "
        f"{len(merged_content)} chars, {len(all_software)} software entries"
    )
    return state


def report_generator_node(state: CybersecState) -> CybersecState:
    """Assemble the final JSON + text security report."""
    logger.info("[ReportGenerator] Assembling final report…")

    threats = state.get("threats", [])
    vulnerabilities = state.get("vulnerabilities", [])
    risk_score = state.get("risk_score", 0.0)
    risk_level = state.get("risk_level", "Low")
    recommendations = state.get("recommendations", [])
    priority_actions = state.get("priority_actions", [])
    files = state.get("files", [])

    # Generate LLM executive summary
    summary_prompt = (
        f"Write a 3-sentence executive summary for a cybersecurity assessment report.\n"
        f"Risk level: {risk_level} (score: {risk_score}/100).\n"
        f"Threats detected: {len(threats)}. CVEs found: {len(vulnerabilities)}.\n"
        f"Top threat types: {', '.join(set(t.get('type','') for t in threats[:3])) or 'None'}.\n"
        f"Be concise and professional. No markdown."
    )
    summary = generate_response(summary_prompt)
    if not summary or summary.startswith("[LLM"):
        severity_counts = {}
        for t in threats:
            s = t.get("severity", "Unknown")
            severity_counts[s] = severity_counts.get(s, 0) + 1
        summary = (
            f"Analysis identified {len(threats)} threat(s) and {len(vulnerabilities)} CVE(s). "
            f"Overall risk level: {risk_level} (score {risk_score}/100). "
            f"Immediate remediation is {'required' if risk_level in ('Critical','High') else 'recommended'}."
        )

    now = datetime.utcnow().isoformat() + "Z"
    report = {
        "job_id": state.get("job_id", str(uuid.uuid4())),
        "summary": summary,
        "threats": threats,
        "vulnerabilities": vulnerabilities,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_explanation": state.get("risk_explanation", ""),
        "risk_components": state.get("risk_components", {}),
        "recommendations": recommendations,
        "priority_actions": priority_actions,
        "files_analyzed": [os.path.basename(f) for f in files],
        "generated_at": now,
        "execution_summary": build_execution_summary(state),
        "errors": state.get("errors", []),
    }

    state["final_report"] = report

    # Persist to disk
    job_id = state.get("job_id", "unknown")
    json_path = os.path.join(REPORTS_DIR, f"{job_id}.json")
    txt_path = os.path.join(REPORTS_DIR, f"{job_id}.txt")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

    # Plain text version
    txt_lines = [
        "=" * 70,
        "     MULTI-AGENT CYBERSECURITY ASSESSMENT REPORT",
        "=" * 70,
        f"Job ID      : {report['job_id']}",
        f"Generated   : {report['generated_at']}",
        f"Risk Level  : {risk_level}  (score: {risk_score}/100)",
        "",
        "EXECUTIVE SUMMARY",
        "-" * 70,
        summary,
        "",
        "DETECTED THREATS",
        "-" * 70,
    ]
    if threats:
        for t in threats:
            txt_lines.append(
                f"  [{t.get('severity','?').upper()}] {t.get('type','')}  "
                f"(confidence: {t.get('confidence', 0):.0%})"
            )
            for ev in t.get("evidence", []):
                txt_lines.append(f"       ↳ {ev}")
    else:
        txt_lines.append("  No threats detected.")

    txt_lines += ["", "CVE / VULNERABILITY FINDINGS", "-" * 70]
    if vulnerabilities:
        for v in vulnerabilities:
            txt_lines.append(
                f"  {v.get('cve','')}  CVSS {v.get('cvss',0)}  "
                f"[{v.get('severity','')}]  — {v.get('software','')}"
            )
            txt_lines.append(f"       {v.get('description','')[:120]}")
    else:
        txt_lines.append("  No CVEs retrieved.")

    txt_lines += ["", "RECOMMENDATIONS", "-" * 70]
    if priority_actions:
        txt_lines.append("  Priority Actions:")
        for p in priority_actions:
            txt_lines.append(f"    ★ {p}")
        txt_lines.append("")
    for rec in recommendations:
        txt_lines.append(f"  • {rec}")

    txt_lines += ["", "=" * 70, "  END OF REPORT", "=" * 70]

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("\n".join(txt_lines))

    logger.info("[ReportGenerator] Report saved → %s", json_path)
    state["processing_steps"].append("report_generator: report saved to disk")
    return state


# ── Build the LangGraph ────────────────────────────────────────────────────────

def build_workflow() -> Any:
    """Construct and compile the LangGraph StateGraph."""
    graph = StateGraph(CybersecState)

    # Register nodes
    graph.add_node("parse_input", parse_input_node)
    graph.add_node("coordinator_agent", run_coordinator)
    graph.add_node("threat_detection_agent", run_threat_detection)
    graph.add_node("cve_retrieval_agent", run_cve_retrieval)
    graph.add_node("risk_scoring_agent", run_risk_scoring)
    graph.add_node("recommendation_agent", run_recommendation)
    graph.add_node("report_generator", report_generator_node)

    # Define edges
    graph.set_entry_point("parse_input")
    graph.add_edge("parse_input", "coordinator_agent")
    graph.add_edge("coordinator_agent", "threat_detection_agent")
    graph.add_edge("threat_detection_agent", "cve_retrieval_agent")
    graph.add_edge("cve_retrieval_agent", "risk_scoring_agent")
    graph.add_edge("risk_scoring_agent", "recommendation_agent")
    graph.add_edge("recommendation_agent", "report_generator")
    graph.add_edge("report_generator", END)

    return graph.compile()


# Singleton compiled workflow
_workflow = None


def get_workflow():
    global _workflow
    if _workflow is None:
        _workflow = build_workflow()
    return _workflow


def run_analysis(job_id: str, file_paths: List[str]) -> dict:
    """
    Public entry point: run the full LangGraph pipeline.
    Returns the final_report dict.
    """
    initial_state: CybersecState = {
        "job_id": job_id,
        "files": file_paths,
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

    workflow = get_workflow()
    logger.info("[Workflow] Starting pipeline for job %s with %d file(s).", job_id, len(file_paths))
    final_state = workflow.invoke(initial_state)
    logger.info("[Workflow] Pipeline complete for job %s.", job_id)
    return final_state.get("final_report", {})
