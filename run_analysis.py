#!/usr/bin/env python
"""
Pure Agentic AI Entry Point
────────────────────────────
No backend. No API. Just the multi-agent system with LangGraph.

Run like:
  python run_analysis.py sample.log
  python run_analysis.py access.log network.txt vuln_report.pdf
"""

import sys
import json
import time
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

from app.graph.workflow import run_analysis

def print_header(text):
    """Print a formatted header."""
    print("\n" + "=" * 80)
    print(f"  {text}")
    print("=" * 80)

def print_section(title):
    """Print a section title."""
    print(f"\n{title}")
    print("-" * 80)

def print_threat(threat):
    """Pretty-print a threat finding."""
    severity_colors = {
        "Critical": "🔴",
        "High": "🟠",
        "Medium": "🟡",
        "Low": "🟢",
    }
    color = severity_colors.get(threat["severity"], "⚪")
    print(f"{color} [{threat['severity'].upper()}] {threat['type']} (confidence: {threat['confidence']:.0%})")
    for evidence in threat.get("evidence", []):
        print(f"   ↳ {evidence}")

def print_vulnerability(vuln):
    """Pretty-print a CVE finding."""
    severity_colors = {
        "Critical": "🔴",
        "High": "🟠",
        "Medium": "🟡",
        "Low": "🟢",
    }
    color = severity_colors.get(vuln["severity"], "⚪")
    print(f"{color} {vuln['cve']} CVSS {vuln['cvss']} [{vuln['severity']}]")
    print(f"   Software: {vuln['software']}")
    print(f"   {vuln['description'][:120]}")

def main():
    """Main entry point for the agentic AI system."""
    
    if len(sys.argv) < 2:
        print("""
╔════════════════════════════════════════════════════════════════════════════╗
║           MULTI-AGENT CYBERSECURITY ASSISTANT (Agentic AI)                 ║
╚════════════════════════════════════════════════════════════════════════════╝

USAGE:
  python run_analysis.py <file1> [file2] [file3] ...

EXAMPLES:
  python run_analysis.py sample.log
  python run_analysis.py access.log network.txt
  python run_analysis.py auth.log vuln_report.pdf ids.csv

SUPPORTED FILE TYPES:
  .log, .txt, .csv, .pdf

The system will:
  1. Parse your files
  2. Detect security threats (rules + ML + LLM)
  3. Retrieve CVEs from NVD
  4. Calculate risk score
  5. Generate mitigation recommendations
  6. Print a complete security report
        """)
        sys.exit(1)

    # Get input files
    input_files = sys.argv[1:]
    file_paths = []
    
    for filename in input_files:
        path = Path(filename)
        if not path.exists():
            print(f"❌ ERROR: File not found — {filename}")
            sys.exit(1)
        if path.suffix.lower() not in {".log", ".txt", ".csv", ".pdf"}:
            print(f"❌ ERROR: Unsupported file type — {path.suffix}")
            sys.exit(1)
        file_paths.append(str(path))

    # Print startup banner
    print_header("🛡️  MULTI-AGENT CYBERSECURITY ASSISTANT")
    print(f"Files to analyze: {len(file_paths)}")
    for f in file_paths:
        print(f"  • {Path(f).name}")

    # Run the agentic AI pipeline
    print_header("🤖 INITIATING AGENTIC AI PIPELINE")
    print("LangGraph workflow starting...")
    print("Agents: Coordinator → Threat Detection → CVE Retrieval → Risk Scoring → Recommendations")
    
    start_time = time.time()
    report = run_analysis("cli-analysis", file_paths)
    elapsed = time.time() - start_time

    # ─────────────────────────── Results ───────────────────────────────────

    print_header("📊 SECURITY ANALYSIS REPORT")
    
    # Summary
    print_section("EXECUTIVE SUMMARY")
    print(report.get("summary", "No summary available"))
    print(f"Report generated at: {report.get('generated_at', 'N/A')}")
    print(f"Analysis completed in: {elapsed:.1f} seconds")

    # Risk Score
    print_section("RISK ASSESSMENT")
    risk_score = report.get("risk_score", 0)
    risk_level = report.get("risk_level", "Unknown")
    
    risk_emoji = {
        "Low": "🟢",
        "Medium": "🟡",
        "High": "🟠",
        "Critical": "🔴",
    }
    emoji = risk_emoji.get(risk_level, "⚪")
    
    print(f"{emoji} Risk Level: {risk_level}")
    print(f"Risk Score: {risk_score:.1f} / 100.0")
    if report.get("risk_explanation"):
        print(f"Explanation: {report['risk_explanation']}")

    # Threats
    threats = report.get("threats", [])
    print_section("DETECTED THREATS")
    if threats:
        print(f"Total threats found: {len(threats)}\n")
        for threat in threats[:10]:  # Show top 10
            print_threat(threat)
    else:
        print("✅ No threats detected")

    # Vulnerabilities
    vulns = report.get("vulnerabilities", [])
    print_section("CVE / VULNERABILITY FINDINGS")
    if vulns:
        print(f"Total CVEs found: {len(vulns)}\n")
        for vuln in vulns[:10]:  # Show top 10
            print_vulnerability(vuln)
    else:
        print("✅ No CVEs found")

    # Risk components
    if report.get("risk_components"):
        print_section("RISK COMPONENTS BREAKDOWN")
        comps = report["risk_components"]
        print(f"Threat Severity Score: {comps.get('threat_severity_score', 0):.1f}")
        print(f"CVSS Average: {comps.get('cvss_average', 0):.1f}")
        print(f"Confidence Average: {comps.get('confidence_average', 0):.1f}%")

    # Recommendations
    recs = report.get("recommendations", [])
    priority = report.get("priority_actions", [])
    
    print_section("REMEDIATION RECOMMENDATIONS")
    if priority:
        print("🚨 IMMEDIATE PRIORITY ACTIONS:")
        for i, action in enumerate(priority[:5], 1):
            print(f"  {i}. {action}")
    
    if recs:
        print("\n📋 RECOMMENDED MITIGATIONS:")
        for i, rec in enumerate(recs[:10], 1):
            print(f"  {i}. {rec}")
    else:
        print("No additional recommendations at this time.")

    # Agent execution summary
    if report.get("execution_summary"):
        print_section("AGENT EXECUTION SUMMARY")
        print(report["execution_summary"])

    # Errors (if any)
    if report.get("errors"):
        print_section("⚠️  WARNINGS / ERRORS")
        for error in report["errors"]:
            print(f"  ⚠️  {error}")

    # Footer
    print_header("✅ ANALYSIS COMPLETE")
    print(f"Job ID: {report.get('job_id')}")
    print(f"Files analyzed: {len(report.get('files_analyzed', []))}")
    print(f"Processing time: {elapsed:.1f}s")
    print("\nFor full JSON report, see the report saved to disk.")

if __name__ == "__main__":
    main()
