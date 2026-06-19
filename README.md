#  Multi-Agent Cybersecurity Assistant

An agentic AI system that autonomously analyses security logs, retrieves CVEs, assesses risk, and generates actionable mitigation recommendations — powered by **LangGraph**, **Ollama**, and **scikit-learn**. No backend. No API. Pure agent orchestration.

---

##  What Makes This Agentic AI

Five specialized agents work autonomously through a **LangGraph StateGraph**:

```
Input Files (.log / .txt / .csv / .pdf)
          │
          ▼
┌─────────────────────┐
│   parse_input       │  Extracts events, IPs, software versions
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  Coordinator Agent  │  Manages workflow, retries, error handling
└─────────┬───────────┘
          │
          ▼
┌──────────────────────────────┐
│  Threat Detection Agent      │  Phase 1: Regex rules
│                              │  Phase 2: Isolation Forest (ML)
│                              │  Phase 3: Ollama LLM
└──────────┬───────────────────┘
           │
           ▼
┌──────────────────────────────┐
│  CVE Retrieval Agent         │  NVD API v2 + local fallback dataset
└──────────┬───────────────────┘
           │
           ▼
┌──────────────────────────────┐
│  Risk Scoring Agent          │  0.4×threat + 0.4×CVSS + 0.2×confidence
└──────────┬───────────────────┘
           │
           ▼
┌──────────────────────────────┐
│  Recommendation Agent        │  Rule-based + Ollama LLM enrichment
└──────────┬───────────────────┘
           │
           ▼
┌──────────────────────────────┐
│  Report Generator            │  Console output + JSON saved to disk
└──────────────────────────────┘
```

---

##  Tech Stack

| Component | Technology |
|---|---|
| Agent Orchestration | LangGraph |
| LLM (local) | Ollama (llama3) |
| Anomaly Detection | scikit-learn (Isolation Forest) |
| File Parsing | PyMuPDF, Pandas, Regex |
| CVE Database | NVD API v2 + local fallback |
| Schemas | Pydantic |
| Testing | pytest |

---

##  Installation

### 1. Clone the repository

```bash
git clone https://github.com/pranv777/multi-agent-cybersecurity-assistant.git
cd multi-agent-cybersecurity-assistant
```

### 2. Create virtual environment with Python 3.11

```bash
# Windows
py -3.11 -m venv venv
venv\Scripts\activate

# macOS / Linux
python3.11 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Set up Ollama

Download from [https://ollama.com/download](https://ollama.com/download) and install.

Then in a separate terminal:

```bash
ollama serve
ollama pull llama3
```

### 5. Configure environment

Edit `.env` if needed (defaults work out of the box):

```env
OLLAMA_MODEL=llama3
OLLAMA_BASE_URL=http://localhost:11434
```

---

##  Usage

```bash
# Single file
python run_analysis.py sample.log

# Multiple files (analyzed together by all agents)
python run_analysis.py access.log network.txt vuln_report.pdf

# Show help
python run_analysis.py
```

### Supported File Types

| Extension | Description |
|---|---|
| `.log` | System / auth / access logs |
| `.txt` | Vulnerability reports, scan outputs |
| `.csv` | Network event exports |
| `.pdf` | Security scan reports |

---

##  Sample Output

```
================================================================================
  🛡️  MULTI-AGENT CYBERSECURITY ASSISTANT
================================================================================
Files to analyze: 1
  • sample.log

================================================================================
  🤖 INITIATING AGENTIC AI PIPELINE
================================================================================
Agents: Coordinator → Threat Detection → CVE Retrieval → Risk Scoring → Recommendations

================================================================================
  📊 SECURITY ANALYSIS REPORT
================================================================================

EXECUTIVE SUMMARY
--------------------------------------------------------------------------------
Analysis identified 4 threats and 3 CVEs. Overall risk level: Critical (80.2/100).
Immediate remediation is required.

RISK ASSESSMENT
--------------------------------------------------------------------------------
🔴 Risk Level: Critical
Risk Score: 80.2 / 100.0

DETECTED THREATS
--------------------------------------------------------------------------------
Total threats found: 4

🟡 [MEDIUM] Brute Force (confidence: 95%)
   ↳ 5 failed login attempts from IP 192.168.1.100
🔴 [CRITICAL] Malware Indicator (confidence: 80%)
   ↳ Malware-related keywords detected in logs
🟡 [MEDIUM] Port Scan (confidence: 70%)
   ↳ Port scan indicators found: 1 event(s)
🟡 [MEDIUM] Statistical Anomaly (confidence: 70%)
   ↳ Isolation Forest detected unusual log distribution

CVE / VULNERABILITY FINDINGS
--------------------------------------------------------------------------------
Total CVEs found: 3

🔴 CVE-2021-44228 CVSS 10.0 [Critical]
   Software: Log4j 2.14.1
   Log4Shell — JNDI injection RCE in Apache Log4j 2.
🔴 CVE-2021-41773 CVSS 9.8 [Critical]
   Software: Apache 2.4.49
   Path traversal and RCE in Apache HTTP Server 2.4.49.

REMEDIATION RECOMMENDATIONS
--------------------------------------------------------------------------------
🚨 IMMEDIATE PRIORITY ACTIONS:
  1. PATCH NOW: CVE-2021-44228 in Log4j 2.14.1 (CVSS 10.0).
  2. IMMEDIATE: Escalate to security incident response team.
  3. PATCH NOW: CVE-2021-41773 in Apache 2.4.49 (CVSS 9.8).

📋 RECOMMENDED MITIGATIONS:
  1. Enable account lockout policy after 5 failed attempts.
  2. Implement Multi-Factor Authentication (MFA) on all endpoints.
  3. Rate-limit login attempts per IP using fail2ban or equivalent.
  4. Deploy an Intrusion Detection System (IDS).
  5. Apply latest security patches.

AGENT EXECUTION SUMMARY
--------------------------------------------------------------------------------
Steps completed : 6
Errors          : 0
Threats found   : 4
CVEs retrieved  : 3
Risk score      : 80.2 (Critical)

================================================================================
  ✅ ANALYSIS COMPLETE
================================================================================
```

---

##  Running Tests

```bash
# All tests
pytest -v

# Individual test files
pytest tests/test_agents.py -v
pytest tests/test_workflow.py -v
pytest tests/test_parsers.py -v
pytest tests/test_e2e.py -v
```

46 tests — all passing. ✅

---

## 🔢 Risk Scoring Formula

```
risk_score = (0.4 × threat_severity_score)
           + (0.4 × cvss_average × 10)
           + (0.2 × confidence_average × 100)
```

| Severity | Score |
|---|---|
| Low | 25 |
| Medium | 50 |
| High | 75 |
| Critical | 100 |

| Risk Score | Risk Level |
|---|---|
| 0 – 24 | 🟢 Low |
| 25 – 49 | 🟡 Medium |
| 50 – 74 | 🟠 High |
| 75 – 100 | 🔴 Critical |

---

##  Agent Details

### Coordinator Agent
Manages the LangGraph workflow. Validates state, handles errors, retries failed agents, and generates an execution summary after all agents complete.

### Threat Detection Agent
- **Phase 1 — Rule-based:** Regex patterns detect brute force, port scans, malware keywords, suspicious tools (sqlmap, nikto, nmap, hydra, metasploit)
- **Phase 2 — ML:** Isolation Forest (scikit-learn) detects statistical anomalies in log distributions
- **Phase 3 — LLM:** Ollama interprets logs for novel or contextual threats

### CVE Retrieval Agent
Extracts software names and versions from parsed content, then queries the NVD API v2. Falls back to a curated local dataset (Apache, Log4j, OpenSSH, Nginx, OpenSSL, WordPress, etc.) when the API is unreachable.

### Risk Scoring Agent
Applies the weighted formula above. Returns a numeric score (0–100), risk level, component breakdown, and plain-English explanation.

### Recommendation Agent
Generates specific mitigations per threat type (fail2ban for brute force, IDS for port scans, isolation for malware) then enriches them with Ollama LLM for context-aware advice.

---

##  Create a Sample Log File

Paste this into Notepad and save as `sample.log`:

```
2024-01-15 08:23:01 sshd: Failed password for root from 192.168.1.100 port 22
2024-01-15 08:23:02 sshd: Failed password for root from 192.168.1.100 port 22
2024-01-15 08:23:03 sshd: Failed password for admin from 192.168.1.100 port 22
2024-01-15 08:23:04 sshd: Failed password for test from 192.168.1.100 port 22
2024-01-15 08:23:05 sshd: Failed password for user from 192.168.1.100 port 22
2024-01-15 08:23:06 kernel: nmap scan detected from 10.10.10.1
2024-01-15 08:23:07 app: malware payload detected in upload
2024-01-15 08:23:08 apache: brute force attack from 10.0.0.5
Server: Apache 2.4.49 on port 80
Log4j 2.14.1 detected in classpath
```

Then run:

```bash
python run_analysis.py sample.log
```

---

##  Future Enhancements

- [ ] MITRE ATT&CK framework mapping
- [ ] Real-time log streaming support
- [ ] Autoencoder-based anomaly detection
- [ ] Email / Slack alerting for Critical findings
- [ ] STIX/TAXII threat intelligence integration
- [ ] Support for Windows Event Log (.evtx) format
- [ ] Interactive CLI with rich / textual library
- [ ] Docker containerisation

---

##  License

MIT License — free for personal and commercial use.

---
