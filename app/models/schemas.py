"""
Pydantic schemas for request/response validation.
"""
from __future__ import annotations
from typing import Any, List, Optional
from datetime import datetime
from pydantic import BaseModel, Field


# ─────────────────────────── Threat ───────────────────────────

class ThreatItem(BaseModel):
    type: str
    severity: str  # Low | Medium | High | Critical
    confidence: float = Field(..., ge=0.0, le=1.0)
    evidence: List[str] = []
    source_ip: Optional[str] = None


class ThreatAnalysisResult(BaseModel):
    threats: List[ThreatItem] = []
    anomaly_detected: bool = False
    summary: str = ""


# ─────────────────────────── CVE ──────────────────────────────

class CVEItem(BaseModel):
    software: str
    version: Optional[str] = None
    cve: str
    cvss: float
    severity: str
    description: str
    published_date: Optional[str] = None
    references: List[str] = []


class CVERetrievalResult(BaseModel):
    vulnerabilities: List[CVEItem] = []
    software_detected: List[str] = []
    query_status: str = "ok"


# ─────────────────────────── Risk ─────────────────────────────

class RiskScoreResult(BaseModel):
    risk_score: float
    risk_level: str  # Low | Medium | High | Critical
    threat_severity_score: float
    cvss_average: float
    confidence_average: float
    explanation: str


# ─────────────────────────── Recommendations ──────────────────

class RecommendationResult(BaseModel):
    recommendations: List[str] = []
    priority_actions: List[str] = []
    generated_by_llm: bool = False


# ─────────────────────────── Final Report ─────────────────────

class SecurityReport(BaseModel):
    job_id: str
    summary: str
    threats: List[ThreatItem] = []
    vulnerabilities: List[CVEItem] = []
    risk_score: float
    risk_level: str
    recommendations: List[str] = []
    priority_actions: List[str] = []
    files_analyzed: List[str] = []
    generated_at: str
    processing_time_seconds: Optional[float] = None


# ─────────────────────────── API Responses ────────────────────

class AnalyzeResponse(BaseModel):
    job_id: str
    status: str
    report: SecurityReport


class BatchAnalyzeResponse(BaseModel):
    job_id: str
    status: str
    files_count: int
    report: SecurityReport


class ReportResponse(BaseModel):
    job_id: str
    report: SecurityReport
    generated_at: str


class HealthResponse(BaseModel):
    status: str
    ollama_connected: bool
    database_connected: bool
    model: str
    version: str = "1.0.0"


# ─────────────────────────── LangGraph State ──────────────────

class AgentState(BaseModel):
    """Shared state passed between LangGraph nodes."""
    job_id: str = ""
    files: List[str] = []
    parsed_content: str = ""
    raw_logs: str = ""
    threats: List[dict] = []
    vulnerabilities: List[dict] = []
    risk_score: Optional[float] = None
    risk_level: str = ""
    recommendations: List[str] = []
    priority_actions: List[str] = []
    final_report: dict = {}
    errors: List[str] = []
    processing_steps: List[str] = []

    class Config:
        arbitrary_types_allowed = True
