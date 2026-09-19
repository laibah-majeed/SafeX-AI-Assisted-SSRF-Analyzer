"""
models.py

Pydantic request/response models for the AI-Assisted SSRF Analyzer API.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    target_url: str = Field(
        ...,
        description="Authorized local lab URL to run controlled SSRF detection checks against.",
        examples=["http://localhost:8080/fetch?url=http://localhost:8080/internal"],
    )


class EvidenceItem(BaseModel):
    signal: str
    description: str
    observed: str
    weight: str  # "low" | "medium" | "high"


class BaselineInfo(BaseModel):
    status_code: Optional[int] = None
    response_length: Optional[int] = None
    response_time_ms: Optional[float] = None
    response_signature: Optional[str] = None
    error: Optional[str] = None


class ScanResponse(BaseModel):
    target: str
    scan_status: str  # "completed" | "error"
    vulnerability_detected: bool
    severity: str  # "Low" | "Medium" | "High" | "None"
    severity_reasoning: str
    confidence: str  # "Low" | "Medium" | "High"
    confidence_reasoning: str
    baseline: BaselineInfo
    evidence: List[EvidenceItem]
    ai_interpretation: str
    remediation: List[str]
    timestamp: str
    warnings: List[str] = []


class ErrorResponse(BaseModel):
    detail: str
