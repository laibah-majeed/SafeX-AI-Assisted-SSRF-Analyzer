"""
main.py

FastAPI application entrypoint for the AI-Assisted SSRF Analyzer.

Run with:
    uvicorn main:app --reload --port 8000
"""

from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from config import FRONTEND_ORIGIN, ALLOWED_HOSTS
from models import ScanRequest, ScanResponse, BaselineInfo, EvidenceItem
from ssrf_detector import run_detection, UnauthorizedTargetError, InvalidTargetError
from ai_analyzer import generate_ai_interpretation

app = FastAPI(
    title="AI-Assisted SSRF Analyzer",
    description=(
        "Defensive, evidence-based SSRF detection tool for authorized local "
        "security labs. Not for use against production or unauthorized systems."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN, "http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

REMEDIATION_CHECKLIST = [
    "Apply strict URL validation on any user-influenceable destination (scheme, host, and port allowlisting).",
    "Maintain a domain/IP allowlist for outbound server-side requests instead of a denylist.",
    "Block requests to loopback, link-local, and other internal/private address ranges by default.",
    "Validate every redirect target before following it — do not blindly follow redirects.",
    "Apply network segmentation so the application tier cannot reach sensitive internal services it doesn't need.",
    "Run outbound-request-making services with least privilege and no unnecessary network egress.",
    "Use a dedicated, monitored egress proxy for server-side HTTP fetches so requests can be logged and constrained.",
]


@app.get("/")
def root():
    return {
        "service": "AI-Assisted SSRF Analyzer",
        "status": "ok",
        "notice": "Only scan systems you own or are explicitly authorized to test.",
        "authorized_hosts": sorted(ALLOWED_HOSTS),
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResponse)
def scan(request: ScanRequest):
    try:
        result = run_detection(request.target_url)
    except UnauthorizedTargetError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except InvalidTargetError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 - never leak raw tracebacks
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred while scanning the target. "
            "Please verify the target is reachable and try again.",
        ) from exc

    evidence_for_ai = {
        "target": request.target_url,
        "vulnerability_detected": result.vulnerability_detected,
        "severity": result.severity,
        "confidence": result.confidence,
        "confidence_reasoning": result.confidence_reasoning,
        "evidence": result.evidence,
        "baseline": {
            "status_code": result.baseline.status_code,
            "response_length": result.baseline.response_length,
            "response_time_ms": result.baseline.response_time_ms,
        },
    }
    ai_text = generate_ai_interpretation(evidence_for_ai)

    return ScanResponse(
        target=request.target_url,
        scan_status="completed",
        vulnerability_detected=result.vulnerability_detected,
        severity=result.severity,
        severity_reasoning=result.severity_reasoning,
        confidence=result.confidence,
        confidence_reasoning=result.confidence_reasoning,
        baseline=BaselineInfo(
            status_code=result.baseline.status_code,
            response_length=result.baseline.response_length,
            response_time_ms=result.baseline.response_time_ms,
            response_signature=result.baseline.body_signature,
            error=result.baseline.error,
        ),
        evidence=[EvidenceItem(**item) for item in result.evidence],
        ai_interpretation=ai_text,
        remediation=REMEDIATION_CHECKLIST if result.vulnerability_detected else REMEDIATION_CHECKLIST[:3],
        timestamp=datetime.now(timezone.utc).isoformat(),
        warnings=result.warnings,
    )
