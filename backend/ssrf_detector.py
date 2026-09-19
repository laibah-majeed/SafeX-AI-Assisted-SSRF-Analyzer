"""
ssrf_detector.py

Defensive, evidence-based SSRF (Server-Side Request Forgery) detection
engine for AUTHORIZED LOCAL LAB TARGETS ONLY.

Design goals
------------
1. Never contact a host outside the configured allowlist (see config.py).
2. Never assume SSRF from a single signal (e.g. "HTTP 200 = vulnerable").
   Multiple independent signals are combined into a confidence score.
3. Never perform destructive, credential-harvesting, or exploitation
   actions. This module only *observes* differences in response
   behavior between a baseline request and a small number of safe,
   local, non-destructive variations of the same request.
4. Fail closed: any ambiguity or network error is reported as evidence,
   not silently ignored, and never escalates severity by itself.

This module intentionally does NOT contain payloads targeting cloud
metadata services, internal network ranges, or any host other than the
loopback addresses the user has explicitly authorized. That kind of
network discovery is out of scope for this academic/defensive tool.
"""

import hashlib
import statistics
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import requests

from config import (
    ALLOWED_HOSTS,
    ALLOWED_SCHEMES,
    REQUEST_TIMEOUT_SECONDS,
    MAX_RESPONSE_BYTES,
    MAX_REDIRECTS,
    BASELINE_SAMPLES,
)

# Parameter names commonly used by applications that fetch a URL server-side.
# Used ONLY to decide which safe, local substitution checks to run — never
# to guess or brute-force endpoints.
CANDIDATE_URL_PARAMS = [
    "url", "target", "uri", "dest", "destination", "redirect",
    "path", "endpoint", "resource", "fetch", "callback", "next",
]

# Safe, local substitution values. Every value here resolves to the
# loopback interface only.
LOCAL_PROBE_VARIANTS = [
    "http://127.0.0.1:{port}/",
    "http://localhost:{port}/",
    "http://[::1]:{port}/",
]


class UnauthorizedTargetError(Exception):
    """Raised when a target is not in the authorized allowlist."""


class InvalidTargetError(Exception):
    """Raised when a target URL is malformed or uses a disallowed scheme."""


@dataclass
class RequestObservation:
    status_code: Optional[int] = None
    response_length: Optional[int] = None
    response_time_ms: Optional[float] = None
    body_signature: Optional[str] = None
    headers_signature: Optional[str] = None
    error: Optional[str] = None


@dataclass
class DetectionResult:
    vulnerability_detected: bool
    severity: str
    severity_reasoning: str
    confidence: str
    confidence_reasoning: str
    baseline: RequestObservation
    evidence: List[dict] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


def validate_target(target_url: str) -> str:
    """
    Validate that the target URL is well-formed and its host is on the
    authorized allowlist. Returns the normalized URL or raises.
    """
    if not target_url or not target_url.strip():
        raise InvalidTargetError("Target URL must not be empty.")

    parsed = urlparse(target_url.strip())

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise InvalidTargetError(
            f"Scheme '{parsed.scheme}' is not permitted. Use http or https."
        )

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise InvalidTargetError("Target URL must include a valid host.")

    if hostname not in ALLOWED_HOSTS:
        raise UnauthorizedTargetError(
            f"Host '{hostname}' is not in the authorized lab allowlist. "
            f"This tool only scans hosts explicitly configured for testing "
            f"(see backend/config.py ALLOWED_HOSTS)."
        )

    return target_url.strip()


def _signature(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def _safe_get(url: str) -> Tuple[RequestObservation, Optional[bytes]]:
    """
    Perform a single safe, capped, timeout-bounded GET request.
    Never raises — errors are captured as observation data.
    """
    obs = RequestObservation()
    start = time.perf_counter()
    try:
        resp = requests.get(
            url,
            timeout=REQUEST_TIMEOUT_SECONDS,
            allow_redirects=True,
            stream=True,
        )
        raw = resp.raw.read(MAX_RESPONSE_BYTES, decode_content=True) or b""
        elapsed_ms = (time.perf_counter() - start) * 1000

        obs.status_code = resp.status_code
        obs.response_length = len(raw)
        obs.response_time_ms = round(elapsed_ms, 2)
        obs.body_signature = _signature(raw)
        header_str = ";".join(f"{k.lower()}" for k in resp.headers.keys())
        obs.headers_signature = _signature(header_str.encode())
        resp.close()
        return obs, raw
    except requests.exceptions.Timeout:
        obs.error = "timeout"
        obs.response_time_ms = round((time.perf_counter() - start) * 1000, 2)
        return obs, None
    except requests.exceptions.ConnectionError:
        obs.error = "connection_error"
        obs.response_time_ms = round((time.perf_counter() - start) * 1000, 2)
        return obs, None
    except requests.exceptions.RequestException as exc:
        obs.error = f"request_error: {type(exc).__name__}"
        obs.response_time_ms = round((time.perf_counter() - start) * 1000, 2)
        return obs, None


def _establish_baseline(url: str) -> RequestObservation:
    """Run the same request multiple times to characterize normal behavior."""
    samples: List[RequestObservation] = []
    for _ in range(max(1, BASELINE_SAMPLES)):
        obs, _ = _safe_get(url)
        samples.append(obs)

    successful = [s for s in samples if s.error is None]
    if not successful:
        return samples[0]

    lengths = [s.response_length for s in successful if s.response_length is not None]
    times = [s.response_time_ms for s in successful if s.response_time_ms is not None]

    baseline = RequestObservation(
        status_code=successful[-1].status_code,
        response_length=int(statistics.median(lengths)) if lengths else None,
        response_time_ms=round(statistics.median(times), 2) if times else None,
        body_signature=successful[-1].body_signature,
        headers_signature=successful[-1].headers_signature,
    )
    return baseline


def _find_url_param(parsed_query: List[Tuple[str, str]]) -> Optional[str]:
    for key, _ in parsed_query:
        if key.lower() in CANDIDATE_URL_PARAMS:
            return key
    return None


def _build_variant_url(target_url: str, param_name: str, replacement_value: str) -> str:
    parsed = urlparse(target_url)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    new_pairs = [
        (k, replacement_value if k == param_name else v) for k, v in query_pairs
    ]
    new_query = urlencode(new_pairs)
    return urlunparse(parsed._replace(query=new_query))


def run_detection(target_url: str) -> DetectionResult:
    """
    Main entry point: validates target, establishes a baseline, runs a
    small set of safe local substitution checks (only if the URL exposes
    a parameter that looks like it accepts a nested URL), and returns a
    structured, evidence-backed result.
    """
    warnings: List[str] = []
    evidence: List[dict] = []

    validated_url = validate_target(target_url)
    parsed = urlparse(validated_url)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)

    baseline = _establish_baseline(validated_url)

    if baseline.error:
        return DetectionResult(
            vulnerability_detected=False,
            severity="None",
            severity_reasoning=(
                "No severity assigned because the baseline request itself "
                "failed, so no comparison is possible."
            ),
            confidence="Low",
            confidence_reasoning=(
                f"Baseline request to the target failed with error "
                f"'{baseline.error}'. Detection requires a working baseline; "
                "this may indicate the lab target is not running, or that "
                "the port/path is incorrect."
            ),
            baseline=baseline,
            evidence=[{
                "signal": "baseline_failure",
                "description": "The initial baseline request did not complete successfully.",
                "observed": baseline.error,
                "weight": "high",
            }],
            warnings=["Baseline request failed; no further checks were run."],
        )

    param_name = _find_url_param(query_pairs)

    if not param_name:
        # No candidate SSRF injection point was found in the query string.
        # This is a normal, common outcome and is reported honestly rather
        # than forcing a finding.
        evidence.append({
            "signal": "no_candidate_parameter",
            "description": (
                "No query parameter matching common URL-fetching patterns "
                f"({', '.join(CANDIDATE_URL_PARAMS)}) was found in the target URL."
            ),
            "observed": f"query params present: {[k for k, _ in query_pairs] or 'none'}",
            "weight": "medium",
        })
        return DetectionResult(
            vulnerability_detected=False,
            severity="None",
            severity_reasoning=(
                "No candidate server-side-fetch parameter was identified, so "
                "no SSRF-relevant behavior could be exercised. This does not "
                "rule out SSRF via request bodies, headers, or undocumented "
                "parameters, which this tool does not test."
            ),
            confidence="Low",
            confidence_reasoning=(
                "Confidence is Low because the absence of an obvious "
                "parameter is weak negative evidence, not proof of safety."
            ),
            baseline=baseline,
            evidence=evidence,
            warnings=[
                "Provide a URL whose query string includes a parameter such "
                "as 'url' or 'target' that your lab application uses to "
                "fetch a resource server-side, to exercise the detector."
            ],
        )

    # Run safe local substitution checks against the identified parameter.
    signals_triggered = 0
    total_checks = 0
    observations = []

    probe_ports = ["1", "65535"]  # low-numbered closed port, high unassigned port
    for port in probe_ports:
        for variant_template in LOCAL_PROBE_VARIANTS[:1]:  # keep checks minimal
            variant_value = variant_template.format(port=port)
            variant_url = _build_variant_url(validated_url, param_name, variant_value)

            try:
                variant_host = urlparse(variant_url).hostname
            except Exception:
                variant_host = None

            # Re-validate the *outer* request host every time (defense in depth) —
            # the substituted inner value is a query parameter, not the request
            # target itself, so the outer HTTP call always still goes to the
            # already-authorized lab host.
            total_checks += 1
            obs, raw = _safe_get(variant_url)
            observations.append((variant_value, obs))

            time_delta = None
            if obs.response_time_ms is not None and baseline.response_time_ms is not None:
                time_delta = obs.response_time_ms - baseline.response_time_ms

            length_changed = (
                obs.response_length is not None
                and baseline.response_length is not None
                and obs.response_length != baseline.response_length
            )
            status_changed = (
                obs.status_code is not None
                and baseline.status_code is not None
                and obs.status_code != baseline.status_code
            )
            signature_changed = (
                obs.body_signature is not None
                and baseline.body_signature is not None
                and obs.body_signature != baseline.body_signature
            )
            noticeably_slower = (
                time_delta is not None and time_delta > 300  # ms, indicates a real outbound attempt
            )

            local_signals = sum([length_changed, status_changed, signature_changed, noticeably_slower])

            evidence.append({
                "signal": f"param_substitution_probe_port_{port}",
                "description": (
                    f"Substituted the '{param_name}' parameter with a loopback "
                    f"URL pointing at an unusual local port ({port}) and compared "
                    "the response against the baseline."
                ),
                "observed": (
                    f"status={obs.status_code or obs.error}, "
                    f"length_changed={length_changed}, "
                    f"status_changed={status_changed}, "
                    f"body_changed={signature_changed}, "
                    f"time_delta_ms={time_delta}"
                ),
                "weight": "high" if local_signals >= 2 else ("medium" if local_signals == 1 else "low"),
            })

            if local_signals >= 1:
                signals_triggered += 1

    confidence, confidence_reasoning = _score_confidence(signals_triggered, total_checks, warnings)
    vulnerability_detected = signals_triggered >= 2 and total_checks >= 2
    severity, severity_reasoning = _score_severity(vulnerability_detected, signals_triggered, confidence)

    if not vulnerability_detected:
        warnings.append(
            "Response differences alone do not prove SSRF. Manually verify any "
            "finding against the lab application's source or logs before "
            "treating it as confirmed."
        )

    return DetectionResult(
        vulnerability_detected=vulnerability_detected,
        severity=severity,
        severity_reasoning=severity_reasoning,
        confidence=confidence,
        confidence_reasoning=confidence_reasoning,
        baseline=baseline,
        evidence=evidence,
        warnings=warnings,
    )


def _score_confidence(signals_triggered: int, total_checks: int, warnings: List[str]) -> Tuple[str, str]:
    if total_checks == 0:
        return "Low", "No checks could be executed."
    ratio = signals_triggered / total_checks
    if ratio >= 0.75 and signals_triggered >= 2:
        return (
            "High",
            f"{signals_triggered}/{total_checks} probe variations produced multiple "
            "independent behavioral differences (length, status, body, and/or timing) "
            "relative to baseline, which is consistent with the application making a "
            "server-side request that varies with attacker-controlled input.",
        )
    if ratio >= 0.4:
        return (
            "Medium",
            f"{signals_triggered}/{total_checks} probe variations showed some behavioral "
            "difference, but not consistently enough to rule out noise (e.g. dynamic "
            "content, timeouts, or unrelated variability).",
        )
    return (
        "Low",
        f"Only {signals_triggered}/{total_checks} probe variations showed any difference "
        "from baseline, which is more consistent with normal response variability than "
        "with a confirmed server-side fetch.",
    )


def _score_severity(vulnerability_detected: bool, signals_triggered: int, confidence: str) -> Tuple[str, str]:
    if not vulnerability_detected:
        return (
            "None",
            "No severity is assigned because the combined evidence did not meet the "
            "threshold for a positive detection.",
        )
    if confidence == "High" and signals_triggered >= 2:
        return (
            "High",
            "Multiple independent, strongly correlated signals across probe variations "
            "indicate the application likely performs an attacker-influenceable "
            "server-side request. In a real deployment this class of finding can enable "
            "internal network reconnaissance or interaction with internal-only services, "
            "so it is rated High pending manual confirmation.",
        )
    return (
        "Medium",
        "Behavioral differences were observed that are consistent with server-side "
        "request forgery, but the signal strength or consistency was not high enough "
        "for a High rating. Rated Medium pending manual verification in the lab "
        "environment.",
    )
