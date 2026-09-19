# Detection Methodology

## Pipeline Overview

```text
Authorized URL
      ↓
Validation
      ↓
Baseline Request
      ↓
Controlled SSRF Checks
      ↓
Response Analysis
      ↓
Evidence
      ↓
Confidence
      ↓
Severity
      ↓
AI-Assisted Interpretation
      ↓
Remediation
      ↓
Final Report
```

## Stage Details

### 1. Authorized URL

The user submits a target URL via the frontend scanner form. This is the
only place a target enters the system — the AI component never selects or
proposes a target.

### 2. Validation

`backend/ssrf_detector.py:validate_target()` checks:

- The URL is well-formed and non-empty.
- The scheme is `http` or `https`.
- The hostname is present in `ALLOWED_HOSTS` (see `backend/config.py`),
  which defaults to `localhost`, `127.0.0.1`, and `::1`, extendable only
  via the `SSRF_LAB_ALLOWED_HOSTS` environment variable.

Any target that fails validation is rejected before any network request is
made, with a `400` (invalid) or `403` (unauthorized) response.

### 3. Baseline Request

The (unmodified) target URL is requested multiple times
(`BASELINE_SAMPLES`, default 2) to characterize normal behavior: status
code, response length, response time, and a SHA-256-based content
signature. Using the median across samples reduces sensitivity to one-off
noise.

### 4. Controlled SSRF Checks

If the target URL's query string contains a parameter matching a list of
common URL-fetching parameter names (`url`, `target`, `dest`, `redirect`,
etc.), the detector substitutes that parameter with a small number of
**safe, loopback-only** values pointing at unusual local ports (a
low-numbered closed port and a high unassigned port). The outer HTTP
request always still goes to the already-authorized lab host — only the
*value of a query parameter* changes.

If no such parameter is found, no substitution checks are run, and this is
reported honestly as a limitation of the test rather than forced into a
finding.

### 5. Response Analysis

Each probe response is compared against the baseline across four
independent dimensions:

- Status code change
- Response length change
- Response body signature change
- Response time delta (a large increase suggests a real outbound
  connection attempt to an unreachable port)

### 6. Evidence

Every check performed — including baseline failures and the "no candidate
parameter" case — is recorded as a structured evidence item with a
`signal`, `description`, `observed` value, and a qualitative `weight`
(low/medium/high).

### 7. Confidence

Confidence (Low/Medium/High) is derived from the *ratio* of probes that
showed a meaningful difference and the *number* of independent signals per
probe. A single differing signal on a single probe yields Low confidence;
multiple corroborating signals across multiple probes yield High
confidence.

### 8. Severity

Severity (None/Medium/High) is only assigned when a positive detection is
made, and scales with confidence and signal count. Severity is never set
to High purely because a request returned HTTP 200 or because a single
signal changed — see `docs/SSRF-research.md` for why single-signal
detection is unreliable.

### 9. AI-Assisted Interpretation

The structured evidence object (not raw network access, not credentials)
is passed to `backend/ai_analyzer.py`, which asks an LLM to explain the
finding in plain English, discuss plausible false positives, and suggest
manual verification steps. If no API key is configured, a deterministic,
clearly-labeled fallback explanation is used instead.

### 10. Remediation

A static, curated checklist of SSRF remediation practices is returned
alongside every scan result (a fuller list for positive findings, a
shorter general baseline for clean results).

### 11. Final Report

The frontend renders all of the above as a scan summary, evidence table,
AI-Assisted Interpretation card, and remediation checklist. The same
structure is used for the Markdown report templates in `reports/`.

## Architecture

```text
┌─────────────────────┐        POST /scan        ┌──────────────────────────┐
│  React + Tailwind    │ ────────────────────────▶│   FastAPI backend        │
│  frontend (Vite)     │                            │   main.py                │
│                       │◀──────────────────────── │   ssrf_detector.py       │
└─────────────────────┘      JSON ScanResponse     │   ai_analyzer.py         │
                                                    │   config.py (allowlist) │
                                                    └──────────┬───────────────┘
                                                               │ GET (loopback only)
                                                               ▼
                                                    ┌──────────────────────────┐
                                                    │ Authorized local lab     │
                                                    │ target (localhost:*)     │
                                                    └──────────────────────────┘
```
