# SSRF Security Finding

## Target

`http://localhost:8080/profile?id=42`

Same local lab application, tested against an endpoint that does not accept
a server-side-fetch URL parameter.

## Testing Environment

- Host OS: local development machine
- Lab application: custom "URL Fetch Preview" demo app, run locally for this
  exercise, listening on `127.0.0.1:8080`
- Scanner: AI-Assisted SSRF Analyzer backend (`backend/ssrf_detector.py`)
- All requests originated from and were directed to the loopback interface
  only

## Vulnerability Detected

**NO**

## Evidence

| Signal | Description | Observed |
|---|---|---|
| Baseline established | 2 baseline requests to the unmodified target URL | status=200, length=248 bytes, time≈18ms |
| `no_candidate_parameter` | No query parameter matching common URL-fetching patterns (`url`, `target`, `dest`, …) was found | query params present: `['id']` |

Because the target URL's only parameter (`id`) does not match any known
server-side-fetch parameter pattern, the detector did not attempt
substitution probes, and instead reported this honestly rather than forcing
a finding.

## Severity

**None**

## Severity Reasoning

No severity is assigned. No SSRF-relevant behavior could be exercised
because no candidate injection point was identified in the tested endpoint.

## AI-Assisted Interpretation

*AI-Assisted Interpretation:* The detector found no query parameter that
matches common patterns applications use for server-side fetches (such as
`url`, `target`, or `redirect`). This is a reasonable and expected outcome
for an endpoint like `/profile?id=42`, which looks like a simple
record-lookup parameter rather than anything that would cause the server
to make an outbound request. This result should not be read as a full
guarantee of safety: the same endpoint could still be vulnerable through a
request body field, an HTTP header, or an undocumented parameter that this
tool does not exercise. If this endpoint is known to accept additional
parameters elsewhere in the application (for example, in a POST body), it
should be tested separately with a URL that exposes those parameters in
the query string, or via manual/source-level review.

## Recommended Remediation

- No SSRF-specific remediation is indicated for this endpoint based on the
  tested surface.
- As a general defensive baseline, continue to validate and allowlist any
  destination URLs anywhere else in the application that do perform
  server-side fetches.
- Periodically re-run this detector against new or changed endpoints as the
  application evolves.

## False-Positive Considerations

Not applicable — no positive finding was produced. The main risk here is a
**false negative**: the absence of an obvious fetch parameter does not
prove the endpoint (or another part of the application) is free of SSRF.

## Limitations

This tool only inspects query-string parameters on the URL provided by the
user. It does not test POST bodies, headers, cookies, or parameters
discovered through crawling. A "NO" result reflects the limited surface
that was actually tested, not a full security audit of the application.
