# SSRF Security Finding

## Target

`http://localhost:8080/fetch?url=http://localhost:8080/internal`

Intentionally vulnerable local lab application (e.g. a custom Flask/Express
"URL preview" demo app) running on `localhost:8080`. Not a production or
third-party system.

## Testing Environment

- Host OS: local development machine
- Lab application: custom "URL Fetch Preview" demo app, run locally for this
  exercise, listening on `127.0.0.1:8080`
- Scanner: AI-Assisted SSRF Analyzer backend (`backend/ssrf_detector.py`)
- All requests originated from and were directed to the loopback interface
  only

## Vulnerability Detected

**YES**

## Evidence

| Signal | Description | Observed |
|---|---|---|
| Baseline established | 2 baseline requests to the unmodified target URL | status=200, length=512 bytes, time≈40ms |
| `param_substitution_probe_port_1` | Substituted the `url` parameter with `http://127.0.0.1:1/` (closed low port) | status changed (200→502), body changed, time_delta_ms≈+310 |
| `param_substitution_probe_port_65535` | Substituted the `url` parameter with `http://127.0.0.1:65535/` (unassigned high port) | status changed (200→502), body changed, time_delta_ms≈+295 |

Both substitution probes produced consistent, repeatable differences from
baseline across status code, response body, and response timing —
independent signals that together suggest the application is making a
server-side HTTP request using the attacker-influenceable `url` parameter
and reflecting the outcome (including connection failures) back to the
client.

## Severity

**High**

## Severity Reasoning

Three independent signals (status code change, body change, and a timing
delta consistent with a real outbound connection attempt) agreed across
both probe variations. In a real deployment, this pattern — an
attacker-controlled destination reflected into a server-side fetch — could
allow reconnaissance of internal-only services or interaction with
internal APIs that are not meant to be reachable from outside. Severity is
rated High pending the manual verification step below.

## AI-Assisted Interpretation

*AI-Assisted Interpretation:* The evidence collected is consistent with the
`url` parameter being passed, with little or no validation, into a
server-side HTTP client. The status code flip from 200 to 502 alongside a
measurable slowdown when pointing at a closed or unusual local port is a
classic behavioral fingerprint of a real outbound connection attempt,
rather than an application simply echoing input back unmodified. That
said, this is not absolute proof: a coincidental proxy/gateway timeout
misconfigured to occur around the same threshold, or an unrelated backend
restart during testing, could in principle produce a similar pattern. The
repeatability across two different probe values raises confidence but does
not eliminate this possibility. Recommended verification is to check the
lab application's server-side code or logs to confirm it opened an
outbound connection using the substituted value.

## Recommended Remediation

- Apply strict URL validation on the `url` parameter (scheme, host, and
  port allowlisting).
- Maintain an allowlist of permitted destination hosts instead of trying to
  denylist dangerous ones.
- Block requests to loopback and link-local addresses by default unless
  explicitly required by the feature.
- Validate and cap any redirects the server-side fetch follows.
- Run the fetching service with least privilege and restricted network
  egress (network segmentation).
- Route server-side fetches through a monitored egress proxy so requests
  can be logged and constrained centrally.

## False-Positive Considerations

- A misconfigured reverse proxy timing out around the same window as the
  probes could mimic this signature. Re-run the baseline and probes at a
  different time to rule out transient infrastructure noise.
- If the lab app caches responses, a cache miss/hit boundary could also
  produce a length or timing change unrelated to SSRF. Confirm caching is
  disabled or accounted for during testing.

## Limitations

This finding is based on observable response differences only. It does
not confirm actual internal network access was achieved, and it does not
attempt to enumerate internal hosts, extract credentials, or execute code.
Manual code/log review in the lab environment is required to fully confirm
this finding.
