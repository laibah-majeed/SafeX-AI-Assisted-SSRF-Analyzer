# Limitations

This tool is an academic, defensive SSRF detection utility. It is
intentionally scoped and has the following limitations:

- **Not a full vulnerability scanner.** It performs one narrow class of
  checks (query-parameter substitution with behavioral comparison) and
  does not cover the broader OWASP vulnerability landscape.
- **Limited detection patterns.** Only query parameters matching a fixed
  list of common names (`url`, `target`, `dest`, `redirect`, etc.) are
  tested. Applications using other parameter names will not be exercised.
- **Blind SSRF may be missed.** If the server makes a request but never
  reflects any observable difference back to the client (status, timing,
  body), this tool cannot detect it.
- **Authentication-protected endpoints may be missed.** The scanner does
  not manage sessions, cookies, or authentication flows, so protected
  endpoints may respond identically (e.g. with a login redirect)
  regardless of the underlying behavior.
- **Response-based detection can produce false positives.** Caching, rate
  limiting, dynamic content, and network jitter can all produce the kind
  of behavioral differences this tool looks for, without SSRF being
  present. See `docs/SSRF-research.md` for details.
- **Response-based detection can produce false negatives.** A well-behaved
  proxy or WAF that normalizes error responses could mask genuine SSRF
  behavior from this tool's signals.
- **Complex redirect behavior may not be fully detected.** The tool
  follows a bounded number of redirects but does not deeply analyze
  redirect chains for SSRF-relevant behavior.
- **Not suitable for production scanning.** The allowlist restricts
  targets to `localhost` / `127.0.0.1` / `::1` and explicitly configured
  lab hosts by design. It should never be pointed at production or
  third-party systems.
- **Depends on observable response behavior.** All conclusions are drawn
  from what the HTTP response reveals; the tool has no visibility into
  server-side code, logs, or network traffic beyond what it directly
  requests.
- **Not a replacement for professional penetration testing.** Findings
  from this tool should be treated as a starting point for manual
  investigation, not a certified security assessment.
