"""
ai_analyzer.py

Generates an "AI-Assisted Interpretation" of SSRF scanner evidence.

IMPORTANT SAFETY BOUNDARIES
----------------------------
- The AI is given ONLY the structured evidence object produced by
  ssrf_detector.py (status codes, lengths, timing deltas, signal names).
  It never receives raw target selection power, credentials, or the
  ability to trigger new scans.
- The AI's output is advisory only. It is always labeled
  "AI-Assisted Interpretation" and the API layer never substitutes it
  for the deterministic detection result.
- If no API key is configured, a clearly-labeled deterministic fallback
  explanation is generated instead so the tool remains fully runnable
  without any external dependency.
"""

import json
from typing import Any, Dict

from config import AI_PROVIDER, ANTHROPIC_API_KEY, OPENAI_API_KEY, AI_MODEL

SYSTEM_PROMPT = """You are a defensive application-security assistant embedded in an \
educational SSRF (Server-Side Request Forgery) detection tool used only against \
authorized local lab targets.

You will be given structured, machine-collected scanner evidence as JSON. Your job is \
to write a plain-English "AI-Assisted Interpretation" for a student/analyst reader. \
You must:
- Explain what the evidence does and does not show.
- Explicitly discuss plausible false-positive explanations (dynamic content, timeouts, \
rate limiting, redirects, authentication, network jitter).
- State the confidence level and why, in your own words.
- Suggest concrete manual verification steps appropriate for a local lab (e.g. checking \
application logs or source code) rather than further automated exploitation.
- Explain remediation briefly in plain language.
- NEVER claim certainty. Never state a finding is "confirmed" — only the human analyst \
confirms findings after manual review.
- NEVER suggest testing any host other than the one described in the evidence.
- Keep the tone academic, calm, and precise. No dramatization.

Respond with plain text only (no markdown headers), 150-250 words.
"""


def _fallback_interpretation(evidence: Dict[str, Any]) -> str:
    """
    Deterministic, template-based interpretation used when no AI provider
    is configured. Ensures the tool is fully functional out of the box.
    """
    vuln = evidence.get("vulnerability_detected")
    confidence = evidence.get("confidence", "Low")
    severity = evidence.get("severity", "None")
    signal_count = len(evidence.get("evidence", []))

    if vuln:
        return (
            f"[AI-Assisted Interpretation — deterministic fallback, no LLM configured] "
            f"The detector flagged this target as a potential SSRF candidate with "
            f"{confidence} confidence and {severity} severity, based on {signal_count} "
            f"recorded evidence signals showing measurable differences between the "
            f"baseline request and the local-loopback substitution probes (response "
            f"length, status code, response body, and/or timing). This pattern is "
            f"consistent with the application making an attacker-influenceable "
            f"server-side request, but it is not proof: dynamic page content, caching, "
            f"rate limiting, or coincidental timing variance can produce similar "
            f"differences. Before treating this as confirmed, manually inspect the lab "
            f"application's source code or server logs to verify that the substituted "
            f"parameter value actually reached an outbound HTTP client server-side. "
            f"Recommended remediation includes validating and allowlisting any "
            f"user-influenceable destination URLs, rejecting requests to loopback and "
            f"link-local addresses unless explicitly required, and validating redirect "
            f"targets rather than following them blindly. Configure an LLM API key in "
            f"backend/.env to replace this fallback with a live, evidence-grounded "
            f"AI explanation."
        )
    return (
        f"[AI-Assisted Interpretation — deterministic fallback, no LLM configured] "
        f"The detector did not find sufficient evidence to flag this target as SSRF. "
        f"Confidence is {confidence}: the observed responses to the local-loopback "
        f"substitution probes were not meaningfully different from the established "
        f"baseline, which suggests the tested parameter either does not trigger a "
        f"server-side fetch, or the application has protections (validation, "
        f"allowlisting, or network egress restrictions) that prevent the substituted "
        f"value from changing observable behavior. This is not a full guarantee of "
        f"safety — SSRF can still exist via other parameters, headers, request bodies, "
        f"or blind (non-response-reflecting) request paths that this tool does not "
        f"exercise. Consider manual source review and testing additional parameters "
        f"as follow-up. Configure an LLM API key in backend/.env to replace this "
        f"fallback with a live, evidence-grounded AI explanation."
    )


def _call_anthropic(evidence_json: str) -> str:
    import httpx

    resp = httpx.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={
            "model": AI_MODEL,
            "max_tokens": 500,
            "system": SYSTEM_PROMPT,
            "messages": [
                {"role": "user", "content": f"Scanner evidence JSON:\n{evidence_json}"}
            ],
        },
        timeout=20,
    )
    resp.raise_for_status()
    data = resp.json()
    text_parts = [block["text"] for block in data.get("content", []) if block.get("type") == "text"]
    return "AI-Assisted Interpretation: " + "\n".join(text_parts).strip()


def _call_openai(evidence_json: str) -> str:
    import httpx

    resp = httpx.post(
        "https://api.openai.com/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json",
        },
        json={
            "model": "gpt-4o-mini",
            "max_tokens": 500,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Scanner evidence JSON:\n{evidence_json}"},
            ],
        },
        timeout=20,
    )
    resp.raise_for_status()
    data = resp.json()
    text = data["choices"][0]["message"]["content"]
    return "AI-Assisted Interpretation: " + text.strip()


def generate_ai_interpretation(evidence: Dict[str, Any]) -> str:
    """
    Produce a labeled AI-Assisted Interpretation string from structured
    scanner evidence. Falls back to a deterministic explanation if no
    provider/API key is configured or if the call fails for any reason.
    """
    evidence_json = json.dumps(evidence, default=str, indent=2)

    try:
        if AI_PROVIDER == "anthropic" and ANTHROPIC_API_KEY:
            return _call_anthropic(evidence_json)
        if AI_PROVIDER == "openai" and OPENAI_API_KEY:
            return _call_openai(evidence_json)
    except Exception as exc:  # noqa: BLE001 - always fall back safely
        return (
            _fallback_interpretation(evidence)
            + f"\n\n(Note: live AI call failed with '{type(exc).__name__}', "
            "showing deterministic fallback instead.)"
        )

    return _fallback_interpretation(evidence)
