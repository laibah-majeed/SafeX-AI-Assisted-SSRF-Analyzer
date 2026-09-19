"""
config.py

Central configuration for the AI-Assisted SSRF Analyzer backend.

SECURITY NOTE:
This tool is a DEFENSIVE, EDUCATIONAL SSRF detection utility intended only
for use against systems you own or are explicitly authorized to test
(e.g. an intentionally vulnerable local lab such as DVWA, WebGoat, or a
custom lab app running on localhost).

The ALLOWED_HOSTS list below is the single source of truth for which
hosts the scanner is permitted to contact. Requests to any host not in
this list are rejected before any network call is made.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Authorized target allowlist
# ---------------------------------------------------------------------------
# Only hosts listed here may be scanned. Add additional lab hosts explicitly
# via the SSRF_LAB_ALLOWED_HOSTS environment variable (comma-separated),
# e.g. SSRF_LAB_ALLOWED_HOSTS=lab.local,192.168.56.10
DEFAULT_ALLOWED_HOSTS = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
}

_extra_hosts_env = os.getenv("SSRF_LAB_ALLOWED_HOSTS", "")
EXTRA_ALLOWED_HOSTS = {
    h.strip().lower() for h in _extra_hosts_env.split(",") if h.strip()
}

ALLOWED_HOSTS = DEFAULT_ALLOWED_HOSTS.union(EXTRA_ALLOWED_HOSTS)

# Only these schemes are permitted for the *target* URL entered by the user.
ALLOWED_SCHEMES = {"http", "https"}

# ---------------------------------------------------------------------------
# Network safety limits
# ---------------------------------------------------------------------------
REQUEST_TIMEOUT_SECONDS = float(os.getenv("SSRF_REQUEST_TIMEOUT", "5"))
MAX_RESPONSE_BYTES = int(os.getenv("SSRF_MAX_RESPONSE_BYTES", "200000"))  # 200 KB cap
MAX_REDIRECTS = int(os.getenv("SSRF_MAX_REDIRECTS", "3"))

# Number of repeated baseline requests used to establish "normal" behavior.
BASELINE_SAMPLES = int(os.getenv("SSRF_BASELINE_SAMPLES", "2"))

# ---------------------------------------------------------------------------
# AI analysis configuration
# ---------------------------------------------------------------------------
# The AI is ONLY ever given structured scanner evidence to interpret.
# It never selects targets, never triggers scans, and never receives
# credentials. If no API key is configured, a clearly-labeled deterministic
# fallback explanation is used instead so the tool still runs end-to-end.
AI_PROVIDER = os.getenv("AI_PROVIDER", "anthropic")  # "anthropic" | "openai" | "none"
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
AI_MODEL = os.getenv("AI_MODEL", "claude-sonnet-4-6")

# ---------------------------------------------------------------------------
# CORS (local dev only)
# ---------------------------------------------------------------------------
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "http://localhost:5173")
