# AI-Assisted SSRF Analyzer

A defensive, evidence-based Server-Side Request Forgery (SSRF) detection
tool built for **authorized local security labs**, with AI-assisted
interpretation of scanner findings.

> **Security Notice:** Only scan systems you own or are explicitly
> authorized to test. This tool enforces a host allowlist
> (`localhost` / `127.0.0.1` / `::1` plus any hosts you explicitly
> configure) and will refuse any other target. It is not designed for, and
> must not be used for, unauthorized or production scanning.

---

## Project Overview

AI-Assisted SSRF Analyzer lets you enter an authorized local lab URL, runs
controlled, non-destructive SSRF detection checks against it, and produces
a structured security report combining deterministic evidence with a
plain-English **AI-Assisted Interpretation**.

Pipeline:

```text
URL → SSRF Detection → Evidence → Severity → AI-Assisted Interpretation → Remediation
```

## Objective

Provide a small, understandable, end-to-end example of how SSRF detection
can be approached responsibly: with an allowlist, multi-signal evidence
instead of single-signal guesses, honest confidence scoring, and clearly
labeled AI assistance that never replaces manual verification.

## Features

- Host allowlist enforced server-side before any network call is made
- Baseline-vs-probe behavioral comparison (status, length, body, timing)
- Multi-signal confidence scoring (Low / Medium / High)
- Reasoned severity scoring (None / Medium / High) — never "High" from a
  single HTTP 200
- AI-Assisted Interpretation with automatic deterministic fallback if no
  API key is configured
- Dark, responsive cybersecurity-dashboard UI (React + Tailwind)
- Structured JSON API (FastAPI) with input validation and no raw
  stack-trace leakage
- Markdown report templates for a true-positive and a safe/false-positive
  lab test

## Tech Stack

**Frontend:** React (Vite), Tailwind CSS, JavaScript
**Backend:** Python, FastAPI, requests/httpx, Pydantic
**AI:** Anthropic or OpenAI API (optional — deterministic fallback
included)

## Architecture

See [`docs/methodology.md`](docs/methodology.md) for the full pipeline
diagram and stage-by-stage explanation. In short:

```text
React frontend  ──POST /scan──▶  FastAPI backend ──▶ allowlisted local target
                ◀──JSON report──                 └──▶ AI interpretation (or fallback)
```

## Folder Structure

```text
AI-Assisted-SSRF-Analyzer/
│
├── frontend/
│   ├── package.json
│   ├── index.html
│   ├── vite.config.js
│   ├── postcss.config.js
│   ├── tailwind.config.js
│   └── src/
│       ├── main.jsx
│       ├── App.jsx
│       ├── index.css
│       ├── components/
│       │   ├── Header.jsx
│       │   ├── ScannerForm.jsx
│       │   ├── ScanResult.jsx
│       │   ├── EvidenceCard.jsx
│       │   ├── AIAnalysis.jsx
│       │   └── Remediation.jsx
│       └── services/
│           └── api.js
│
├── backend/
│   ├── main.py
│   ├── ssrf_detector.py
│   ├── models.py
│   ├── config.py
│   ├── ai_analyzer.py
│   ├── requirements.txt
│   └── .env.example
│
├── reports/
│   ├── vulnerable-target.md
│   └── safe-target.md
│
├── docs/
│   ├── SSRF-research.md
│   ├── methodology.md
│   └── limitations.md
│
├── screenshots/
│   └── .gitkeep
│
├── README.md
├── .gitignore
└── LICENSE
```

## Requirements

- Python 3.10+
- Node.js 18+ and npm
- A local, intentionally vulnerable lab application to scan (e.g. a small
  demo "URL preview/fetch" app you build or run yourself). This project
  does **not** ship a vulnerable target app — you provide one, per your
  own lab setup.

## Installation

Clone or download this repository, then set up the backend and frontend
as described below.

## Backend Setup

### Windows

```bat
cd AI-Assisted-SSRF-Analyzer\backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

### macOS / Linux

```bash
cd AI-Assisted-SSRF-Analyzer/backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` if you want to:

- Add additional authorized lab hosts (`SSRF_LAB_ALLOWED_HOSTS`)
- Configure a live AI provider (`AI_PROVIDER`, `ANTHROPIC_API_KEY` or
  `OPENAI_API_KEY`) — otherwise the deterministic fallback interpretation
  is used automatically

## Frontend Setup

```bash
cd AI-Assisted-SSRF-Analyzer/frontend
npm install
```

Optionally create `frontend/.env` to point at a non-default backend URL:

```text
VITE_API_BASE_URL=http://localhost:8000
```

## Running the Application

**Backend** (from `backend/`, with the virtual environment activated):

```bash
uvicorn main:app --reload --port 8000
```

The API will be available at `http://localhost:8000` (interactive docs at
`http://localhost:8000/docs`).

**Frontend** (from `frontend/`, in a separate terminal):

```bash
npm run dev
```

The UI will be available at `http://localhost:5173`.

## Testing Environment

Set up your own intentionally vulnerable local lab application (for
example, a small script with a `/fetch?url=...` endpoint that fetches the
given URL server-side without validation) running on `localhost`. Point
the analyzer at it. Never point this tool at a system you do not own or
have explicit authorization to test.

## Detection Methodology

See [`docs/methodology.md`](docs/methodology.md) for the complete
pipeline: validation → baseline → controlled checks → response analysis →
evidence → confidence → severity → AI interpretation → remediation →
report.

## AI-Assisted Analysis

`backend/ai_analyzer.py` sends only structured, already-collected evidence
(no raw scanning capability, no credentials, no target-selection power) to
an LLM and asks it to explain the finding in plain English, discuss false
positives, and suggest manual verification steps. All AI output is clearly
labeled **AI-Assisted Interpretation** in both the API response and the
UI, and is never treated as proof on its own. If no API key is configured,
a clearly-labeled deterministic fallback explanation is generated instead
so the tool works fully out of the box.

## Sample Results

See [`reports/vulnerable-target.md`](reports/vulnerable-target.md) and
[`reports/safe-target.md`](reports/safe-target.md) for full example
reports in the project's standard report format.

## True Positive Testing

Documented in [`reports/vulnerable-target.md`](reports/vulnerable-target.md):
a lab endpoint that accepts a `url` parameter and fetches it server-side
without validation, showing consistent status/body/timing differences
across probe variations, leading to a High-severity, High-confidence
finding.

## False Positive Testing

Documented in [`reports/safe-target.md`](reports/safe-target.md): a lab
endpoint with no server-side-fetch parameter, correctly reported as
`Vulnerability Detected: NO` with an honest explanation of why (no
candidate parameter, not "tested and proven safe").

## Limitations

See [`docs/limitations.md`](docs/limitations.md) for the full list,
including blind SSRF, authentication-protected endpoints, and other
scenarios this tool intentionally does not attempt to cover.

## Security Notice

- This tool only ever contacts hosts on its configured allowlist.
- It performs no destructive actions, credential harvesting, command
  execution, or unauthorized network discovery.
- Request timeouts and response-size caps are enforced throughout.
- No credentials are stored by the application.

## Authorization Statement

> All security testing performed for this project was conducted only
> against intentionally vulnerable applications and authorized local lab
> environments. No production or unauthorized systems were tested.

## GitHub Setup

```bash
cd AI-Assisted-SSRF-Analyzer
git init
git add .
git commit -m "Initial commit: AI-Assisted SSRF Analyzer"
git branch -M main
git remote add origin <your-repository-url>
git push -u origin main
```

Remember: `.env` is excluded via `.gitignore` — never commit real API
keys. Use `backend/.env.example` as the template for collaborators.

### Screenshots

Add screenshots to `screenshots/` after running the application locally.
Recommended captures:

1. Dashboard (empty state)
2. Scanner form in progress
3. Vulnerability result (positive finding)
4. AI-Assisted Interpretation card
5. Safe target result (negative finding)
6. Lab environment / target app
