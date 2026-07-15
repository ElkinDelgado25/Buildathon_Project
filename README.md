# 🛡️ Cybersecurity Agent — DevSecOps Audit Assistant

An intelligent agent that analyzes SAST/DAST security findings with OpenAI and
creates an evidence-based audit record for human review.

## 🏗️ Architecture

```
[Sensors]  ──►  [Brain (FastAPI + OpenAI)]  ──►  [Traceability (PostgreSQL)]
SonarQube        Python/FastAPI                   findings table
OWASP ZAP        + GPT model                      decisions + audit summary
                                                   audit_log
```

## 🚀 Quick Start

### Prerequisites
- Docker Desktop with Docker Compose
- An OpenAI API key with access to the selected model

### Setup

```powershell
# 1. Create the local environment file
Copy-Item .env.example .env

# 2. Set OPENAI_API_KEY in .env

# 3. Start PostgreSQL and the API
docker compose up --build
```

### API Documentation
Once running, visit:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **Health check**: http://localhost:8000/health

### Run the API outside Docker

If you prefer to run FastAPI from your machine while PostgreSQL runs in Docker:

```powershell
docker compose up -d postgres
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Use the `localhost` database URL already provided in `.env.example` for this mode.

### Deploy on Render

The repository includes `render.yaml`, which creates a Docker web service and
a managed PostgreSQL database. It is intended for the hackathon MVP; the CLI
remains the primary user interface.

1. Push this repository to GitHub.
2. In Render, create a **Blueprint** and select the repository.
3. Set `OPENAI_API_KEY` when Render prompts for the secret, then apply the Blueprint.
4. After deployment, copy the public service URL and point the CLI to it:

```powershell
python -m app.cli --api-url https://your-service.onrender.com health
```

For a fresh MVP database, Render starts with `APP_ENV=development` so the API
creates its tables. Before production use, replace this bootstrap behavior
with versioned Alembic migrations and add CLI/API-key authentication.

The current `docker-compose.yml` is for local development only. SonarQube and
OWASP ZAP are not deployed by this Blueprint; configure their reachable URLs
and tokens in Render only when the scanner integrations are ready.

## 📡 Core Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/findings/analyze` | Analyze a security finding with OpenAI |
| `GET` | `/api/v1/findings/` | List all raw findings |
| `GET` | `/api/v1/decisions/` | List all AI decisions |
| `GET` | `/api/v1/decisions/{id}` | Full decision detail with audit summary |
| `POST` | `/api/v1/audit/review` | Submit a human review |
| `GET` | `/api/v1/audit/reviews` | List all audit reviews |
| `POST` | `/api/v1/audits/plan` | Create a bounded SAST/DAST audit plan |
| `POST` | `/api/v1/audits/{id}/findings` | Attach scanner evidence and evaluate policy |
| `GET` | `/api/v1/audits/{id}/trace` | Retrieve normalized evidence and the policy decision |
| `GET` | `/api/v1/rules` | List the cached SonarQube/ZAP rule catalog |
| `POST` | `/api/v1/rules/sync/{source}` | Synchronize configured scanner rules |

## 💻 Command-line client

With the API running, the project can be operated without Swagger or `curl`:

```bash
# Check the service
python -m app.cli health

# SOC-style overview (similar to a fastfetch status screen)
python -m app.cli dashboard

# Analyze a SonarQube finding stored as a JSON object
python -m app.cli findings analyze --source sonarqube --file finding.json

# Browse the traceability data
python -m app.cli findings list --source sonarqube
python -m app.cli decisions list
python -m app.cli decisions get DECISION_ID

# Record and inspect a human review
python -m app.cli audit review DECISION_ID --by alice --verdict agree --comment "Verified"
python -m app.cli audit decision DECISION_ID

# Plan a bounded audit and attach a scanner finding
python -m app.cli audits plan demo-repository --type sast
python -m app.cli audits add-finding AUDIT_ID --source sonarqube --file finding.json
python -m app.cli audits trace AUDIT_ID

# Synchronize and inspect configured scanner rules
python -m app.cli rules sync sonarqube
python -m app.cli rules list --source sonarqube
```

The default API URL is `http://localhost:8000`. Override it with the global
option `--api-url` or the `CYBERSEC_API_URL` environment variable. Add the
global `--json` option before the command to obtain machine-readable output:

```bash
python -m app.cli --api-url http://localhost:8000 --json decisions list
```

Run `python -m app.cli --help` (or add `--help` to any subcommand) for the full
command reference. Finding input accepts `--payload '{...}'`, `--file PATH`, or
`--file -` for standard input.

For an optional logo rendered as terminal art, install `chafa` and place an image
at `assent/Logo-terminal.png` (a transparent-background PNG) or `assent/Logo.png`.
The `dashboard` command uses it automatically and falls back to the built-in ASCII
banner when it is unavailable.

## 🧪 Example: Analyze a Simulated Finding

```bash
curl -X POST http://localhost:8000/api/v1/findings/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "source": "sonarqube",
    "raw_payload": {
      "rule": "python:S5131",
      "severity": "CRITICAL",
      "component": "src/api/auth.py",
      "line": 42,
      "message": "Change this code to not construct SQL queries directly from user-controlled data.",
      "type": "VULNERABILITY",
      "tags": ["sql-injection", "cwe-89"]
    }
  }'
```

## 🔍 Traceability Flow

```
Finding (raw data) → LLM prompt → Audit summary → Decision → Human audit
     ↓                  ↓              ↓              ↓            ↓
  Immutable         Stored for    Evidence-based   Verdict +    Analyst
  in DB            reproduction     rationale      confidence   review
```

## 📁 Project Structure

```
app/
├── main.py              # FastAPI entry point
├── config.py            # Environment configuration
├── database.py          # Async SQLAlchemy setup
├── models/              # ORM models (Finding, Decision, AuditLog)
├── schemas/             # Pydantic request/response schemas
├── services/            # Business logic (LLM + Analysis orchestration)
├── sensors/             # SonarQube & ZAP integrations
└── routers/             # API route handlers
```

## 🛠️ Tech Stack

- **Backend**: Python 3.11+ / FastAPI
- **Database**: PostgreSQL + SQLAlchemy (async)
- **LLM**: OpenAI API
- **Migrations**: Alembic
