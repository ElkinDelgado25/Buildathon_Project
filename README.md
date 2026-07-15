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

## 📡 Core Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/findings/analyze` | Analyze a security finding with OpenAI |
| `GET` | `/api/v1/findings/` | List all raw findings |
| `GET` | `/api/v1/decisions/` | List all AI decisions |
| `GET` | `/api/v1/decisions/{id}` | Full decision detail with audit summary |
| `POST` | `/api/v1/audit/review` | Submit a human review |
| `GET` | `/api/v1/audit/reviews` | List all audit reviews |

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
