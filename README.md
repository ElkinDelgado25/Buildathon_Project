# 🛡️ Cybersecurity Agent — Traceable Vulnerability Analysis

An intelligent agent that analyzes SAST/DAST security findings using LLM reasoning with **full Chain of Thought traceability**. Every decision is auditable and reproducible.

## 🏗️ Architecture

```
[Sensors]  ──►  [Brain (FastAPI + LLM)]  ──►  [Traceability (PostgreSQL)]
SonarQube        Python/FastAPI                 findings table
OWASP ZAP        + Gemini / Ollama              decisions + CoT
                                                audit_log
```

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- PostgreSQL 15+
- A Gemini API key (or Ollama running locally)

### Setup

```bash
# 1. Create virtual environment
python -m venv venv
source venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment
cp .env.example .env
# Edit .env with your database URL and API keys

# 4. Create the database
createdb cybersec_agent

# 5. Run the server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### API Documentation
Once running, visit:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## 📡 Core Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/findings/analyze` | Analyze a security finding with LLM |
| `GET` | `/api/v1/findings/` | List all raw findings |
| `GET` | `/api/v1/decisions/` | List all AI decisions |
| `GET` | `/api/v1/decisions/{id}` | Full decision detail with Chain of Thought |
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
Finding (raw data) → LLM Prompt → Chain of Thought → Decision → Human Audit
     ↓                    ↓              ↓              ↓            ↓
  Immutable           Stored for     Step-by-step    Verdict +    Analyst
  in DB              reproduction    reasoning       confidence   review
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
- **LLM**: Google Gemini API / Ollama (local)
- **Migrations**: Alembic
