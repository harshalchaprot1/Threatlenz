# ThreatLenz

**Trustworthy Big Data-Based Threat Analytics and Response Intelligence Platform**

ThreatLenz is a Python-based network-flow analytics and threat-intelligence project. It processes the CSE-CIC-IDS2018 dataset, evaluates supervised threat classification, creates threat profiles, maps supported categories to MITRE ATT&CK, calculates evidence-aware risk indicators, and exposes stored intelligence through a FastAPI REST API backed by PostgreSQL.

## Current Scope and Limitations

- The evaluated dataset is CSE-CIC-IDS2018 enterprise-emulation network traffic. This is not evidence of detection performance on physical IoT devices.
- The analytics and ETL pipeline uses Apache Spark and Parquet.
- The implemented supervised classifier uses Spark MLlib Random Forest.
- Threat Level Risk Score (TLRS) uses severity, frequency, recurrence, and target impact.
- When required target-impact evidence is unavailable, the complete operational risk score is withheld. Any provisional score is diagnostic only.
- The previously affected target-leakage model is quarantined. Do not treat its predictions as valid production inference.
- Advisory recommendations require analyst validation and do not automatically block traffic or remediate systems.
- Model evaluation results are pilot evidence, not proof of forward-in-time generalization or production readiness.
- The repository currently has no tracked frontend implementation or working Docker Compose configuration.

## Architecture

1. **ETL and data integrity** — load raw network-flow data, validate and normalize records, and produce curated Parquet data.
2. **Spark analytics** — analyze processed flows and summarize traffic categories.
3. **Model training and evaluation** — train and evaluate the Random Forest classifier with leakage safeguards.
4. **Threat intelligence** — create category profiles, supported MITRE ATT&CK mappings, TLRS evidence status, and defensive advisories.
5. **Persistence** — store pipeline runs and threat-intelligence records in PostgreSQL.
6. **REST API** — expose health, pipeline-run, profile, risk, MITRE, and advisory endpoints using FastAPI.

The detailed threat-intelligence design is documented in `docs/threat-intelligence-design.md`.

## Requirements

- Windows, Linux, or macOS
- Python 3.11.x
- PostgreSQL 16 or a compatible supported PostgreSQL version
- Git
- Dependencies listed in `requirements.txt`

Spark workloads may require additional memory and processing time, depending on dataset size.

## Local Setup

Run commands from the repository root.

### 1. Create and activate a virtual environment

On Windows PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If the virtual environment already exists, activate it rather than creating it again.

### 2. Configure environment variables

Create a local `.env` file from the template:

```powershell
Copy-Item .env.example .env
```

Edit `.env` and set the PostgreSQL database name, username, password, host, and port to match your local PostgreSQL setup. Never commit real credentials.

The example configuration uses:

- Host: `localhost`
- Port: `5432`
- Database: `threatlenz`
- User: `threatlenz`

These are example settings, not guaranteed to exist on a new machine.

### 3. Prepare the database

Create the PostgreSQL database and user using your approved local PostgreSQL administration method. Ensure the configured user has the required privileges.

The project exposes `init_db()` in `src/database.py` to create SQLAlchemy tables. Schema initialization changes the database, so run it only after verifying the target database and understanding the effect on existing data.

### 4. Start the API

With PostgreSQL running and `.env` configured:

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

Keep this terminal open while making API requests.

## API Endpoints

Base URL: `http://127.0.0.1:8000`

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | Service metadata |
| GET | `/health` | API and database health |
| GET | `/api/v1/runs?limit=5` | List pipeline runs |
| GET | `/api/v1/runs/{run_id}` | Retrieve a pipeline run |
| GET | `/api/v1/profiles?limit=5` | List threat profiles |
| GET | `/api/v1/profiles/{snapshot_id}` | Retrieve a profile |
| GET | `/api/v1/profiles/{snapshot_id}/risk` | Retrieve risk and evidence status |
| GET | `/api/v1/profiles/{snapshot_id}/mitre` | Retrieve MITRE mapping |
| GET | `/api/v1/profiles/{snapshot_id}/advisories` | Retrieve defensive advisories |

Interactive API documentation is available at `http://127.0.0.1:8000/docs` while the API is running. The OpenAPI schema is available at `http://127.0.0.1:8000/openapi.json`.

For Postman, select the `GET` method, enter an endpoint URL, and click **Send**. No saved collection is required.

## Run Tests

From the repository root, using the project virtual environment:

```powershell
.\.venv\Scripts\python.exe -m pytest
```

The test suite covers core ETL, analytics, database, API, pipeline, recommendation, risk-scoring, and training behavior. A passing test suite does not establish production readiness or eliminate the model's documented evaluation limitations.

## Data and Pipeline

The main pipeline modules are:

- `src/etl.py` — ETL and integrity processing; writes curated data under `data/processed/flows.parquet` and an ETL integrity report.
- `src/analytics.py` — Spark analytics.
- `src/train.py` — Random Forest training and evaluation.
- `src/pipeline.py` — threat-intelligence pipeline orchestration.
- `src/database.py` — PostgreSQL persistence and SQLAlchemy schema management.
- `backend/app/main.py` — FastAPI application.

The ETL, analytics, training, and threat-intelligence modules contain Python entry points. Inspect their configuration, input requirements, and output paths before running them. Full-data processing can be resource-intensive and may overwrite generated artifacts.

## Security and Operational Notes

- Keep `.env` and all credentials out of version control.
- Treat stored reports as historical evidence with their recorded model status.
- Do not use quarantined model artifacts for inference.
- Do not interpret missing target-impact evidence as zero impact.
- Validate recommendations with an analyst before taking action.
- Do not expose a development server publicly without appropriate authentication, authorization, and deployment hardening.

## Project Status

The backend health check, PostgreSQL connectivity, pipeline-run listing, profile listing, risk endpoint, MITRE endpoint, and advisory endpoint have been manually verified in the local development environment.

Docker deployment and frontend functionality have not been verified as working in the current repository.
