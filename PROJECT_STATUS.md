# ThreatLenz Project Status & Phase Checkpoint

**Current Phase:** Threat Intelligence Integration & Deployment Verification  
**Phase Status:** COMPLETED  
**Date:** 2026-10-29  
**Branch:** `main`

---

## 1. Verified Deliverables & Environment State

- **Frontend Data Visualization & Excellence (NEW):**
  - **Composition Donut Chart (`app-composition-donut-chart`):** Native SVG donut displaying exact proportion between verified Benign baseline traffic and adversarial attack classes with real-time percentage breakdowns, correct denominators, and zero fabricated slices.
  - **Category Volume Comparison (`app-category-bar-chart`):** Interactive horizontal bar chart visualizing relative flow volumes across all 14 evaluated threat categories. Includes interactive **Log Scale vs. Linear Scale** toggle to allow low-volume attacks (e.g., Infiltration, Brute Force) to be visible alongside 5M+ benign records. Features click-through deep links directly to individual Threat Profile inspection.
  - **Campaign Recurrence Heatmap (`app-recurrence-heatmap`):** Temporal persistence matrix mapping active observation units across the $H=8$ campaign days for each category, directly connecting visual persistence to the underlying TLRS formula ($R = d / H$).
  - **Production Build:** Bundle compiled cleanly via Angular CLI with zero runtime dependencies on bloated 3rd-party chart packages (`Initial total: 990.18 kB`).
- **Container Services:**
  - `threatlenz-db` (PostgreSQL 16 Alpine): Healthy on internal bridge network `threatlenz-net`. Schema migrated via `database/init/01_schema.sql`.
  - `threatlenz-api` (FastAPI / Python 3.11): Healthy on host port 8000 and internal port 8000. Verified PostgreSQL connection pool.
  - `threatlenz-frontend` (Angular 19 SPA + Nginx Alpine): Healthy on host port 80. Nginx proxies `/api/` and `/health` to `threatlenz-api:8000`, and serves the SPA bundle via `try_files` routing.
- **Frontend Live Data Integration:**
  - Audited all 5 views (`/`, `/profiles`, `/profiles/:id`, `/runs`, `/governance`). Verified zero mock data or hardcoded datasets in use; all components bind to live backend API models.
  - Confirmed 14 persisted threat profiles and active run `run_20261014_013008_2a2af9`.
  - Defensive governance verified: Target impact withheld (`MISSING_EVIDENCE_WITHHELD`), MITRE mappings candidate/unverified (`is_confirmed: false`), and advisories non-automated (`analyst_validation_required: true`).
- **Automated Verification:**
  - Backend API & DB test suite: 24 passed, 1 skipped in Docker test runner (`test/test_api.py`, `test/test_database.py`).
  - Core intelligence & TLRS test suite: 21 passed across category normalization, TLRS scoring formulas, and defensive rules.
  - All 5 frontend routes return HTTP 200 via Nginx reverse proxy.
  - API defensive error handling verified (`404` for missing runs/profiles, `405` for write methods on read-only endpoints, `422` on schema violations).

---

## 2. Known Limitations & Unresolved Issues

1. **Model Inference Quarantined:**
   - Active pipeline run operates under `QUARANTINED_TARGET_LEAKAGE` due to the pilot model leakage (`label_idx` feature contamination).
   - Clean Random Forest model artifacts exist at `models/clean_per_class_rf`, but inference remains opt-in and disabled by default until formal ML validation is completed.
2. **Missing Target Impact Telemetry:**
   - CSE-CIC-IDS2018 Netflow dataset lacks destination asset criticality and host-role telemetry. TLRS scoring defaults strictly to `insufficient_evidence` with operational risk band withheld.
3. **Windows PySpark Local Tests:**
   - Windows host test execution of PySpark requires access to `winutils.exe` with appropriate user ACLs. In containerized environments, PySpark requires dedicated worker/driver images (not bundled into the minimal API image).

---

## 3. Next Phase: ML Validation & Inference Readiness

### Objectives
1. Audit and validate clean Random Forest model artifact (`models/clean_per_class_rf/model`).
2. Verify feature assembly schema, label index mappings, and feature exclusion tests (confirming zero target leakage).
3. Evaluate per-class validation metrics, ROC-AUC, PR curves, and saved threshold policies ($\tau_{\text{infiltration}}=0.70$, $\tau_{\text{web}}=0.30$).
4. Formally certify clean model reliability before enabling operational inference in pipeline execution.

### Acceptance Criteria
- [ ] Clean model artifact passes validation checks without `label_idx` or target metadata leakage.
- [ ] Threshold decision policy validated across target minority attack classes.
- [ ] Pipeline orchestrator produces valid inferred predictions when opt-in inference flag is toggled.
- [ ] Academic integrity and governance documentation updated with clean model benchmarks.

### Immediate Tasks
1. Audit feature metadata at `models/clean_per_class_rf/feature_metadata.json` and `training_config.json`.
2. Inspect `test/test_train.py` and `test/test_threshold_policy.py`.
3. Validate performance metrics in `reports/clean_per_class_rf_evaluation_report.json` against baseline requirements.

---

## 4. Commands to Resume & Verify Environment

```powershell
# 1. Check container health status
docker compose ps

# 2. Verify health endpoint and live database connectivity
curl.exe -s http://127.0.0.1/health

# 3. Query active runs and threat profiles
curl.exe -s http://127.0.0.1/api/v1/runs
curl.exe -s "http://127.0.0.1/api/v1/profiles?limit=5"

# 4. Run backend API and database regression tests
docker exec threatlenz-api pytest -v test/test_api.py test/test_database.py
```

