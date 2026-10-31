# ThreatLenz Project Status & Phase Checkpoint

**Current Phase:** Phase 3: Random Forest Evaluation & Model Governance  
**Phase Status:** COMPLETED & VERIFIED  
**Date:** 2026-11-01  
**Branch:** `main`

---

## 1. Verified Deliverables & Environment State

- **Phase 3 Model Governance & 14-Category Evaluation Layer:**
  - **Sample Count Discrepancy Resolved:** Verified exact sample totals directly from the raw confusion matrices and split metadata: Validation $N = 42,127$ samples, Held-out Test $N = 45,630$ samples.
  - **Random Forest Algorithm & Terminology Alignment:** Standardized terminology to **Random Forest Evaluation** on a **leakage-excluded feature set** (63 features; zero target metadata or label indices). Eliminated artificial names such as "Clean Random Forest" or "Clean RF".
  - **Quarantined Model Disclosure:** Explicitly separated the evaluated Random Forest from the quarantined pilot Random Forest. Formally designated status as *"Operational Inference: Disabled by Governance Policy"*.
  - **14-Category Verified Arithmetic:** Derived TP, FP, FN, TN, Precision, Recall, F1, Specificity, FPR, FNR, Actual Support, and Predicted Support directly from the $14 \times 14$ raw confusion matrices for both validation and held-out test splits.
  - **Strict Governance Standard §5 Gating:** Computed official reliability tiers strictly from validation performance metrics ($\text{Support}_{\text{val}} \ge 100$ and $\min(\text{P},\text{R},\text{F1}) \ge 0.75$ for `HIGH_RELIABILITY`; $\ge 30$ and $\ge 0.60$ for `EVALUABLE`; otherwise `UNRELIABLE`). Corrected `DDoS-LOIC-UDP` ($N=14 < 30$) to `UNRELIABLE`. Displayed held-out test performance as generalization comparison without assigning an unauthorized second tier.
  - **Model Governance UI Redesign (`/governance`):**
    - *Area A (Model Integrity & Operational State):* Dual-panel card cleanly differentiating Random Forest Evaluation (leakage-excluded benchmark) from Quarantined Pilot Model (inference disabled).
    - *Area B (14-Category Evaluation Table):* Interactive table with Validation (Official Tier) vs. Held-out Test (Generalization) split toggle, official reliability badge, support, precision, recall, F1, specificity, generalization tag, and expandable technical drawer with exact TP/FP/FN/TN and governance gating rule.
    - *Area C & D:* Preserved the $14 \times 14$ confusion matrix toggle (normalized vs. raw) and Top 10 feature importance chart with leak-free disclosures.

- **Backend Read-Only Analytics Layer (`backend/app/routers/analytics.py`):**
  - Enhanced `GET /api/v1/analytics/model-diagnostics` to return structured `category_evaluations` list with validation and test `SplitClassMetrics`, official reliability tier, and exact gating reasons.
  - Updated Pydantic schemas in `backend/app/schemas_analytics.py` and TypeScript interfaces in `frontend/src/app/core/models/analytics.model.ts`.
  - Automated test suite (`test/test_analytics_router.py`) verified with 4/4 passing tests including sample counts (42,127 vs 45,630) and category evaluation assertions.

- **Phase 2 Executive Dashboard Polish (Verified):**
  - Standardized international 3-digit comma grouping (`7,235,606` total flows, `5,064,128` benign baseline flows) via Angular `en-US` `LOCALE_ID`.
  - Refined Operational Risk Assessment banner to restrained governance information styling with Target Impact Withheld disclosure.
  - Fixed Destination Port Concentration Threat Category dropdown alignment and trigger wrapper heights.

- **Container Services & Docker Audit:**
  - Implemented 4 high-performance read-only analytics endpoints backed by precomputed analytical artifacts (`reports/spark_analytics_report.json` and `reports/clean_per_class_rf_evaluation_report.json`):
    - `GET /api/v1/analytics/temporal`: Campaign observation date timeline (8 dates) and attack profile dates.
    - `GET /api/v1/analytics/ports`: Cross-category destination port concentrations across 14 categories and 12 distinct destination ports.
    - `GET /api/v1/analytics/model-diagnostics`: Top 10 Random Forest feature importances and dual $14 \times 14$ confusion matrices (Validation vs. Held-out Test split).
    - `GET /api/v1/analytics/feature-redundancy`: 9 evaluated Pearson correlation pairs (6 near-duplicates, 2 strongly collinear, 1 non-collinear).
  - Strongly typed Pydantic models in `backend/app/schemas_analytics.py` registered in `backend/app/main.py`.
  - Comprehensive unit and integration test suite (`test/test_analytics_router.py`) verified in container.

- **Frontend Data Visualization & Architecture Extensions:**
  - **Type Contracts (`frontend/src/app/core/models/analytics.model.ts`):** Complete TypeScript definitions matching backend analytics schemas.
  - **API Service Integration (`frontend/src/app/core/services/api.service.ts`):** Typed Observable methods for all 4 analytics endpoints with error propagation and reactive state handling.
  - **Dashboard Visualizations (`/dashboard`):**
    - `CapturedDayBarComponent`: Non-contiguous 8 campaign observation dates with volume tooltips.
    - `PortConcentrationCardComponent`: Destination port concentration cards with top ports, service names, and extreme concentration badges.
  - **Model Governance Visualizations (`/governance`):**
    - `FeatureImportanceChartComponent`: Clean Random Forest top 10 features descending by Gini importance with rank badges and leak-free statistical feature disclosures.
    - `ConfusionMatrixGridComponent`: $14 \times 14$ matrix with Validation vs. Held-out Test split toggle, normalized (%) vs. raw count toggle, emerald diagonal, amber/rose off-diagonal, and academic benchmark disclosures.
  - **Profile Detail Evidence Safeguards (`/profiles/:id`):**
    - Multi-factor TLRS component breakdown with visual contribution gauges (Severity 40%, Frequency 25%, Recurrence 20%).
    - Destination asset criticality clearly presented as **Unavailable / Insufficient Evidence (15%)** with operational TLRS score and risk band strictly withheld under governance policy.
    - MITRE ATT&CK Attribution Safeguards distinguishing Candidate Mappings, Unverified, and Verified attributions, with missing host telemetry checklists.
  - **Analytical Reports View (`/reports`):**
    - Added dedicated `/reports` route and navigation link in application shell.
    - `PortMatrixHeatmapComponent`: Cross-category matrix mapping all 14 threat categories against 12 destination ports with row-normalized percentages and tooltips.
    - `FeatureRedundancyTableComponent`: 9 evaluated Pearson pairs highlighting 6 near-duplicates, 2 strongly collinear pairs, and 1 non-collinear pair with engineering pruning recommendations.
    - `MitreCoverageSummaryComponent`: Enterprise summary showing candidate vs. unverified distributions across all 14 categories (0 verified due to Netflow limitations).

- **Container Services & Docker Audit:**
  - `threatlenz-db` (PostgreSQL 16 Alpine): Healthy on internal network `threatlenz-net`.
  - `threatlenz-api` (FastAPI / Python 3.11): Healthy on host port 8000. Verified reports artifact mounting and analytics router registration.
  - `threatlenz-frontend` (Angular 19 SPA + Nginx Alpine): Multi-stage container builds cleanly (`1.08 MB` total bundle). Nginx serves SPA routes via fallback and proxies `/api/` and `/health` to API container.
  - Verified end-to-end HTTP 200 connectivity across all 6 frontend routes (`/dashboard`, `/profiles`, `/profiles/:id`, `/governance`, `/runs`, `/reports`) and all API endpoints through Nginx proxy.

- **Automated Verification Results:**
  - Container test suite: 37 passed, 1 skipped across backend APIs, analytics router, database, recommendations, and TLRS formulas (`test/test_api.py`, `test/test_analytics_router.py`, `test/test_database.py`, `test/test_recommendations.py`, `test/test_tlrs.py`).
  - Production build clean: `npm run build` completed with zero TypeScript compilation errors.
  - Git tracking rules refined to ensure frontend model directories remain tracked while root ML model binaries remain ignored.

---

## 2. Known Limitations & Unresolved Issues

1. **Model Inference Quarantined:**
   - Active pipeline run operates under `QUARANTINED_TARGET_LEAKAGE` due to the pilot model leakage (`label_idx` feature contamination).
   - Clean Random Forest model artifacts exist at `models/clean_per_class_rf`, but inference remains opt-in and disabled by default until formal ML validation is completed.
2. **Missing Target Impact Telemetry:**
   - CSE-CIC-IDS2018 Netflow dataset lacks destination asset criticality and host-role telemetry. TLRS scoring defaults strictly to `insufficient_evidence` with operational risk band withheld.
3. **Host-Level PySpark Execution:**
   - Running full PySpark ETL/training pipelines requires a distributed or containerized Spark master/worker environment with Java 11/17 (not bundled into minimal backend runtime image).

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

---

## 4. Commands to Resume & Verify Environment

```powershell
# 1. Check container health status
docker-compose ps

# 2. Verify health endpoint through Nginx reverse proxy
curl.exe -s http://127.0.0.1/health

# 3. Query analytics endpoints through Nginx proxy
curl.exe -s http://127.0.0.1/api/v1/analytics/temporal
curl.exe -s http://127.0.0.1/api/v1/analytics/ports
curl.exe -s http://127.0.0.1/api/v1/analytics/model-diagnostics
curl.exe -s http://127.0.0.1/api/v1/analytics/feature-redundancy

# 4. Run backend API, analytics router, and database regression tests in container
docker exec threatlenz-api pytest -v test/test_api.py test/test_analytics_router.py test/test_database.py test/test_recommendations.py test/test_tlrs.py
```
