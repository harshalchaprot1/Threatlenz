# ThreatLenz Autonomous Notebook & ML Improvement Implementation Progress

## Project State & Audit Summary
- **Operating Environment**: Windows 11 (pwsh), Python 3.11.9, PySpark 3.5.9, scikit-learn 1.5.2, pandas 2.3.3, pyarrow 25.0.1, matplotlib 3.11.2, nbclient 0.11.0, nbformat 5.11.1.
- **Hardware Resources**: 16.39 GB Total RAM (~4.0 GB free). Spark master configured as `local[4]` with 3 GB driver memory and 8 shuffle partitions to prevent OutOfMemory/freezes.
- **Git Status**: Clean. `nginx/default.conf` uncommitted changes preserved and protected. Zero production code files mutated.
- **Dataset Provenance**: Curated CSE-CIC-IDS2018 flows in partitioned Parquet at `data/processed/flows.parquet/` (8 event dates: `2018-02-14` to `2018-03-02`). Total curated flows verified: **7,235,606 rows** across 83 columns.
- **Target Label**: `label` (canonical 14-class mapping, Benign = 0, Attacks = 1..13).
- **Leakage Auditing & Diagnostics**:
  1. Historical baseline `models/pilot_rf_model` retained `label_idx` in its feature set (`models/feature_metadata.json` importance: 0.178853). This was fixed in `clean_rf` and `clean_per_class_rf`.
  2. In `global_chronological` split strategy, attack campaigns occur on isolated calendar days. Thus, validation only saw {Benign, Bot, Infiltration} and test saw only {Benign, Bot}, leading to complete out-of-distribution evaluation collapse.
  3. Under `chronological_per_class` split strategy (70/15/15 time-block split per class), all 14 classes are represented across Train (274,385), Val (42,127), and Test (45,630) on a 5% stratified subsample (362,142 rows total).
  4. Historical reported numbers verified:
     - Baseline Val Accuracy: **47.37%** (Majority class: 64.81%, Macro-F1: 64.93%) in `clean_per_class_rf_evaluation_report.json`.
     - Baseline Held-Out Test Accuracy: **61.96%** (Majority class: 68.75%, Macro-F1: 64.23%) in `final_threshold_test_evaluation_report.json`.
     - Attack recall is high (>99%), but heavy class weighting (max 500x) creates substantial false alarms on Benign traffic (Benign recall ~22.7% on Val, ~48.3% on Test, misclassified as Infiltration and Web Brute Force).
     - Optimal decision thresholding constrained on validation (tau_infil = 0.60, tau_web = 0.35) suppressed Benign false positives on test from 16,213 down to 1,475.
     - Held-out test performance with optimized policy: **Accuracy: 92.86%**, **Macro-F1: 0.7427**, **False Alarm Rate: 4.70%**, **Attack Recall: 94.21%**, eliminating **14,738 false alarms**.

---

## Progress Log

| Phase | Action | Files Inspected / Created | Status | Evidence / Notes |
|---|---|---|---|---|
| **Phase 1: Audit** | Git status & environment audit | `nginx/default.conf`, `src/config.py`, `src/train.py`, `models/`, `reports/` | Completed | Verified uncommitted changes protected. Verified dataset (7.23M parquet). Verified historical reports and leakage fixes. |
| **Phase 2: Smoke Test** | PySpark parquet read/write verification | `test/test_parquet_smoke.py` | Completed | PySpark 3.5.9 passed in 23.66s. |
| **Phase 3: Notebook Construction** | Create `ThreatLenz_Implementation_Analysis.ipynb` | `scripts/build_analysis_notebook.py`, `ThreatLenz_Implementation_Analysis.ipynb` | Completed | Built complete reproducible 11-section analysis notebook following repository conventions. |
| **Phase 4: Notebook Execution** | Execute all notebook cells end-to-end | `ThreatLenz_Implementation_Analysis.ipynb`, `reports/plots/` | Completed | Executed via nbclient. 15 of 15 code cells executed with 0 errors. Plots generated under `reports/plots/`. |
| **Phase 5: Evaluation & Reporting** | Validation model selection and test evaluation | `reports/plots/`, `reports/final_threshold_test_evaluation_report.json` | Completed | Accuracy improved from 61.96% to 92.86% on held-out test split, Macro-F1 from 0.6423 to 0.7427, FPR dropped from 51.68% to 4.70%. |
| **Phase 6: Test Suite Validation** | Run full model and pipeline tests | `test/test_train.py`, `test/test_pipeline.py` | Completed | All 24 tests passed in 96.74s (0:01:36). |
| **Phase 7: Threshold Policy Implementation** | Implement opt-in threshold policy & unit tests | `src/train.py`, `test/test_threshold_policy.py` | Completed | Added Spark-native `apply_threshold_decision_policy`. Preserved `prediction`, writes to `adjusted_prediction`. `apply_threshold_policy=False` by default. 30 of 30 tests passed. |
| **Phase 8: Pipeline & Governance Integration** | Integrate opt-in inference, threshold policy, provenance & persistence | `src/config.py`, `src/pipeline.py`, `src/database.py`, `test/test_pipeline_inference.py` | Completed | Preserved legacy behavior (`pipeline_enable_model_inference=False`). Added operational inference, threshold gating, and ModelReliabilityAssessment from validation. Full regression suite: 34 of 34 tests passed in 145.37s. |
