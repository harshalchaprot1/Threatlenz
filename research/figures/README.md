# ThreatLenz — Academic Research Figure Collection

This directory contains genuine, high-resolution visual telemetry and application interface captures from the **ThreatLenz** threat intelligence and intrusion detection platform.

> [!NOTE]
> All figures in this collection were captured directly from the live, running ThreatLenz enterprise application (PostgreSQL lakehouse, FastAPI backend, and Angular frontend served via Nginx) under benchmark execution `run_20261014_013008_2a2af9` (CSE-CIC-IDS2018 dataset). No mockups, synthetic interfaces, or developer-tool overlays were used.
>
> **Image Identity & SHA-256 Disclosure:** The collection contains **29 PNG files** representing **20 unique visual images**. Four groups of files share identical SHA-256 hashes because full-page desktop viewports co-locate multiple analytical sections within a single screen view:
> 1. `01-dashboard-overview.png` & `01-dashboard-category-distribution.png` (Category distribution cards are situated within the primary `/dashboard` viewport).
> 2. `02-profile-detail-overview.png` & `02-profile-tlrs-breakdown.png` (TLRS card and identity hero co-exist within `/profiles/30c3bcf831787d31`).
> 3. `05-feature-redundancy-table.png`, `05-feature-redundancy-explanation.png`, & `05-why-63-features.png` (The 63-feature derivation panel, glossary, and correlation table are co-rendered on `/reports?tab=redundancy` at 1920×1200).
> 4. `06-mitre-candidate-profiles.png` & `06-mitre-telemetry-limitations.png` (Candidate profiles and telemetry gap disclosure banners are co-rendered on `/reports?tab=mitre`).
> All 29 files are intentionally preserved to maintain dedicated semantic filenames for specific academic figure references.

---

## 1. Directory Structure

```text
research/figures/
├── README.md                                  # Figure index and suggested academic citations
├── 01-dashboard/                              # Executive dashboard, traffic distribution & KPIs
├── 02-profile-analysis/                       # Profile detail, TLRS risk breakdown & reliability tiers
├── 03-governance/                             # Model governance, split policy & calibration audit
├── 04-analytics-reports/                      # Destination port concentration heatmap & reports
├── 05-feature-redundancy/                     # 9-pair Pearson correlation matrix & 63-feature derivation
├── 06-mitre-attack/                           # Enterprise MITRE ATT&CK candidate mapping & telemetry gaps
└── 07-system-runs/                            # Lakehouse runs, dataset provenance & partition metadata
```

---

## 2. Research Figure Inventory & Academic Captions

### Category 01: Executive Dashboard & Traffic Telemetry

| Filename | Resolution | Application View | Suggested Academic Paper Caption |
|---|---|---|---|
| `01-dashboard/01-dashboard-overview.png` | 1920 × 1080 | `/dashboard` | **Figure 1**: ThreatLenz executive dashboard presenting enterprise network flow telemetry (7.23M flows), 14 evaluated traffic categories, active lakehouse run context, and high-level risk distribution. |
| `01-dashboard/01-dashboard-category-distribution.png` | 1920 × 1080 | `/dashboard` | **Figure 1A**: Categorical distribution of network flows across 13 attack classes and the Benign baseline (69.99% majority support). |
| `01-dashboard/01-dashboard-overview-1366x768.png` | 1366 × 768 | `/dashboard` | **Figure 1B**: Responsive desktop layout (1366×768) of the executive dashboard and KPI strip. |
| `01-dashboard/01-dashboard-overview-1024x1366.png` | 1024 × 1366 | `/dashboard` | **Figure 1C**: Tablet viewport rendering (1024×1366) demonstrating adaptive KPI card wrapping and category navigation. |
| `01-dashboard/01-dashboard-overview-390x844.png` | 390 × 844 | `/dashboard` | **Figure 1D**: Mobile viewport rendering (390×844) displaying compact telemetry headers and stacked distribution metrics. |

---

### Category 02: Profile Detail, TLRS Risk Scoring & Model Reliability

| Filename | Resolution | Application View | Suggested Academic Paper Caption |
|---|---|---|---|
| `02-profile-analysis/02-profile-detail-overview.png` | 1920 × 1080 | `/profiles/30c3bcf831787d31` | **Figure 2**: Threat profile detail view for volumetric attack campaign (DDoS-HOIC), showing executive ribbon, traffic duration, flow volume, and model reliability gating tier. |
| `02-profile-analysis/02-profile-tlrs-breakdown.png` | 1920 × 1080 | `/profiles/30c3bcf831787d31` | **Figure 2A**: Threat Level Risk Score (TLRS) assessment card displaying factor weights (Severity 40%, Frequency 25%, Recurrence 20%) with Target Impact (15%) explicitly withheld due to L4 Netflow boundaries. |
| `02-profile-analysis/02-profile-reliability-status.png` | 1920 × 1080 | `/profiles/5bd73c2681010280` | **Figure 2B**: Authoritative model evaluation tier resolution for low-support attack profile (DDoS-LOIC-UDP), correctly gated as `Unreliable (Excluded)` due to insufficient validation observations (Support = 14 < 30). |
| `02-profile-analysis/02-profile-benign-baseline.png` | 1920 × 1080 | `/profiles/ab1752ccb4059eb2` | **Figure 2C**: Negative baseline threat profile (`Benign`), displaying non-attack characteristics and `Baseline (N/A)` reliability status. |
| `02-profile-analysis/02-profile-detail-overview-1366x768.png` | 1366 × 768 | `/profiles/30c3bcf831787d31` | **Figure 2D**: Responsive laptop layout (1366×768) of the profile detail and TLRS evidence ribbon. |
| `02-profile-analysis/02-profile-detail-overview-1024x1366.png` | 1024 × 1366 | `/profiles/30c3bcf831787d31` | **Figure 2E**: Tablet layout (1024×1366) of profile analysis tabs and factor contributions. |
| `02-profile-analysis/02-profile-detail-overview-390x844.png` | 390 × 844 | `/profiles/30c3bcf831787d31` | **Figure 2F**: Mobile layout (390×844) displaying responsive profile identity hero and stacked telemetry cards. |

---

### Category 03: Model Governance & Quarantined Leakage Audit

| Filename | Resolution | Application View | Suggested Academic Paper Caption |
|---|---|---|---|
| `03-governance/03-governance-overview.png` | 1920 × 1080 | `/governance` | **Figure 3**: Model governance and architectural audit panel, displaying leakage elimination protocols, pilot model quarantine disclosure (`label_idx` target leakage), and Random Forest validation benchmarks. |
| `03-governance/03-governance-overview-1366x768.png` | 1366 × 768 | `/governance` | **Figure 3A**: Responsive desktop rendering (1366×768) of model governance boundaries and per-class reliability criteria. |
| `03-governance/03-governance-overview-1024x1366.png` | 1024 × 1366 | `/governance` | **Figure 3B**: Tablet layout (1024×1366) of the 14-class validation and test split confusion matrices. |

---

### Category 04: Analytical Reports & Port Concentration

| Filename | Resolution | Application View | Suggested Academic Paper Caption |
|---|---|---|---|
| `04-analytics-reports/04-analytics-overview.png` | 1920 × 1080 | `/reports?tab=all` | **Figure 4**: Comprehensive analytical intelligence report overview, synthesizing destination port concentrations, feature collinearity pruning, and candidate MITRE ATT&CK coverage. |
| `04-analytics-reports/04-port-matrix.png` | 1920 × 1080 | `/reports?tab=ports` | **Figure 4A**: Destination port concentration matrix showing traffic volumes and synthetic testbed port concentration patterns across attack categories. |
| `04-analytics-reports/04-analytics-overview-1366x768.png` | 1366 × 768 | `/reports?tab=all` | **Figure 4B**: Responsive laptop layout (1366×768) of analytical report tabs and summary KPI metrics. |

---

### Category 05: Feature Redundancy & 63-Feature Pipeline Derivation

| Filename | Resolution | Application View | Suggested Academic Paper Caption |
|---|---|---|---|
| `05-feature-redundancy/05-feature-redundancy-table.png` | 1920 × 1200 | `/reports?tab=redundancy` | **Figure 5**: Pearson correlation analysis across 9 representative feature pairs. Human-readable names are displayed above raw technical tags with clean `Retained in 63-Feature Pipeline` vs `Pruned from 63-Feature Pipeline` status badges. |
| `05-feature-redundancy/05-feature-redundancy-explanation.png` | 1920 × 1200 | `/reports?tab=redundancy` | **Figure 5A**: Network telemetry terminology glossary defining forward/backward directionality, flow 5-tuple, total packet length, inter-arrival time (&mu;s), and mathematical correlation thresholds. |
| `05-feature-redundancy/05-why-63-features.png` | 1920 × 1200 | `/reports?tab=redundancy` | **Figure 5B**: Evidence-based architecture breakdown deriving the 63-feature model input vector: 80 raw CSV columns &rarr; 83 lakehouse columns &rarr; 5 metadata/target exclusions &rarr; 1 shortcut port quarantine &rarr; 8 zero-variance constant features &rarr; 6 collinear subflows pruned = 63 clean features. |
| `05-feature-redundancy/05-feature-redundancy-table-1366x768.png` | 1366 × 900 | `/reports?tab=redundancy` | **Figure 5C**: Responsive laptop layout (1366×900) of the feature redundancy table and mathematical progression panel. |
| `05-feature-redundancy/05-feature-redundancy-table-1024x1366.png` | 1024 × 1366 | `/reports?tab=redundancy` | **Figure 5D**: Tablet layout (1024×1366) of the feature redundancy audit and classification filters. |
| `05-feature-redundancy/05-feature-redundancy-table-390x844.png` | 390 × 1000 | `/reports?tab=redundancy` | **Figure 5E**: Mobile layout (390×1000) showing stacked feature units and responsive horizontal table scrolling. |

---

### Category 06: MITRE ATT&CK Framework Mapping & Evidence Disclosure

| Filename | Resolution | Application View | Suggested Academic Paper Caption |
|---|---|---|---|
| `06-mitre-attack/06-mitre-candidate-profiles.png` | 1920 × 1080 | `/reports?tab=mitre` | **Figure 6**: MITRE ATT&CK enterprise coverage summary, clearly distinguishing Candidate Profiles (10), Unverified Mappings (3: Bot, Infiltration, SQL Injection), and Zero Verified Attribution (0). |
| `06-mitre-attack/06-mitre-telemetry-limitations.png` | 1920 × 1080 | `/reports?tab=mitre` | **Figure 6A**: Detailed telemetry gap disclosure highlighting the inability of Layer-4 Netflow to verify adversary attribution without host process trees, syscall audits, and EDR telemetry. |
| `06-mitre-attack/06-mitre-candidate-profiles-1366x768.png` | 1366 × 768 | `/reports?tab=mitre` | **Figure 6B**: Responsive laptop layout (1366×768) of the MITRE ATT&CK candidate coverage summary. |

---

### Category 07: System Runs & Lakehouse Provenance

| Filename | Resolution | Application View | Suggested Academic Paper Caption |
|---|---|---|---|
| `07-system-runs/07-system-runs-overview.png` | 1920 × 1080 | `/runs` | **Figure 7**: Lakehouse provenance overview displaying active ingestion run `run_20261014_013008_2a2af9`, manifest SHA-256 hash `22d6470cfb100c00`, Parquet compression ratio (67%), and 8 non-contiguous capture date partitions. |
| `07-system-runs/07-system-runs-overview-1366x768.png` | 1366 × 768 | `/runs` | **Figure 7A**: Responsive desktop rendering (1366×768) of run execution parameters and partition file counts. |

---

## 3. Capture Protocol & Verification Notes

- **Capture Tooling**: Headless Chromium (`chrome.exe --headless=new --virtual-time-budget=5000`) executed via automated orchestration.
- **Data Authenticity**: All views reflect live API responses from PostgreSQL and FastAPI (`http://localhost:80`).
- **Privacy & Safety**: Captures contain zero personal identities, internal network secrets, or API keys.
- **Reproducibility**: Interface states correspond to commit `dc671ef` with Feature Redundancy UI refinements and 63-feature pipeline explanations deployed.

