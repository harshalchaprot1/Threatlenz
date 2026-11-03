import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { forkJoin, of } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { ThreatLenzApiService } from '../../core/services/api.service';
import {
  PipelineRunDetail,
  PipelineRunSummary,
  ThreatProfileSummary,
  ModelDiagnosticsResponse,
  RankedFeatureImportanceItem,
} from '../../core/models';
import {
  ReliabilityBadgeComponent,
  StatusBadgeComponent,
  FeatureImportanceChartComponent,
  ConfusionMatrixGridComponent,
} from '../../shared/components';

@Component({
  selector: 'app-governance',
  standalone: true,
  imports: [
    CommonModule,
    MatButtonModule,
    MatIconModule,
    MatProgressSpinnerModule,
    StatusBadgeComponent,
    ReliabilityBadgeComponent,
    FeatureImportanceChartComponent,
    ConfusionMatrixGridComponent,
  ],
  template: `
    <div class="gov-container">
      <!-- Header -->
      <div class="page-header">
        <h1 class="page-title">Model Governance &amp; Reliability Gating</h1>
        <p class="page-subtitle">
          Academic transparency, target-leakage mitigation history, and validation-only operational gating rules.
        </p>
      </div>

      <!-- Loading State -->
      @if (loading) {
        <div class="state-container">
          <mat-spinner diameter="40"></mat-spinner>
          <span>Querying model governance telemetry...</span>
        </div>
      }

      <!-- Error State -->
      @if (errorMessage && !loading) {
        <div class="state-container error-state" role="alert">
          <span class="material-symbols-outlined state-icon">error</span>
          <h3>Governance Telemetry Unavailable</h3>
          <p>{{ errorMessage }}</p>
          <button mat-flat-button color="accent" (click)="loadGovernanceData()">
            Retry
          </button>
        </div>
      }

      <!-- Main Governance Content -->
      @if (!loading && !errorMessage) {
        <!-- AREA A: Model Integrity & Operational State -->
        <div class="integrity-dual-grid">
          <!-- Card 1: Random Forest Evaluation -->
          <div class="integrity-card eval-card">
            <div class="integrity-header">
              <div class="header-icon-group">
                <span class="material-symbols-outlined integrity-icon icon-eval">science</span>
                <div>
                  <h3 class="integrity-title">Random Forest Evaluation</h3>
                  <span class="integrity-sub">Academic Performance Evaluation Benchmark</span>
                </div>
              </div>
              <span class="eval-status-pill">Evaluated Benchmark</span>
            </div>

            <div class="integrity-body">
              <div class="kv-grid">
                <div class="kv-item">
                  <span class="kv-label">Classification Algorithm</span>
                  <span class="kv-value">Random Forest Classifier</span>
                </div>
                <div class="kv-item">
                  <span class="kv-label">Feature Set Methodology</span>
                  <span class="kv-value">Target-Label Leakage Excluded (63 Features)</span>
                </div>
                <div class="kv-item">
                  <span class="kv-label">Validation Split Samples</span>
                  <span class="kv-value font-mono">42,127 observations</span>
                </div>
                <div class="kv-item">
                  <span class="kv-label">Held-out Test Samples</span>
                  <span class="kv-value font-mono">45,630 observations</span>
                </div>
              </div>

              <p class="integrity-note">
                Evaluated on verified Netflow statistical features. Target label indicators, metadata, and 6 collinear subflows are excluded from the feature assembler.
              </p>

              <details class="tech-accordion">
                <summary class="tech-summary">
                  <span class="material-symbols-outlined summary-icon">info</span>
                  <span>Technical Evaluation Evidence</span>
                </summary>
                <div class="tech-content">
                  <div class="tech-row">
                    <span class="tech-k">Pipeline:</span>
                    <span class="tech-v font-mono">{{ diagnosticsData?.pipeline_name }}</span>
                  </div>
                  <div class="tech-row">
                    <span class="tech-k">Evaluation Disclosure:</span>
                    <span class="tech-v">{{ diagnosticsData?.quarantine_disclosure }}</span>
                  </div>
                </div>
              </details>
            </div>
          </div>

          <!-- Card 2: Quarantined Pilot Random Forest -->
          <div class="integrity-card quarantine-card">
            <div class="integrity-header">
              <div class="header-icon-group">
                <span class="material-symbols-outlined integrity-icon icon-quarantine">gavel</span>
                <div>
                  <h3 class="integrity-title">Quarantined Random Forest Model</h3>
                  <span class="integrity-sub">Pilot Architecture Integrity Audit</span>
                </div>
              </div>
              <span class="quarantine-status-pill">Quarantined</span>
            </div>

            <div class="integrity-body">
              <div class="kv-grid">
                <div class="kv-item">
                  <span class="kv-label">Governance Status</span>
                  <span class="kv-value text-amber font-semibold">Quarantined by Governance Policy</span>
                </div>
                <div class="kv-item">
                  <span class="kv-label">Operational Inference</span>
                  <span class="kv-value text-red font-semibold">Disabled by Governance Policy</span>
                </div>
                <div class="kv-item full-width">
                  <span class="kv-label">Quarantine Reason</span>
                  <span class="kv-value">
                    Target-label leakage: indexed target label (<code class="inline-code">label_idx</code>) was present in initial pilot feature assembler.
                  </span>
                </div>
              </div>

              <p class="integrity-note alert-warning">
                <strong>Governance Safeguard:</strong> This pilot artifact is excluded from operational scoring and must not be used as an approved evaluation benchmark.
              </p>

              <details class="tech-accordion">
                <summary class="tech-summary">
                  <span class="material-symbols-outlined summary-icon">verified_user</span>
                  <span>Quarantine &amp; Verification Safeguards</span>
                </summary>
                <div class="tech-content">
                  <div class="tech-row">
                    <span class="tech-k">Automated Regression:</span>
                    <span class="tech-v">Feature exclusion safeguards assert 0 label metadata in evaluated pipelines.</span>
                  </div>
                  <div class="tech-row">
                    <span class="tech-k">Operational State:</span>
                    <span class="tech-v font-mono">INFERENCE_DISABLED_GOVERNANCE_SAFEGUARD</span>
                  </div>
                </div>
              </details>
            </div>
          </div>
        </div>

        <!-- Academic Evaluation Diagnostics: Feature Importance & Confusion Matrix -->
        <app-feature-importance-chart
          [allFeatures]="allFeatures"
          [loading]="loading"
          [errorMessage]="errorMessage"
        ></app-feature-importance-chart>

        <app-confusion-matrix-grid
          [validationMetrics]="diagnosticsData?.validation_metrics"
          [testMetrics]="diagnosticsData?.test_metrics"
          [loading]="loading"
        ></app-confusion-matrix-grid>

        <!-- Multi-Metric Validation Gating Matrix -->
        <div class="panel-card">
          <div class="panel-header">
            <span class="panel-title">Validation Gating &amp; Reliability Policy</span>
            <span class="spec-tag">Governance Standard §5</span>
          </div>

          <p class="gating-desc">
            To prevent overfitting and misleading operational confidence, model reliability ratings are evaluated
            <strong>strictly on the chronological validation split</strong>. The held-out test split is never accessed for operational policy tuning.
          </p>

          <div class="gating-grid">
            <div class="gating-card gating-high">
              <div class="gating-badge">HIGH_RELIABILITY</div>
              <p class="gating-rule">Support<sub>val</sub> &ge; 100 &amp; min(Precision, Recall, F1) &ge; 0.75</p>
              <span class="gating-action">Action: Eligible for operational threat prioritization and scoring.</span>
            </div>

            <div class="gating-card gating-evaluable">
              <div class="gating-badge">EVALUABLE</div>
              <p class="gating-rule">Support<sub>val</sub> &ge; 30 &amp; min(Precision, Recall, F1) &ge; 0.60</p>
              <span class="gating-action">Action: Permitted with cautionary confidence indicator.</span>
            </div>

            <div class="gating-card gating-unreliable">
              <div class="gating-badge">UNRELIABLE</div>
              <p class="gating-rule">Support<sub>val</sub> &lt; 30 or min metric &lt; 0.60 or metric missing</p>
              <span class="gating-action">Action: Excluded from evidence; triggers automatic VERIFY_ML advisory.</span>
            </div>

            <div class="gating-card gating-non-evaluable">
              <div class="gating-badge">NON_EVALUABLE</div>
              <p class="gating-rule">Support<sub>val</sub> = 0 (Zero validation observations)</p>
              <span class="gating-action">Action: Evaluator cannot establish statistical validity.</span>
            </div>
          </div>
        </div>

        <!-- AREA B: Category-Level Evaluation Grid with Validation / Test Switcher -->
        <div class="panel-card">
          <div class="panel-header">
            <div>
              <span class="panel-title">14-Category Evaluation &amp; Governance Verification</span>
              <p class="panel-subtitle-text">
                Official reliability is assigned strictly from validation performance. Held-out test performance is displayed as generalization evidence.
              </p>
            </div>

            <!-- Split Selector Switch -->
            <div class="split-toggle-group">
              <button
                class="split-btn"
                [class.active]="activeSplit === 'validation'"
                (click)="activeSplit = 'validation'"
              >
                Validation Split (Official Tier)
              </button>
              <button
                class="split-btn"
                [class.active]="activeSplit === 'test'"
                (click)="activeSplit = 'test'"
              >
                Held-out Test (Generalization)
              </button>
            </div>
          </div>

          <div class="table-responsive">
            <table class="gov-table">
              <thead>
                <tr>
                  <th>Threat Category</th>
                  <th>Official Reliability</th>
                  <th>Support ({{ activeSplit === 'validation' ? 'Val' : 'Test' }})</th>
                  <th>Precision</th>
                  <th>Recall</th>
                  <th>F1-Score</th>
                  <th>Specificity</th>
                  <th>Generalization Evidence</th>
                </tr>
              </thead>
              <tbody>
                @for (cat of diagnosticsData?.category_evaluations; track cat.class_name) {
                  @let metrics = activeSplit === 'validation' ? cat.validation : cat.test;
                  <tr class="main-row">
                    <td class="font-bold category-name-cell">
                      <span>{{ cat.class_name }}</span>
                    </td>
                    <td>
                      <app-reliability-badge [reliability]="cat.official_reliability_tier"></app-reliability-badge>
                    </td>
                    <td class="font-mono">{{ metrics.support | number }}</td>
                    <td class="font-mono">{{ (metrics.precision * 100).toFixed(1) }}%</td>
                    <td class="font-mono">{{ (metrics.recall * 100).toFixed(1) }}%</td>
                    <td class="font-mono">{{ (metrics.f1_score * 100).toFixed(1) }}%</td>
                    <td class="font-mono">{{ (metrics.specificity * 100).toFixed(2) }}%</td>
                    <td class="gen-cell">
                      <span class="gen-tag">{{ cat.generalization_assessment }}</span>
                    </td>
                  </tr>
                  <!-- Expandable Technical Details Drawer -->
                  <tr class="drawer-row">
                    <td colspan="8" class="drawer-cell">
                      <details class="category-details">
                        <summary class="details-summary">
                          <span class="material-symbols-outlined summary-arrow">tune</span>
                          <span>Audit Evidence &amp; Confusion Statistics ({{ cat.class_name }})</span>
                        </summary>
                        <div class="drawer-content">
                          <div class="stat-bubble">
                            <span class="bubble-k">TP</span>
                            <span class="bubble-v font-mono">{{ metrics.tp | number }}</span>
                          </div>
                          <div class="stat-bubble">
                            <span class="bubble-k">FP</span>
                            <span class="bubble-v font-mono">{{ metrics.fp | number }}</span>
                          </div>
                          <div class="stat-bubble">
                            <span class="bubble-k">FN</span>
                            <span class="bubble-v font-mono">{{ metrics.fn | number }}</span>
                          </div>
                          <div class="stat-bubble">
                            <span class="bubble-k">TN</span>
                            <span class="bubble-v font-mono">{{ metrics.tn | number }}</span>
                          </div>
                          <div class="stat-bubble">
                            <span class="bubble-k">FPR</span>
                            <span class="bubble-v font-mono">{{ (metrics.fpr * 100).toFixed(2) }}%</span>
                          </div>
                          <div class="stat-bubble">
                            <span class="bubble-k">FNR</span>
                            <span class="bubble-v font-mono">{{ (metrics.fnr * 100).toFixed(2) }}%</span>
                          </div>
                          <div class="gating-reason-box">
                            <span class="reason-label">Exact Governance Rule (§5):</span>
                            <span class="reason-text">{{ cat.gating_reason }}</span>
                          </div>
                        </div>
                      </details>
                    </td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        </div>
      }
    </div>
  `,
  styles: [`
    .gov-container {
      display: flex;
      flex-direction: column;
      gap: 24px;
    }

    .page-header {
      margin-bottom: -4px;
    }

    .page-title {
      font-size: 20px;
      font-weight: 700;
      color: var(--tl-text-primary);
      margin: 0 0 4px 0;
    }

    .page-subtitle {
      font-size: 13px;
      color: var(--tl-text-secondary);
      margin: 0;
    }

    .disclosure-card {
      background: rgba(17, 24, 39, 0.9);
      border: 1px solid rgba(6, 182, 212, 0.4);
      border-radius: 8px;
      padding: 24px;
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .disclosure-header {
      display: flex;
      align-items: center;
      gap: 14px;
    }

    /* AREA A: Dual-Grid for Model Integrity & Quarantined Architecture */
    .integrity-dual-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;

      @media (max-width: 900px) {
        grid-template-columns: 1fr;
      }
    }

    .integrity-card {
      background: var(--tl-bg-surface);
      border: 1px solid var(--tl-border);
      border-radius: 8px;
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 14px;

      &.eval-card {
        border-top: 3px solid var(--tl-cyan, #06B6D4);
      }

      &.quarantine-card {
        border-top: 3px solid #F59E0B;
      }
    }

    .integrity-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 10px;
      padding-bottom: 12px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    }

    .header-icon-group {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .integrity-icon {
      font-size: 24px;
      &.icon-eval { color: var(--tl-cyan, #06B6D4); }
      &.icon-quarantine { color: #F59E0B; }
    }

    .integrity-title {
      font-size: 14px;
      font-weight: 700;
      color: var(--tl-text-primary);
      margin: 0;
    }

    .integrity-sub {
      font-size: 11px;
      color: var(--tl-text-muted);
    }

    .eval-status-pill {
      font-size: 11px;
      font-weight: 600;
      color: var(--tl-cyan, #06B6D4);
      background: rgba(6, 182, 212, 0.1);
      border: 1px solid rgba(6, 182, 212, 0.25);
      padding: 2px 8px;
      border-radius: 4px;
    }

    .quarantine-status-pill {
      font-size: 11px;
      font-weight: 600;
      color: #F59E0B;
      background: rgba(245, 158, 11, 0.12);
      border: 1px solid rgba(245, 158, 11, 0.3);
      padding: 2px 8px;
      border-radius: 4px;
    }

    .integrity-body {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .kv-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
      background: var(--tl-bg-card);
      border: 1px solid var(--tl-border);
      border-radius: 6px;
      padding: 12px;
    }

    .kv-item {
      display: flex;
      flex-direction: column;
      gap: 2px;

      &.full-width {
        grid-column: 1 / -1;
      }
    }

    .kv-label {
      font-size: 10px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.4px;
      color: var(--tl-text-muted);
    }

    .kv-value {
      font-size: 12px;
      color: var(--tl-text-primary);
    }

    .text-amber { color: #FBBF24; }
    .text-red { color: #F87171; }
    .font-semibold { font-weight: 600; }

    .inline-code {
      font-family: monospace;
      font-size: 11px;
      background: rgba(255, 255, 255, 0.06);
      padding: 1px 4px;
      border-radius: 3px;
      color: var(--tl-cyan, #06B6D4);
    }

    .integrity-note {
      font-size: 12px;
      color: var(--tl-text-secondary);
      margin: 0;
      line-height: 1.5;

      &.alert-warning {
        padding: 8px 12px;
        background: rgba(239, 68, 68, 0.06);
        border: 1px solid rgba(239, 68, 68, 0.2);
        border-radius: 4px;
        color: #E2E8F0;

        strong {
          color: #F87171;
        }
      }
    }

    .tech-accordion {
      background: var(--tl-bg-card);
      border: 1px solid var(--tl-border);
      border-radius: 4px;
      padding: 6px 10px;
    }

    .tech-summary {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 11px;
      font-weight: 600;
      color: var(--tl-text-secondary);
      cursor: pointer;
      user-select: none;

      .summary-icon {
        font-size: 14px;
        color: var(--tl-cyan, #06B6D4);
      }
    }

    .tech-content {
      padding-top: 10px;
      margin-top: 8px;
      border-top: 1px solid rgba(255, 255, 255, 0.05);
      display: flex;
      flex-direction: column;
      gap: 6px;
    }

    .tech-row {
      display: flex;
      gap: 6px;
      font-size: 11px;
    }

    .tech-k {
      color: var(--tl-text-muted);
      font-weight: 600;
      min-width: 120px;
    }

    .tech-v {
      color: var(--tl-text-primary);
      flex: 1;
    }

    /* AREA B: Split Toggle & Per-Category Grid Styles */
    .panel-subtitle-text {
      font-size: 12px;
      color: var(--tl-text-secondary);
      margin: 2px 0 0 0;
    }

    .split-toggle-group {
      display: inline-flex;
      background: var(--tl-bg-card);
      border: 1px solid var(--tl-border);
      border-radius: 4px;
      padding: 2px;
      gap: 2px;
    }

    .split-btn {
      background: transparent;
      border: none;
      color: var(--tl-text-muted);
      font-size: 12px;
      font-weight: 600;
      padding: 5px 12px;
      border-radius: 3px;
      cursor: pointer;
      transition: all 0.2s ease;

      &.active {
        background: var(--tl-cyan, #06B6D4);
        color: #0F172A;
      }
    }

    .category-name-cell {
      color: var(--tl-text-primary);
      font-size: 13px;
    }

    .gen-cell {
      font-size: 11px;
    }

    .gen-tag {
      display: inline-block;
      font-size: 11px;
      color: var(--tl-text-secondary);
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid rgba(255, 255, 255, 0.06);
      padding: 2px 8px;
      border-radius: 3px;
    }

    .drawer-row {
      background: rgba(0, 0, 0, 0.2);
    }

    .drawer-cell {
      padding: 4px 12px 10px 12px !important;
      border-bottom: 1px solid rgba(255, 255, 255, 0.06) !important;
    }

    .category-details {
      background: rgba(255, 255, 255, 0.015);
      border: 1px solid rgba(255, 255, 255, 0.04);
      border-radius: 4px;
      padding: 6px 10px;
    }

    .details-summary {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 11px;
      color: var(--tl-text-muted);
      cursor: pointer;
      user-select: none;

      .summary-arrow {
        font-size: 14px;
        color: var(--tl-cyan, #06B6D4);
      }
    }

    .details-summary:hover {
      color: var(--tl-text-primary);
    }

    .drawer-content {
      padding-top: 10px;
      margin-top: 6px;
      border-top: 1px solid rgba(255, 255, 255, 0.04);
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 8px;
    }

    .stat-bubble {
      display: flex;
      align-items: center;
      gap: 6px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--tl-border);
      border-radius: 4px;
      padding: 3px 8px;
      font-size: 11px;
    }

    .bubble-k {
      color: var(--tl-text-muted);
      font-weight: 700;
      font-size: 10px;
    }

    .bubble-v {
      color: var(--tl-text-primary);
      font-weight: 600;
    }

    .gating-reason-box {
      flex: 1 1 100%;
      display: flex;
      align-items: baseline;
      gap: 6px;
      font-size: 11px;
      margin-top: 4px;
      padding-top: 6px;
      border-top: 1px solid rgba(255, 255, 255, 0.03);
    }

    .reason-label {
      color: var(--tl-cyan, #06B6D4);
      font-weight: 700;
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.3px;
    }

    .reason-text {
      color: var(--tl-text-secondary);
    }

    .warning-icon {
      font-size: 32px;
      color: var(--tl-cyan);
    }

    .disclosure-title-group {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }

    .disclosure-title {
      font-size: 16px;
      font-weight: 700;
      color: var(--tl-text-primary);
    }

    .disclosure-subtitle {
      font-size: 12px;
      color: var(--tl-cyan);
    }

    .disclosure-body {
      font-size: 13px;
      color: #D1D5DB;
      line-height: 1.6;

      p {
        margin: 0 0 10px 0;
      }
    }

    .code-tag {
      background: var(--tl-bg-base);
      color: var(--tl-cyan);
      font-family: monospace;
      padding: 1px 6px;
      border-radius: 4px;
      border: 1px solid var(--tl-border);
      font-size: 12px;
    }

    .safeguard-list {
      margin: 8px 0 0 0;
      padding-left: 20px;
      display: flex;
      flex-direction: column;
      gap: 8px;

      li {
        line-height: 1.5;
      }
    }

    .panel-card {
      background: var(--tl-bg-surface);
      border: 1px solid var(--tl-border);
      border-radius: 8px;
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .panel-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 10px;
    }

    .panel-title {
      font-size: 15px;
      font-weight: 700;
      color: var(--tl-text-primary);
    }

    .run-id-tag, .spec-tag, .count-tag {
      font-family: monospace;
      font-size: 11px;
      background: var(--tl-bg-card);
      border: 1px solid var(--tl-border);
      padding: 3px 8px;
      border-radius: 4px;
      color: var(--tl-text-secondary);
    }

    .governance-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      background: var(--tl-bg-card);
      border: 1px solid var(--tl-border);
      border-radius: 6px;
      padding: 16px;
    }

    .gov-item {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }

    .gov-key {
      font-size: 10px;
      color: var(--tl-text-muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
      font-weight: 700;
    }

    .gov-val {
      font-size: 13px;
      color: var(--tl-text-primary);
    }

    .status-pill {
      color: #FBBF24;
      font-weight: 600;
    }

    .quarantine-box {
      background: rgba(239, 68, 68, 0.08);
      border: 1px solid rgba(239, 68, 68, 0.3);
      border-radius: 6px;
      padding: 12px 16px;
    }

    .quarantine-label {
      font-size: 11px;
      font-weight: 700;
      color: #F87171;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      display: block;
      margin-bottom: 4px;
    }

    .quarantine-text {
      margin: 0;
      font-size: 12px;
      color: #D1D5DB;
      line-height: 1.5;
    }

    .gating-desc {
      font-size: 13px;
      color: var(--tl-text-secondary);
      margin: -8px 0 0 0;
      line-height: 1.5;
    }

    .gating-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 16px;
    }

    .gating-card {
      background: var(--tl-bg-card);
      border: 1px solid var(--tl-border);
      border-radius: 6px;
      padding: 16px;
      display: flex;
      flex-direction: column;
      gap: 10px;
    }

    .gating-badge {
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.5px;
    }

    .gating-high .gating-badge { color: #34D399; }
    .gating-evaluable .gating-badge { color: #60A5FA; }
    .gating-unreliable .gating-badge { color: #FBBF24; }
    .gating-non-evaluable .gating-badge { color: #9CA3AF; }

    .gating-rule {
      font-size: 12px;
      color: var(--tl-text-primary);
      margin: 0;
      font-weight: 500;
    }

    .gating-action {
      font-size: 11px;
      color: var(--tl-text-secondary);
      line-height: 1.4;
    }

    .table-responsive {
      overflow-x: auto;
    }

    .gov-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;

      th {
        text-align: left;
        padding: 10px 12px;
        color: var(--tl-text-muted);
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        border-bottom: 1px solid var(--tl-border);
      }

      td {
        padding: 12px;
        border-bottom: 1px solid rgba(255, 255, 255, 0.04);
        color: var(--tl-text-primary);
      }
    }

    .font-bold {
      font-weight: 600;
    }

    .font-mono {
      font-family: monospace;
    }

    .policy-cell {
      font-size: 12px;
    }

    .policy-accepted {
      color: #34D399;
      font-weight: 500;
    }

    .policy-restricted {
      color: #FBBF24;
      font-weight: 500;
    }

    .state-container {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      min-height: 300px;
      gap: 16px;
      background: var(--tl-bg-surface);
      border: 1px solid var(--tl-border);
      border-radius: 8px;
      color: var(--tl-text-secondary);
    }

    .error-state {
      .state-icon {
        font-size: 44px;
        color: #EF4444;
      }
      h3 {
        color: var(--tl-text-primary);
        margin: 0;
      }
      p {
        margin: 0 0 16px 0;
      }
    }
  `],
})
export class GovernanceComponent implements OnInit {
  loading: boolean = true;
  errorMessage: string | null = null;
  activeSplit: 'validation' | 'test' = 'validation';

  activeRun: PipelineRunDetail | null = null;
  profiles: ThreatProfileSummary[] = [];
  diagnosticsData: ModelDiagnosticsResponse | null = null;
  allFeatures: RankedFeatureImportanceItem[] = [];

  constructor(private readonly apiService: ThreatLenzApiService) {}

  ngOnInit(): void {
    this.loadGovernanceData();
  }

  loadGovernanceData(): void {
    this.loading = true;
    this.errorMessage = null;

    this.apiService.listRuns(1, 0).subscribe({
      next: (runs) => {
        const runId = runs.items.length > 0 ? runs.items[0].run_id : null;
        const requests: {
          runDetail?: any;
          profiles: any;
          diagnostics: any;
          allFeatures: any;
        } = {
          profiles: this.apiService.listProfiles({ limit: 100 }),
          diagnostics: this.apiService.getModelDiagnostics(),
          allFeatures: this.apiService.getAllFeatureImportances().pipe(
            catchError((err) => {
              console.warn('Failed to load all feature importances; governance core telemetry preserved:', err);
              return of(null);
            })
          ),
        };

        if (runId) {
          requests.runDetail = this.apiService.getRunDetail(runId);
        }

        forkJoin(requests).subscribe({
          next: (res: any) => {
            if (res.runDetail) {
              this.activeRun = res.runDetail;
            }
            this.profiles = res.profiles.items || [];
            this.diagnosticsData = res.diagnostics;
            this.allFeatures = res.allFeatures?.all_feature_importances || [];
            this.loading = false;
          },
          error: (err) => {
            this.errorMessage = err.message || 'Failed to load governance telemetry.';
            this.loading = false;
          },
        });
      },
      error: (err) => {
        this.errorMessage = err.message || 'Failed to query pipeline runs.';
        this.loading = false;
      },
    });
  }
}
