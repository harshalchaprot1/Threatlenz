import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { forkJoin } from 'rxjs';
import { ThreatLenzApiService } from '../../core/services/api.service';
import { PipelineRunDetail, PipelineRunSummary, ThreatProfileSummary } from '../../core/models';
import { ReliabilityBadgeComponent, StatusBadgeComponent } from '../../shared/components';

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
        <!-- Target Leakage Mitigation Disclosure Banner -->
        <div class="disclosure-card">
          <div class="disclosure-header">
            <span class="material-symbols-outlined warning-icon">verified_user</span>
            <div class="disclosure-title-group">
              <span class="disclosure-title">Target-Label Leakage Mitigation &amp; Quarantine History</span>
              <span class="disclosure-subtitle">Academic Integrity &amp; Trustworthy AI Verification</span>
            </div>
          </div>
          <div class="disclosure-body">
            <p>
              During initial model evaluation diagnostics, a subtle data leakage bug was identified: the indexed target label
              (<code class="code-tag">label_idx</code>) was accidentally retained in the vector assembler feature list, producing artificially inflated
              evaluation metrics.
            </p>
            <p>
              <strong>Safeguards Enforced by ThreatLenz:</strong>
            </p>
            <ul class="safeguard-list">
              <li>
                <strong>Immediate Quarantine:</strong> The compromised pilot model artifact (<code class="code-tag">models/pilot_rf_model</code>) was
                quarantined and permanently disabled from operational inference.
              </li>
              <li>
                <strong>Feature Leakage Exclusion Test:</strong> Automated tests (<code class="code-tag">test_feature_exclusion_and_leakage_safeguards</code>)
                strictly assert that <code class="code-tag">label_idx</code> and all label metadata are excluded from the training feature pipeline.
              </li>
              <li>
                <strong>Clean Model Pilot:</strong> Retrained pilot (<code class="code-tag">models/clean_per_class_rf/model</code>) operates on strictly
                leakage-free Netflow statistical features.
              </li>
            </ul>
          </div>
        </div>

        <!-- Active Run Governance Status -->
        @if (activeRun) {
          <div class="panel-card">
            <div class="panel-header">
              <span class="panel-title">Active Run Model Governance State</span>
              <span class="run-id-tag">{{ activeRun.run_id }}</span>
            </div>

            <div class="governance-grid">
              <div class="gov-item">
                <span class="gov-key">Model Artifact:</span>
                <span class="gov-val font-mono">{{ activeRun.model_artifact }}</span>
              </div>
              <div class="gov-item">
                <span class="gov-key">Model Status:</span>
                <span class="gov-val status-pill">{{ activeRun.model_status }}</span>
              </div>
              <div class="gov-item">
                <span class="gov-key">Inference Executed:</span>
                <span class="gov-val">{{ activeRun.model_inference_executed ? 'Yes' : 'No (Disabled for Governance)' }}</span>
              </div>
              <div class="gov-item">
                <span class="gov-key">Metrics Evaluation Status:</span>
                <span class="gov-val font-mono">{{ activeRun.model_evaluation_metrics_status }}</span>
              </div>
            </div>

            @if (activeRun.model_quarantine_reason) {
              <div class="quarantine-box">
                <span class="quarantine-label">Quarantine Reason:</span>
                <p class="quarantine-text">{{ activeRun.model_quarantine_reason }}</p>
              </div>
            }
          </div>
        }

        <!-- Multi-Metric Validation Gating Matrix -->
        <div class="panel-card">
          <div class="panel-header">
            <span class="panel-title">Multi-Metric Validation-Only Gating Specification</span>
            <span class="spec-tag">docs/threat-intelligence-design.md §5</span>
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

        <!-- Per-Category Operational Reliability Table -->
        <div class="panel-card">
          <div class="panel-header">
            <span class="panel-title">Threat Category Reliability Assessment</span>
            <span class="count-tag">{{ profiles.length }} Categories Mapped</span>
          </div>

          <div class="table-responsive">
            <table class="gov-table">
              <thead>
                <tr>
                  <th>Category</th>
                  <th>Attack Status</th>
                  <th>Flow Count</th>
                  <th>Recurrence</th>
                  <th>Assigned Reliability</th>
                  <th>Operational Action Policy</th>
                </tr>
              </thead>
              <tbody>
                @for (profile of profiles; track profile.snapshot_id) {
                  <tr>
                    <td class="font-bold">{{ profile.canonical_label }}</td>
                    <td>
                      <app-status-badge [status]="profile.attack_status"></app-status-badge>
                    </td>
                    <td class="font-mono">{{ profile.flow_count | number }}</td>
                    <td class="font-mono">{{ (profile.recurrence_ratio * 100).toFixed(1) }}%</td>
                    <td>
                      <app-reliability-badge [reliability]="profile.model_reliability"></app-reliability-badge>
                    </td>
                    <td class="policy-cell">
                      @if (profile.model_reliability === 'HIGH_RELIABILITY' || profile.model_reliability === 'EVALUABLE') {
                        <span class="policy-accepted">Operational Priority Active</span>
                      } @else {
                        <span class="policy-restricted">Requires Analyst Verification (VERIFY_ML)</span>
                      }
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

  activeRun: PipelineRunDetail | null = null;
  profiles: ThreatProfileSummary[] = [];

  constructor(private readonly apiService: ThreatLenzApiService) {}

  ngOnInit(): void {
    this.loadGovernanceData();
  }

  loadGovernanceData(): void {
    this.loading = true;
    this.errorMessage = null;

    this.apiService.listRuns(1, 0).subscribe({
      next: (runs) => {
        if (runs.items.length > 0) {
          const runId = runs.items[0].run_id;
          forkJoin({
            runDetail: this.apiService.getRunDetail(runId),
            profiles: this.apiService.listProfiles({ limit: 100 }),
          }).subscribe({
            next: ({ runDetail, profiles }) => {
              this.activeRun = runDetail;
              this.profiles = profiles.items;
              this.loading = false;
            },
            error: (err) => {
              this.errorMessage = err.message || 'Failed to load governance telemetry.';
              this.loading = false;
            },
          });
        } else {
          this.loading = false;
        }
      },
      error: (err) => {
        this.errorMessage = err.message || 'Failed to query pipeline runs.';
        this.loading = false;
      },
    });
  }
}
