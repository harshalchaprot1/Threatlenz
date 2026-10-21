import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { forkJoin } from 'rxjs';
import { ThreatLenzApiService } from '../../core/services/api.service';
import { HealthResponse, PipelineRunSummary, ThreatProfileSummary } from '../../core/models';
import {
  EvidenceBannerComponent,
  ReliabilityBadgeComponent,
  StatCardComponent,
  StatusBadgeComponent,
} from '../../shared/components';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [
    CommonModule,
    RouterModule,
    MatButtonModule,
    MatIconModule,
    MatProgressSpinnerModule,
    StatCardComponent,
    StatusBadgeComponent,
    ReliabilityBadgeComponent,
    EvidenceBannerComponent,
  ],
  template: `
    <div class="dashboard-container">
      <!-- Loading State -->
      @if (loading) {
        <div class="state-container">
          <mat-spinner diameter="44"></mat-spinner>
          <span class="state-label">Loading ThreatLenz intelligence dashboard...</span>
        </div>
      }

      <!-- Error State -->
      @if (errorMessage && !loading) {
        <div class="state-container error-state" role="alert">
          <span class="material-symbols-outlined state-icon">error</span>
          <h3>Dashboard Connectivity Error</h3>
          <p>{{ errorMessage }}</p>
          <button mat-flat-button color="accent" (click)="loadDashboardData()">
            <span class="material-symbols-outlined" style="font-size: 18px; margin-right: 6px;">refresh</span>
            Retry Connection
          </button>
        </div>
      }

      <!-- Main Dashboard Content -->
      @if (!loading && !errorMessage) {
        <!-- Health & Dataset Provenance Banner -->
        <div class="system-health-banner">
          <div class="health-indicator">
            <span class="material-symbols-outlined" [ngClass]="health?.status === 'healthy' ? 'icon-healthy' : 'icon-degraded'">
              {{ health?.status === 'healthy' ? 'check_circle' : 'warning' }}
            </span>
            <div class="health-meta">
              <span class="health-status">System {{ health?.status === 'healthy' ? 'Operational' : 'Degraded' }}</span>
              <span class="db-meta">
                Database: {{ health?.database?.dialect | uppercase }} ({{ health?.database?.status }})
              </span>
            </div>
          </div>

          <div class="dataset-pill" title="Evaluated Dataset Benchmark">
            <span class="material-symbols-outlined" style="font-size: 16px;">database</span>
            <span>CSE-CIC-IDS2018 Enterprise Netflow</span>
          </div>
        </div>

        <!-- Evidence Safeguard Callout -->
        <app-evidence-banner
          [isConfirmed]="false"
          [evidenceCoverage]="0.85"
          provisionalRiskBand="DIAGNOSTIC_ONLY: Heuristic Mode Active"
        ></app-evidence-banner>

        <!-- KPI Summary Cards -->
        <div class="kpi-grid">
          <app-stat-card
            title="Total Network Flows"
            [value]="totalFlowsFormatted"
            subtitle="Analyzed Netflow traffic records"
            icon="analytics"
            [badgeText]="profiles.length > 0 ? (profiles.length + ' Categories') : 'Netflow Archive'"
            badgeType="info"
          ></app-stat-card>

          <app-stat-card
            title="Active Attack Classes"
            [value]="attackCategoriesCount"
            subtitle="Distinct attack categories identified"
            icon="coronavirus"
            [badgeText]="attackCategoriesCount + ' Attack Classes'"
            badgeType="danger"
          ></app-stat-card>

          <app-stat-card
            title="Benign Baseline Flows"
            [value]="benignFlowsFormatted"
            subtitle="Verified non-adversarial baseline"
            icon="verified_user"
            badgeText="Normal Traffic"
            badgeType="success"
          ></app-stat-card>

          <app-stat-card
            title="Operational Risk Status"
            [value]="operationalRiskStatus"
            subtitle="Missing host target telemetry"
            icon="policy"
            badgeText="Evidence Policy"
            badgeType="warning"
          ></app-stat-card>
        </div>

        <!-- Active Pipeline Run Card -->
        @if (latestRun) {
          <div class="panel-card run-card">
            <div class="panel-header">
              <div class="panel-title-group">
                <span class="material-symbols-outlined panel-icon">history_edu</span>
                <span class="panel-title">Active Intelligence Pipeline Run</span>
              </div>
              <span class="run-id-pill">{{ latestRun.run_id }}</span>
            </div>

            <div class="run-details-grid">
              <div class="run-field">
                <span class="field-label">Report Name</span>
                <span class="field-val">{{ latestRun.report_name }}</span>
              </div>
              <div class="run-field">
                <span class="field-label">Pipeline Version</span>
                <span class="field-val">v{{ latestRun.pipeline_version }}</span>
              </div>
              <div class="run-field">
                <span class="field-label">Execution Duration</span>
                <span class="field-val">{{ latestRun.execution_duration_seconds }}s</span>
              </div>
              <div class="run-field">
                <span class="field-label">Source Manifest SHA-256</span>
                <span class="field-val font-mono">{{ latestRun.source_manifest_hash }}</span>
              </div>
              <div class="run-field">
                <span class="field-label">Model Status</span>
                <span class="field-val model-status-badge">{{ latestRun.model_status }}</span>
              </div>
              <div class="run-field">
                <span class="field-label">Execution Timestamp</span>
                <span class="field-val">{{ latestRun.run_timestamp | date:'medium' }}</span>
              </div>
            </div>
          </div>
        }

        <!-- Top Threat Profiles Summary Table -->
        <div class="panel-card">
          <div class="panel-header">
            <div class="panel-title-group">
              <span class="material-symbols-outlined panel-icon">grid_view</span>
              <span class="panel-title">Categorized Threat Profiles ({{ profiles.length }})</span>
            </div>
            <a mat-button color="accent" routerLink="/profiles" class="view-all-link">
              <span>View in Threat Explorer</span>
              <span class="material-symbols-outlined" style="font-size: 16px;">arrow_forward</span>
            </a>
          </div>

          <div class="table-responsive">
            <table class="preview-table">
              <thead>
                <tr>
                  <th>Category</th>
                  <th>Attack Status</th>
                  <th>Flow Count</th>
                  <th>Packets</th>
                  <th>Recurrence</th>
                  <th>Model Reliability</th>
                  <th style="text-align: right;">Action</th>
                </tr>
              </thead>
              <tbody>
                @for (profile of profiles; track profile.snapshot_id) {
                  <tr>
                    <td class="category-cell">
                      <span class="cat-label">{{ profile.canonical_label }}</span>
                      <span class="cat-raw">{{ profile.raw_label }}</span>
                    </td>
                    <td>
                      <app-status-badge [status]="profile.attack_status"></app-status-badge>
                    </td>
                    <td class="font-mono">{{ profile.flow_count | number }}</td>
                    <td class="font-mono text-muted">{{ profile.total_packets | number }}</td>
                    <td class="font-mono">{{ (profile.recurrence_ratio * 100).toFixed(1) }}%</td>
                    <td>
                      <app-reliability-badge [reliability]="profile.model_reliability"></app-reliability-badge>
                    </td>
                    <td style="text-align: right;">
                      <a
                        mat-stroked-button
                        color="primary"
                        [routerLink]="['/profiles', profile.snapshot_id]"
                        class="inspect-btn"
                      >
                        Inspect
                      </a>
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
    .dashboard-container {
      display: flex;
      flex-direction: column;
      gap: 24px;
    }

    .state-container {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      min-height: 400px;
      gap: 16px;
      text-align: center;
      background: var(--tl-bg-surface);
      border: 1px solid var(--tl-border);
      border-radius: 8px;
      padding: 32px;
    }

    .state-label {
      color: var(--tl-text-secondary);
      font-size: 14px;
    }

    .error-state {
      .state-icon {
        font-size: 48px;
        color: #EF4444;
      }
      h3 {
        color: var(--tl-text-primary);
        margin: 0;
      }
      p {
        color: var(--tl-text-secondary);
        max-width: 500px;
        margin: 0 0 16px 0;
        font-size: 13px;
      }
    }

    .system-health-banner {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
      padding: 12px 18px;
      background: var(--tl-bg-surface);
      border: 1px solid var(--tl-border);
      border-radius: 8px;
    }

    .health-indicator {
      display: flex;
      align-items: center;
      gap: 12px;

      .icon-healthy {
        color: var(--tl-emerald);
        font-size: 24px;
      }

      .icon-degraded {
        color: var(--tl-amber);
        font-size: 24px;
      }
    }

    .health-meta {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }

    .health-status {
      font-size: 13px;
      font-weight: 700;
      color: var(--tl-text-primary);
    }

    .db-meta {
      font-size: 11px;
      color: var(--tl-text-secondary);
    }

    .dataset-pill {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 11px;
      font-weight: 600;
      color: var(--tl-cyan);
      background: rgba(6, 182, 212, 0.1);
      border: 1px solid rgba(6, 182, 212, 0.25);
      padding: 4px 10px;
      border-radius: 16px;
    }

    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 16px;
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

    .panel-title-group {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .panel-icon {
      color: var(--tl-cyan);
      font-size: 22px;
    }

    .panel-title {
      font-size: 15px;
      font-weight: 700;
      color: var(--tl-text-primary);
    }

    .run-id-pill {
      font-family: monospace;
      font-size: 12px;
      background: var(--tl-bg-card);
      border: 1px solid var(--tl-border);
      padding: 2px 8px;
      border-radius: 4px;
      color: var(--tl-text-secondary);
    }

    .run-details-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      background: var(--tl-bg-card);
      border: 1px solid var(--tl-border);
      border-radius: 6px;
      padding: 16px;
    }

    .run-field {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }

    .field-label {
      font-size: 10px;
      color: var(--tl-text-muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
      font-weight: 700;
    }

    .field-val {
      font-size: 13px;
      color: var(--tl-text-primary);
      font-weight: 500;
    }

    .font-mono {
      font-family: monospace;
    }

    .model-status-badge {
      color: #FBBF24;
      font-weight: 600;
      font-size: 12px;
    }

    .table-responsive {
      overflow-x: auto;
    }

    .preview-table {
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

      tbody tr:hover {
        background: rgba(255, 255, 255, 0.02);
      }
    }

    .category-cell {
      display: flex;
      flex-direction: column;
      gap: 2px;

      .cat-label {
        font-weight: 600;
        color: var(--tl-text-primary);
      }

      .cat-raw {
        font-size: 11px;
        color: var(--tl-text-muted);
      }
    }

    .text-muted {
      color: var(--tl-text-secondary);
    }

    .inspect-btn {
      font-size: 12px;
      height: 30px;
      line-height: 30px;
      padding: 0 12px;
    }

    .view-all-link {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      font-size: 12px;
      font-weight: 600;
    }
  `],
})
export class DashboardComponent implements OnInit {
  loading: boolean = true;
  errorMessage: string | null = null;
  health: HealthResponse | null = null;
  latestRun: PipelineRunSummary | null = null;
  profiles: ThreatProfileSummary[] = [];

  constructor(private readonly apiService: ThreatLenzApiService) {}

  ngOnInit(): void {
    this.loadDashboardData();
  }

  loadDashboardData(): void {
    this.loading = true;
    this.errorMessage = null;

    forkJoin({
      health: this.apiService.getHealth(),
      runs: this.apiService.listRuns(1, 0),
      profiles: this.apiService.listProfiles({ limit: 100 }),
    }).subscribe({
      next: ({ health, runs, profiles }) => {
        this.health = health;
        this.latestRun = runs.items.length > 0 ? runs.items[0] : null;
        this.profiles = profiles.items;
        this.loading = false;
      },
      error: (err) => {
        this.errorMessage = err.message || 'Failed to load dashboard data.';
        this.loading = false;
      },
    });
  }

  get totalFlowsFormatted(): string {
    const total = this.profiles.reduce((acc, p) => acc + (p.flow_count || 0), 0);
    return total > 0 ? total.toLocaleString() : (this.loading ? '...' : '0');
  }

  get attackCategoriesCount(): number {
    if (this.latestRun && this.latestRun.attack_categories_count !== undefined) {
      return this.latestRun.attack_categories_count;
    }
    return this.profiles.filter((p) => p.attack_status === 'ATTACK').length;
  }

  get benignFlowsFormatted(): string {
    const benign = this.profiles.find((p) => p.canonical_label === 'Benign');
    return benign ? benign.flow_count.toLocaleString() : (this.loading ? '...' : '0');
  }

  get operationalRiskStatus(): string {
    if (this.latestRun) {
      return this.latestRun.target_impact_status === 'MISSING_EVIDENCE_WITHHELD'
        ? 'Withheld'
        : this.latestRun.target_impact_status;
    }
    return 'Withheld';
  }
}
