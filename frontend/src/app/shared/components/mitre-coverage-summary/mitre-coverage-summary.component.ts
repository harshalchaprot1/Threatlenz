import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MitreMappingResponse } from '../../../core/models';

export interface MitreProfileSummaryItem {
  category: string;
  mapping: MitreMappingResponse;
}

@Component({
  selector: 'app-mitre-coverage-summary',
  standalone: true,
  imports: [CommonModule, MatProgressSpinnerModule],
  template: `
    <div class="mitre-summary-card">
      <div class="summary-header">
        <div class="header-titles">
          <span class="summary-title">{{ title }}</span>
          <span class="summary-subtitle">{{ subtitle }}</span>
        </div>
        <div class="coverage-metrics">
          <div class="metric-pill candidate-pill">
            <span class="metric-val">{{ candidateCount }}</span>
            <span class="metric-label">Candidate Mappings</span>
          </div>
          <div class="metric-pill unverified-pill">
            <span class="metric-val">{{ unverifiedCount }}</span>
            <span class="metric-label">Unverified Telemetry</span>
          </div>
          <div class="metric-pill verified-pill">
            <span class="metric-val">{{ verifiedCount }}</span>
            <span class="metric-label">Verified Attribution</span>
          </div>
          <div class="metric-pill na-pill">
            <span class="metric-val">{{ naCount }}</span>
            <span class="metric-label">Benign Baseline</span>
          </div>
        </div>
      </div>

      <!-- Loading State -->
      @if (loading) {
        <div class="state-container">
          <mat-spinner diameter="36"></mat-spinner>
          <span>Querying enterprise MITRE mapping telemetry across 14 categories...</span>
        </div>
      }

      <!-- Error State -->
      @if (errorMessage && !loading) {
        <div class="state-container error-state">
          <span class="material-symbols-outlined state-icon">error</span>
          <span>{{ errorMessage }}</span>
        </div>
      }

      <!-- Attribution Evidence Policy Banner -->
      @if (!loading && !errorMessage && items.length > 0) {
        <div class="evidence-governance-box">
          <span class="material-symbols-outlined gov-icon">policy</span>
          <div class="gov-text">
            <strong>Attribution Policy Safeguard:</strong>
            ThreatLenz maps behavioral Netflow heuristics strictly as <em>Candidate Mappings</em> ({{ candidateCount }}) or <em>Unverified</em> ({{ unverifiedCount }}). Zero profiles are designated as <em>Verified Attribution</em> (0 of 14) because Netflow statistics lack required host audit logs, process lineages, and memory payload artifacts.
          </div>
        </div>

        <div class="table-responsive">
          <table class="mitre-table">
            <thead>
              <tr>
                <th>Threat Category</th>
                <th>ATT&CK Technique</th>
                <th>Enterprise Tactic</th>
                <th>Mapping Status</th>
                <th>Attribution State</th>
                <th>Missing Telemetry Artifacts</th>
              </tr>
            </thead>
            <tbody>
              @for (item of items; track item.category) {
                <tr>
                  <td class="font-bold category-name">{{ item.category }}</td>
                  <td class="tech-cell font-mono">
                    @if (item.mapping.technique_id) {
                      <a
                        [href]="'https://attack.mitre.org/techniques/' + item.mapping.technique_id.replace('.', '/')"
                        target="_blank"
                        rel="noopener"
                        class="tech-link"
                      >
                        <span class="tech-id">{{ item.mapping.technique_id }}</span>
                        <span class="material-symbols-outlined link-icon">open_in_new</span>
                      </a>
                      <span class="tech-name">{{ item.mapping.technique_name }}</span>
                    } @else {
                      <span class="tech-none font-mono">None</span>
                    }
                  </td>
                  <td class="tactic-cell">{{ item.mapping.tactic || 'Not Applicable' }}</td>
                  <td>
                    <span class="status-badge" [ngClass]="'status-' + item.mapping.mapping_status">
                      {{ formatStatus(item.mapping.mapping_status) }}
                    </span>
                  </td>
                  <td>
                    <span class="unconfirmed-badge" [class.confirmed-badge]="item.mapping.is_confirmed">
                      {{ item.mapping.is_confirmed ? 'VERIFIED' : 'UNCONFIRMED' }}
                    </span>
                  </td>
                  <td class="telemetry-cell">
                    @if (item.mapping.missing_telemetry && item.mapping.missing_telemetry.length > 0) {
                      <div class="missing-items-wrap">
                        @for (tel of item.mapping.missing_telemetry; track tel) {
                          <span class="tel-tag" [attr.title]="tel">{{ tel }}</span>
                        }
                      </div>
                    } @else {
                      <span class="tel-none text-muted">Baseline (None required)</span>
                    }
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      }

      @if (!loading && !errorMessage && items.length === 0) {
        <div class="state-container">
          <span class="material-symbols-outlined state-icon">hub</span>
          <span>No MITRE ATT&CK candidate mapping records available.</span>
        </div>
      }
    </div>
  `,
  styles: [`
    .mitre-summary-card {
      background: var(--tl-bg-surface, #1E293B);
      border: 1px solid var(--tl-border, rgba(255, 255, 255, 0.08));
      border-radius: 8px;
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .summary-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 14px;
    }

    .header-titles {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }

    .summary-title {
      font-size: 16px;
      font-weight: 700;
      color: var(--tl-text-primary, #F8FAFC);
    }

    .summary-subtitle {
      font-size: 12px;
      color: var(--tl-text-secondary, #94A3B8);
    }

    .coverage-metrics {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }

    .metric-pill {
      display: flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 11px;
      border: 1px solid transparent;

      &.candidate-pill {
        background: rgba(59, 130, 246, 0.12);
        color: #93C5FD;
        border-color: rgba(59, 130, 246, 0.3);
      }

      &.unverified-pill {
        background: rgba(245, 158, 11, 0.12);
        color: #FDE68A;
        border-color: rgba(245, 158, 11, 0.3);
      }

      &.verified-pill {
        background: rgba(16, 185, 129, 0.12);
        color: #6EE7B7;
        border-color: rgba(16, 185, 129, 0.3);
      }

      &.na-pill {
        background: rgba(107, 114, 128, 0.12);
        color: #D1D5DB;
        border-color: rgba(107, 114, 128, 0.3);
      }

      .metric-val {
        font-weight: 700;
        font-size: 13px;
        font-family: monospace;
      }

      .metric-label {
        font-size: 11px;
      }
    }

    .evidence-governance-box {
      display: flex;
      align-items: flex-start;
      gap: 12px;
      background: rgba(6, 182, 212, 0.08);
      border: 1px solid rgba(6, 182, 212, 0.3);
      border-radius: 6px;
      padding: 12px 16px;

      .gov-icon {
        font-size: 22px;
        color: var(--tl-cyan, #06B6D4);
        margin-top: 1px;
      }

      .gov-text {
        font-size: 12px;
        color: #D1D5DB;
        line-height: 1.5;

        strong {
          color: var(--tl-cyan, #06B6D4);
        }
      }
    }

    .table-responsive {
      overflow-x: auto;
      border: 1px solid var(--tl-border, rgba(255, 255, 255, 0.08));
      border-radius: 6px;
    }

    .mitre-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;

      th {
        text-align: left;
        padding: 10px 12px;
        background: rgba(15, 23, 42, 0.8);
        color: var(--tl-text-muted, #64748B);
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        border-bottom: 1px solid var(--tl-border, rgba(255, 255, 255, 0.08));
      }

      td {
        padding: 10px 12px;
        border-bottom: 1px solid rgba(255, 255, 255, 0.04);
        color: var(--tl-text-primary, #F8FAFC);
        vertical-align: middle;
      }
    }

    .category-name {
      color: var(--tl-text-primary, #F8FAFC);
      font-weight: 600;
      white-space: nowrap;
    }

    .tech-cell {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }

    .tech-link {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      color: var(--tl-cyan, #06B6D4);
      text-decoration: none;
      font-weight: 700;
      font-size: 12px;

      &:hover {
        text-decoration: underline;
      }

      .link-icon {
        font-size: 13px;
      }
    }

    .tech-name {
      font-size: 11px;
      color: var(--tl-text-secondary, #94A3B8);
      font-family: inherit;
    }

    .tech-none {
      color: var(--tl-text-muted, #64748B);
      font-size: 11px;
    }

    .tactic-cell {
      color: var(--tl-text-secondary, #94A3B8);
      font-size: 11px;
    }

    .status-badge {
      display: inline-block;
      font-size: 10px;
      font-weight: 700;
      padding: 2px 7px;
      border-radius: 4px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      white-space: nowrap;

      &.status-candidate {
        background: rgba(59, 130, 246, 0.15);
        color: #60A5FA;
        border: 1px solid rgba(59, 130, 246, 0.3);
      }

      &.status-unverified {
        background: rgba(245, 158, 11, 0.15);
        color: #FBBF24;
        border: 1px solid rgba(245, 158, 11, 0.3);
      }

      &.status-verified {
        background: rgba(16, 185, 129, 0.15);
        color: #34D399;
        border: 1px solid rgba(16, 185, 129, 0.3);
      }

      &.status-not_applicable {
        background: rgba(107, 114, 128, 0.15);
        color: #9CA3AF;
        border: 1px solid rgba(107, 114, 128, 0.3);
      }
    }

    .unconfirmed-badge {
      display: inline-block;
      font-size: 10px;
      font-weight: 700;
      padding: 2px 6px;
      border-radius: 4px;
      background: rgba(239, 68, 68, 0.12);
      color: #F87171;
      border: 1px solid rgba(239, 68, 68, 0.25);
      white-space: nowrap;

      &.confirmed-badge {
        background: rgba(16, 185, 129, 0.12);
        color: #34D399;
        border-color: rgba(16, 185, 129, 0.25);
      }
    }

    .telemetry-cell {
      max-width: 280px;
    }

    .missing-items-wrap {
      display: flex;
      flex-wrap: wrap;
      gap: 4px;
    }

    .tel-tag {
      font-size: 10px;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.08);
      padding: 1px 6px;
      border-radius: 3px;
      color: #D1D5DB;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      max-width: 140px;
    }

    .tel-none {
      font-size: 11px;
    }

    .font-mono {
      font-family: monospace;
    }

    .font-bold {
      font-weight: 600;
    }

    .text-muted {
      color: var(--tl-text-muted, #64748B);
    }

    .state-container {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      min-height: 180px;
      gap: 12px;
      color: var(--tl-text-secondary, #94A3B8);
      font-size: 13px;
    }

    .error-state {
      color: #EF4444;
      .state-icon { font-size: 32px; }
    }
  `],
})
export class MitreCoverageSummaryComponent {
  @Input() title: string = 'Enterprise MITRE ATT&CK Mapping & Attribution Telemetry Evidence';
  @Input() subtitle: string = 'Candidate tactical techniques and missing telemetry evidence across 14 threat categories';
  @Input() loading: boolean = false;
  @Input() errorMessage: string | null = null;

  @Input() set profilesWithMitre(data: MitreProfileSummaryItem[] | null | undefined) {
    this.items = data || [];
    this.recalculateCounts();
  }

  items: MitreProfileSummaryItem[] = [];

  candidateCount: number = 0;
  unverifiedCount: number = 0;
  verifiedCount: number = 0;
  naCount: number = 0;

  private recalculateCounts(): void {
    this.candidateCount = 0;
    this.unverifiedCount = 0;
    this.verifiedCount = 0;
    this.naCount = 0;

    for (const item of this.items) {
      const status = item.mapping?.mapping_status?.toLowerCase();
      if (status === 'candidate') this.candidateCount++;
      else if (status === 'unverified') this.unverifiedCount++;
      else if (status === 'verified') this.verifiedCount++;
      else if (status === 'not_applicable') this.naCount++;
    }
  }

  formatStatus(status: string): string {
    switch (status?.toLowerCase()) {
      case 'candidate': return 'Candidate';
      case 'unverified': return 'Unverified';
      case 'verified': return 'Verified';
      case 'not_applicable': return 'Not Applicable';
      default: return status || 'Unknown';
    }
  }
}

