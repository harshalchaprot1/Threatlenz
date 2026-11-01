import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MitreMappingResponse } from '../../../core/models';

export interface MitreProfileSummaryItem {
  category: string;
  mapping: MitreMappingResponse;
}

export type MitreFilter = 'ALL' | 'CANDIDATE' | 'UNVERIFIED' | 'BENIGN';

@Component({
  selector: 'app-mitre-coverage-summary',
  standalone: true,
  imports: [CommonModule, FormsModule, MatProgressSpinnerModule],
  template: `
    <div class="mitre-summary-card">
      <!-- Section Header -->
      <div class="summary-header">
        <div class="header-titles">
          <div class="title-row">
            <span class="summary-title">{{ title }}</span>
            <span class="mitre-pill">Enterprise MITRE ATT&CK Matrix</span>
          </div>
          <span class="summary-subtitle">{{ subtitle }}</span>
        </div>

        <div class="header-controls">
          <!-- Filter by Status -->
          <div class="filter-group">
            <label for="mitreFilter" class="filter-label">Filter Status:</label>
            <div class="select-wrapper">
              <select
                id="mitreFilter"
                class="filter-select"
                [ngModel]="selectedFilter"
                (ngModelChange)="onFilterChange($event)"
              >
                <option value="ALL">All Categories (14)</option>
                <option value="CANDIDATE">Candidate Profiles (10)</option>
                <option value="UNVERIFIED">Unverified Mappings (3)</option>
                <option value="BENIGN">Benign Baseline (1)</option>
              </select>
            </div>
            @if (selectedFilter !== 'ALL') {
              <button class="reset-filter-btn" (click)="resetFilter()" title="Reset to all mappings">
                <span class="material-symbols-outlined reset-icon">close</span>
                <span>Reset</span>
              </button>
            }
          </div>
        </div>
      </div>

      <!-- Global Telemetry Boundary Disclosure -->
      <div class="boundary-disclosure-panel">
        <div class="disclosure-header">
          <span class="material-symbols-outlined boundary-icon">policy</span>
          <div class="disclosure-title-group">
            <span class="disclosure-title">Global Telemetry Boundary &amp; Attribution Safeguard</span>
            <span class="safeguard-badge">0 Verified Attributions</span>
          </div>
        </div>
        <p class="disclosure-body">
          Current mappings represent <strong>candidate technique profiles</strong> based exclusively on L4 Netflow statistical behavioral indicators. Because the evaluated CSE-CIC-IDS2018 dataset lacks host process execution trees, endpoint EDR logs, decrypted application payloads, and server authentication logs, <strong>zero mappings have verified adversary attribution</strong>. Netflow telemetry alone is insufficient to confirm tactical execution.
        </p>

        <!-- Status Metrics Bar -->
        <div class="coverage-metrics">
          <div class="metric-pill candidate-pill">
            <span class="metric-val">{{ candidateCount }}</span>
            <span class="metric-label">Candidate Profiles</span>
          </div>
          <div class="metric-pill unverified-pill">
            <span class="metric-val">{{ unverifiedCount }}</span>
            <span class="metric-label">Unverified Mappings</span>
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

      <!-- Mappings Table -->
      @if (!loading && !errorMessage && filteredItems.length > 0) {
        <div class="table-responsive">
          <table class="mitre-table">
            <thead>
              <tr>
                <th class="col-cat">Threat Category</th>
                <th class="col-tech">ATT&amp;CK Technique</th>
                <th class="col-tactic">Enterprise Tactic</th>
                <th class="col-status">Attribution Status</th>
                <th class="col-telemetry">Missing Telemetry for Verification</th>
              </tr>
            </thead>
            <tbody>
              @for (item of filteredItems; track item.category) {
                <tr>
                  <td class="category-cell">
                    <span class="cat-label font-bold">{{ item.category }}</span>
                  </td>

                  <td class="tech-cell font-mono">
                    @if (item.mapping.technique_id) {
                      <div class="tech-group">
                        <a
                          [href]="'https://attack.mitre.org/techniques/' + item.mapping.technique_id.replace('.', '/')"
                          target="_blank"
                          rel="noopener"
                          class="tech-link"
                          title="View on MITRE ATT&CK Framework"
                        >
                          <span class="tech-id">{{ item.mapping.technique_id }}</span>
                          <span class="material-symbols-outlined link-icon">open_in_new</span>
                        </a>
                        <span class="tech-name">{{ item.mapping.technique_name }}</span>
                      </div>
                    } @else {
                      <span class="tech-none font-mono">None (Baseline)</span>
                    }
                  </td>

                  <td class="tactic-cell">
                    @if (item.mapping.tactic) {
                      <span class="tactic-tag">{{ item.mapping.tactic }}</span>
                    } @else {
                      <span class="tactic-none text-muted">&mdash;</span>
                    }
                  </td>

                  <td class="status-cell">
                    <span
                      class="status-pill"
                      [ngClass]="'status-' + item.mapping.mapping_status"
                    >
                      <span class="status-dot"></span>
                      <span>{{ getStatusLabel(item.mapping.mapping_status) }}</span>
                    </span>
                  </td>

                  <td class="telemetry-cell">
                    @if (item.mapping.missing_telemetry && item.mapping.missing_telemetry.length > 0) {
                      <div class="telemetry-tags-wrap">
                        @for (tel of item.mapping.missing_telemetry; track tel) {
                          <span class="tel-tag" [attr.title]="tel">
                            <span class="material-symbols-outlined tel-icon">data_alert</span>
                            <span>{{ tel }}</span>
                          </span>
                        }
                      </div>
                    } @else {
                      <span class="tel-none text-muted">Baseline non-malicious traffic (No host telemetry required)</span>
                    }
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>

        <div class="mitre-footer">
          <div class="footer-note">
            <span class="material-symbols-outlined note-icon">info</span>
            <span>
              All technique IDs link directly to the official MITRE ATT&CK knowledge base. Mappings represent prospective tactical hypotheses based on Netflow flow signatures.
            </span>
          </div>
          @if (selectedFilter !== 'ALL') {
            <span class="filter-count-note">
              Showing {{ filteredItems.length }} of 14 categories
            </span>
          }
        </div>
      }

      @if (!loading && !errorMessage && filteredItems.length === 0) {
        <div class="state-container">
          <span class="material-symbols-outlined state-icon">search_off</span>
          <span>No MITRE mapping profiles match the selected filter.</span>
          <button class="reset-filter-btn" (click)="resetFilter()">Reset Filter</button>
        </div>
      }
    </div>
  `,
  styles: [`
    .mitre-summary-card {
      background: var(--tl-bg-surface, #1E293B);
      border: 1px solid var(--tl-border, rgba(255, 255, 255, 0.08));
      border-radius: 8px;
      padding: 18px 20px;
      display: flex;
      flex-direction: column;
      gap: 14px;
    }

    .summary-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
    }

    .header-titles {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }

    .title-row {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }

    .summary-title {
      font-size: 16px;
      font-weight: 700;
      color: var(--tl-text-primary, #F8FAFC);
    }

    .mitre-pill {
      font-size: 10px;
      font-weight: 600;
      color: var(--tl-cyan, #06B6D4);
      background: rgba(6, 182, 212, 0.1);
      border: 1px solid rgba(6, 182, 212, 0.25);
      border-radius: 4px;
      padding: 2px 8px;
    }

    .summary-subtitle {
      font-size: 12px;
      color: var(--tl-text-secondary, #94A3B8);
    }

    .header-controls {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .filter-group {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .filter-label {
      font-size: 12px;
      color: var(--tl-text-secondary, #94A3B8);
      font-weight: 500;
    }

    .select-wrapper {
      position: relative;
    }

    .filter-select {
      background: rgba(15, 23, 42, 0.8);
      border: 1px solid var(--tl-border, rgba(255, 255, 255, 0.12));
      border-radius: 5px;
      color: var(--tl-text-primary, #F8FAFC);
      font-size: 12px;
      font-weight: 500;
      padding: 5px 28px 5px 10px;
      cursor: pointer;
      appearance: none;
      background-image: url("data:image/svg+xml;charset=UTF-8,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%2394A3B8'%3e%3cpath d='M7 10l5 5 5-5z'/%3e%3c/svg%3e");
      background-repeat: no-repeat;
      background-position: right 6px center;
      background-size: 16px;
      min-width: 170px;

      &:focus {
        outline: none;
        border-color: var(--tl-cyan, #06B6D4);
      }
    }

    .reset-filter-btn {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      background: rgba(239, 68, 68, 0.1);
      border: 1px solid rgba(239, 68, 68, 0.25);
      color: #F87171;
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.15s ease;

      .reset-icon { font-size: 14px; }
      &:hover { background: rgba(239, 68, 68, 0.2); color: #FECACA; }
    }

    /* Boundary Disclosure Panel */
    .boundary-disclosure-panel {
      background: rgba(15, 23, 42, 0.5);
      border: 1px solid rgba(6, 182, 212, 0.25);
      border-left: 3px solid var(--tl-cyan, #06B6D4);
      border-radius: 6px;
      padding: 14px 16px;
      display: flex;
      flex-direction: column;
      gap: 10px;
    }

    .disclosure-header {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .boundary-icon {
      font-size: 20px;
      color: var(--tl-cyan, #06B6D4);
    }

    .disclosure-title-group {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }

    .disclosure-title {
      font-size: 13px;
      font-weight: 700;
      color: var(--tl-text-primary, #F8FAFC);
    }

    .safeguard-badge {
      font-size: 10px;
      font-weight: 600;
      background: rgba(148, 163, 184, 0.15);
      border: 1px solid rgba(148, 163, 184, 0.3);
      color: #CBD5E1;
      padding: 2px 7px;
      border-radius: 4px;
      text-transform: uppercase;
      letter-spacing: 0.4px;
    }

    .disclosure-body {
      margin: 0;
      font-size: 12px;
      color: #CBD5E1;
      line-height: 1.5;

      strong {
        color: var(--tl-text-primary, #F8FAFC);
      }
    }

    .coverage-metrics {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-top: 2px;
    }

    .metric-pill {
      display: flex;
      align-items: center;
      gap: 6px;
      padding: 3px 9px;
      border-radius: 5px;
      font-size: 11px;
      border: 1px solid transparent;

      &.candidate-pill {
        background: rgba(6, 182, 212, 0.1);
        color: #67E8F9;
        border-color: rgba(6, 182, 212, 0.25);
      }

      &.unverified-pill {
        background: rgba(245, 158, 11, 0.1);
        color: #FCD34D;
        border-color: rgba(245, 158, 11, 0.25);
      }

      &.verified-pill {
        background: rgba(16, 185, 129, 0.1);
        color: #6EE7B7;
        border-color: rgba(16, 185, 129, 0.25);
      }

      &.na-pill {
        background: rgba(107, 114, 128, 0.1);
        color: #94A3B8;
        border-color: rgba(107, 114, 128, 0.25);
      }

      .metric-val {
        font-weight: 700;
        font-size: 12px;
        font-family: monospace;
      }

      .metric-label {
        font-size: 10.5px;
      }
    }

    /* Table Styles */
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
        padding: 8px 12px;
        background: rgba(15, 23, 42, 0.85);
        color: var(--tl-text-muted, #64748B);
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.4px;
        border-bottom: 1px solid var(--tl-border, rgba(255, 255, 255, 0.08));
      }

      td {
        padding: 10px 12px;
        border-bottom: 1px solid rgba(255, 255, 255, 0.04);
        color: var(--tl-text-primary, #F8FAFC);
        vertical-align: middle;
      }

      tr:hover {
        background: rgba(255, 255, 255, 0.03);
      }
    }

    .col-cat { width: 155px; }
    .col-tech { min-width: 200px; }
    .col-tactic { width: 140px; }
    .col-status { width: 150px; }
    .col-telemetry { min-width: 320px; }

    .category-cell {
      .cat-label {
        color: var(--tl-text-primary, #F8FAFC);
        font-size: 12px;
        white-space: nowrap;
      }
    }

    .tech-cell {
      .tech-group {
        display: flex;
        flex-direction: column;
        gap: 2px;
      }
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

    .tactic-tag {
      display: inline-block;
      font-size: 11px;
      color: #CBD5E1;
      background: rgba(255, 255, 255, 0.04);
      padding: 2px 7px;
      border-radius: 4px;
      border: 1px solid rgba(255, 255, 255, 0.06);
    }

    .tactic-none {
      font-size: 12px;
    }

    .status-pill {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      font-size: 10.5px;
      font-weight: 600;
      padding: 3px 8px;
      border-radius: 4px;
      white-space: nowrap;

      .status-dot {
        width: 6px;
        height: 6px;
        border-radius: 50%;
      }

      &.status-candidate {
        background: rgba(6, 182, 212, 0.12);
        color: #67E8F9;
        border: 1px solid rgba(6, 182, 212, 0.3);
        .status-dot { background: #06B6D4; }
      }

      &.status-unverified {
        background: rgba(245, 158, 11, 0.12);
        color: #FCD34D;
        border: 1px solid rgba(245, 158, 11, 0.3);
        .status-dot { background: #F59E0B; }
      }

      &.status-verified {
        background: rgba(16, 185, 129, 0.12);
        color: #6EE7B7;
        border: 1px solid rgba(16, 185, 129, 0.3);
        .status-dot { background: #10B981; }
      }

      &.status-not_applicable {
        background: rgba(107, 114, 128, 0.12);
        color: #94A3B8;
        border: 1px solid rgba(107, 114, 128, 0.25);
        .status-dot { background: #64748B; }
      }
    }

    .telemetry-cell {
      .telemetry-tags-wrap {
        display: flex;
        flex-wrap: wrap;
        gap: 5px;
      }
    }

    .tel-tag {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      font-size: 10.5px;
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid rgba(255, 255, 255, 0.08);
      padding: 2px 7px;
      border-radius: 3px;
      color: #CBD5E1;
      line-height: 1.3;

      .tel-icon {
        font-size: 13px;
        color: var(--tl-amber, #F59E0B);
        opacity: 0.85;
      }
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

    .mitre-footer {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 8px;
      padding-top: 4px;
    }

    .footer-note {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 11px;
      color: var(--tl-text-muted, #64748B);

      .note-icon {
        font-size: 14px;
        color: var(--tl-cyan, #06B6D4);
        flex-shrink: 0;
      }
    }

    .filter-count-note {
      font-size: 11px;
      color: var(--tl-cyan, #06B6D4);
      font-weight: 600;
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
    this.applyFilter();
  }

  items: MitreProfileSummaryItem[] = [];
  filteredItems: MitreProfileSummaryItem[] = [];
  selectedFilter: MitreFilter = 'ALL';

  candidateCount: number = 0;
  unverifiedCount: number = 0;
  verifiedCount: number = 0;
  naCount: number = 0;

  onFilterChange(filter: MitreFilter): void {
    this.selectedFilter = filter;
    this.applyFilter();
  }

  resetFilter(): void {
    this.selectedFilter = 'ALL';
    this.applyFilter();
  }

  private applyFilter(): void {
    if (this.selectedFilter === 'ALL') {
      this.filteredItems = [...this.items];
    } else if (this.selectedFilter === 'CANDIDATE') {
      this.filteredItems = this.items.filter(
        (i) => i.mapping?.mapping_status?.toLowerCase() === 'candidate'
      );
    } else if (this.selectedFilter === 'UNVERIFIED') {
      this.filteredItems = this.items.filter(
        (i) => i.mapping?.mapping_status?.toLowerCase() === 'unverified'
      );
    } else if (this.selectedFilter === 'BENIGN') {
      this.filteredItems = this.items.filter(
        (i) => i.mapping?.mapping_status?.toLowerCase() === 'not_applicable'
      );
    }
  }

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

  getStatusLabel(status: string): string {
    switch (status?.toLowerCase()) {
      case 'candidate': return 'Candidate Profile';
      case 'unverified': return 'Unverified Mapping';
      case 'verified': return 'Verified Attribution';
      case 'not_applicable': return 'Benign Baseline';
      default: return status || 'Unknown';
    }
  }
}


