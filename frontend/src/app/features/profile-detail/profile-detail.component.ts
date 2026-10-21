import { Component, Input, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, RouterModule } from '@angular/router';
import { MatTabsModule } from '@angular/material/tabs';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { forkJoin } from 'rxjs';
import { ThreatLenzApiService } from '../../core/services/api.service';
import {
  AdvisoryResponse,
  MitreMappingResponse,
  RiskAssessmentResponse,
  ThreatProfileSummary,
} from '../../core/models';
import {
  AdvisoryCardComponent,
  EvidenceBannerComponent,
  ReliabilityBadgeComponent,
  RiskBandBadgeComponent,
  StatCardComponent,
  StatusBadgeComponent,
} from '../../shared/components';

@Component({
  selector: 'app-profile-detail',
  standalone: true,
  imports: [
    CommonModule,
    RouterModule,
    MatTabsModule,
    MatButtonModule,
    MatIconModule,
    MatProgressSpinnerModule,
    StatusBadgeComponent,
    ReliabilityBadgeComponent,
    RiskBandBadgeComponent,
    EvidenceBannerComponent,
    AdvisoryCardComponent,
    StatCardComponent,
  ],
  template: `
    <div class="detail-container">
      <!-- Back Navigation Header -->
      <div class="top-nav">
        <a mat-button routerLink="/profiles" class="back-link">
          <span class="material-symbols-outlined" style="font-size: 18px; margin-right: 4px;">arrow_back</span>
          Back to Threat Explorer
        </a>
      </div>

      <!-- Loading State -->
      @if (loading) {
        <div class="state-container">
          <mat-spinner diameter="44"></mat-spinner>
          <span>Loading threat profile intelligence snapshot...</span>
        </div>
      }

      <!-- Error State -->
      @if (errorMessage && !loading) {
        <div class="state-container error-state" role="alert">
          <span class="material-symbols-outlined state-icon">error</span>
          <h3>Profile Inspection Error</h3>
          <p>{{ errorMessage }}</p>
          <a mat-flat-button color="accent" routerLink="/profiles">
            Return to Explorer
          </a>
        </div>
      }

      <!-- Main Profile View -->
      @if (!loading && profile && !errorMessage) {
        <!-- Profile Identity Hero -->
        <div class="profile-hero">
          <div class="hero-left">
            <div class="hero-category-row">
              <h1 class="hero-title">{{ profile.canonical_label }}</h1>
              <app-status-badge [status]="profile.attack_status"></app-status-badge>
              <app-reliability-badge [reliability]="profile.model_reliability"></app-reliability-badge>
            </div>
            <div class="hero-meta-row">
              <span class="meta-item">
                <span class="meta-label">Raw Label:</span>
                <span class="meta-val font-mono">{{ profile.raw_label }}</span>
              </span>
              <span class="meta-divider">•</span>
              <span class="meta-item">
                <span class="meta-label">Snapshot ID:</span>
                <span class="meta-val font-mono">{{ profile.snapshot_id }}</span>
              </span>
              <span class="meta-divider">•</span>
              <span class="meta-item">
                <span class="meta-label">Run ID:</span>
                <span class="meta-val font-mono">{{ profile.run_id }}</span>
              </span>
            </div>
          </div>

          <div class="hero-right">
            <app-risk-band-badge
              [riskBand]="risk?.risk_band"
              [isConfirmed]="risk?.is_confirmed ?? false"
              [provisionalBand]="risk?.provisional_risk_band"
            ></app-risk-band-badge>
          </div>
        </div>

        <!-- 4-Tab Section -->
        <div class="tabs-card">
          <mat-tab-group animationDuration="0ms" class="threat-tabs">
            <!-- TAB 1: Traffic Overview -->
            <mat-tab>
              <ng-template mat-tab-label>
                <span class="material-symbols-outlined tab-icon">tune</span>
                <span>Traffic Characteristics</span>
              </ng-template>

              <div class="tab-pane">
                <div class="kpi-grid">
                  <app-stat-card
                    title="Netflow Count"
                    [value]="profile.flow_count | number"
                    subtitle="Observed physical flow records"
                    icon="alt_route"
                  ></app-stat-card>

                  <app-stat-card
                    title="Total Packets"
                    [value]="profile.total_packets | number"
                    subtitle="Aggregated packet volume"
                    icon="layers"
                  ></app-stat-card>

                  <app-stat-card
                    title="Total Bytes"
                    [value]="formatBytes(profile.total_bytes)"
                    subtitle="Aggregated payload & header volume"
                    icon="data_usage"
                  ></app-stat-card>

                  <app-stat-card
                    title="Observation Recurrence"
                    [value]="(profile.recurrence_ratio * 100).toFixed(1) + '%'"
                    [subtitle]="profile.active_observation_units + ' of ' + profile.recurrence_denominator + ' observation units'"
                    icon="calendar_month"
                  ></app-stat-card>
                </div>

                <div class="overview-grid">
                  <div class="info-block">
                    <span class="block-title">Temporal Observation Window</span>
                    <div class="kv-list">
                      <div class="kv-row">
                        <span class="kv-key">Window Type:</span>
                        <span class="kv-val">{{ profile.window_type }}</span>
                      </div>
                      <div class="kv-row">
                        <span class="kv-key">Interval Start:</span>
                        <span class="kv-val">{{ profile.window_start | date:'medium' }}</span>
                      </div>
                      <div class="kv-row">
                        <span class="kv-key">Interval End:</span>
                        <span class="kv-val">{{ profile.window_end | date:'medium' }}</span>
                      </div>
                      <div class="kv-row">
                        <span class="kv-key">Interval Semantics:</span>
                        <span class="kv-val font-mono">[window_start, window_end) half-open</span>
                      </div>
                    </div>
                  </div>

                  <div class="info-block">
                    <span class="block-title">Deterministic Identity Provenance</span>
                    <div class="kv-list">
                      <div class="kv-row">
                        <span class="kv-key">Profile ID (Natural Key):</span>
                        <span class="kv-val font-mono">{{ profile.profile_id }}</span>
                      </div>
                      <div class="kv-row">
                        <span class="kv-key">Snapshot ID (Immutable):</span>
                        <span class="kv-val font-mono">{{ profile.snapshot_id }}</span>
                      </div>
                      <div class="kv-row">
                        <span class="kv-key">Manifest SHA-256:</span>
                        <span class="kv-val font-mono">{{ profile.source_manifest_hash }}</span>
                      </div>
                      <div class="kv-row">
                        <span class="kv-key">Schema Version:</span>
                        <span class="kv-val">{{ profile.schema_version }}</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </mat-tab>

            <!-- TAB 2: TLRS Risk Assessment -->
            <mat-tab>
              <ng-template mat-tab-label>
                <span class="material-symbols-outlined tab-icon">shield_with_heart</span>
                <span>TLRS Risk Assessment</span>
              </ng-template>

              <div class="tab-pane">
                @if (risk) {
                  <!-- Evidence Banner -->
                  <app-evidence-banner
                    [isConfirmed]="risk.is_confirmed"
                    [evidenceCoverage]="risk.evidence_coverage"
                    [provisionalRiskBand]="risk.provisional_risk_band"
                  ></app-evidence-banner>

                  <!-- Risk Scorecard Header -->
                  <div class="risk-scorecard">
                    <div class="scorecard-cell">
                      <span class="score-label">Operational Risk Band</span>
                      <span class="score-val" [ngClass]="risk.is_confirmed ? 'confirmed-text' : 'withheld-text'">
                        {{ risk.is_confirmed ? risk.risk_band : 'Withheld (Insufficient Evidence)' }}
                      </span>
                    </div>

                    <div class="scorecard-cell">
                      <span class="score-label">Diagnostic Normalized Score</span>
                      <span class="score-val font-mono">
                        {{ risk.tlrs_normalized_rounded }} / 100
                        <span class="score-tag">DIAGNOSTIC ONLY</span>
                      </span>
                    </div>

                    <div class="scorecard-cell">
                      <span class="score-label">Observed Partial Score</span>
                      <span class="score-val font-mono">{{ risk.tlrs_partial_diagnostic.toFixed(2) }}</span>
                    </div>

                    <div class="scorecard-cell">
                      <span class="score-label">Evidence Coverage</span>
                      <span class="score-val font-mono">{{ (risk.evidence_coverage * 100).toFixed(1) }}%</span>
                    </div>
                  </div>

                  <!-- Component Factor Weights Table -->
                  <div class="factors-section">
                    <h3 class="section-heading">Multi-Factor TLRS Component Breakdown</h3>
                    <div class="table-responsive">
                      <table class="factors-table">
                        <thead>
                          <tr>
                            <th>Scoring Component</th>
                            <th>Weight</th>
                            <th>Observed Score [0-100]</th>
                            <th>Weighted Contribution</th>
                            <th>Telemetry Source</th>
                          </tr>
                        </thead>
                        <tbody>
                          <tr>
                            <td class="factor-name">Severity ($S_{{ '{' }}sev{{ '}' }}$)</td>
                            <td class="font-mono">40% (0.40)</td>
                            <td class="font-mono">{{ risk.severity_score }}</td>
                            <td class="font-mono">{{ (risk.severity_score * risk.weight_severity).toFixed(2) }}</td>
                            <td>Class Prior Threat Impact</td>
                          </tr>
                          <tr>
                            <td class="factor-name">Frequency ($S_{{ '{' }}freq{{ '}' }}$)</td>
                            <td class="font-mono">25% (0.25)</td>
                            <td class="font-mono">{{ risk.frequency_score.toFixed(2) }}</td>
                            <td class="font-mono">{{ (risk.frequency_score * risk.weight_frequency).toFixed(2) }}</td>
                            <td>Logarithmic Netflow Count</td>
                          </tr>
                          <tr>
                            <td class="factor-name">Recurrence ($S_{{ '{' }}rec{{ '}' }}$)</td>
                            <td class="font-mono">20% (0.20)</td>
                            <td class="font-mono">{{ risk.recurrence_score.toFixed(2) }}</td>
                            <td class="font-mono">{{ (risk.recurrence_score * risk.weight_recurrence).toFixed(2) }}</td>
                            <td>Active Observation Units</td>
                          </tr>
                          <tr class="missing-row">
                            <td class="factor-name">
                              Target Impact ($S_{{ '{' }}target{{ '}' }}$)
                              <span class="missing-pill">MISSING TELEMETRY</span>
                            </td>
                            <td class="font-mono">15% (0.15)</td>
                            <td class="font-mono text-muted">
                              {{ risk.target_impact_score !== null ? risk.target_impact_score : 'None' }}
                            </td>
                            <td class="font-mono text-muted">0.00</td>
                            <td>Host / Asset Criticality (Absent in Netflow)</td>
                          </tr>
                        </tbody>
                      </table>
                    </div>
                  </div>
                }
              </div>
            </mat-tab>

            <!-- TAB 3: MITRE ATT&CK Mapping -->
            <mat-tab>
              <ng-template mat-tab-label>
                <span class="material-symbols-outlined tab-icon">hub</span>
                <span>MITRE ATT&CK Mapping</span>
              </ng-template>

              <div class="tab-pane">
                @if (mitre) {
                  <div class="mitre-card">
                    <div class="mitre-header">
                      <div class="mitre-technique">
                        @if (mitre.technique_id) {
                          <a
                            [href]="'https://attack.mitre.org/techniques/' + mitre.technique_id.replace('.', '/')"
                            target="_blank"
                            rel="noopener"
                            class="technique-link"
                          >
                            <span class="technique-id font-mono">{{ mitre.technique_id }}</span>
                            <span class="material-symbols-outlined" style="font-size: 16px;">open_in_new</span>
                          </a>
                        } @else {
                          <span class="technique-none font-mono">None</span>
                        }
                        <span class="technique-name">{{ mitre.technique_name || 'No Technique Mapped' }}</span>
                      </div>

                      <div class="mitre-status-box">
                        <span class="status-tag" [ngClass]="'status-' + mitre.mapping_status">
                          {{ mitre.mapping_status | uppercase }}
                        </span>
                        <span class="unconfirmed-pill" [class.confirmed-pill]="mitre.is_confirmed">
                          {{ mitre.is_confirmed ? 'CONFIRMED' : 'UNCONFIRMED EVIDENCE' }}
                        </span>
                      </div>
                    </div>

                    <div class="mitre-body">
                      <div class="tactic-row">
                        <span class="tactic-label">Enterprise ATT&CK Tactic:</span>
                        <span class="tactic-val">{{ mitre.tactic || 'Not Applicable' }}</span>
                      </div>

                      <div class="rationale-block">
                        <span class="block-title">Mapping Rationale &amp; Observable Evidence</span>
                        <p class="rationale-text">{{ mitre.rationale }}</p>
                      </div>

                      @if (mitre.missing_telemetry && mitre.missing_telemetry.length > 0) {
                        <div class="telemetry-block">
                          <span class="block-title">Required Telemetry for Verification</span>
                          <p class="telemetry-intro">
                            Netflow captures flow statistics only. The following telemetry is required before this technique can be marked verified:
                          </p>
                          <ul class="telemetry-list">
                            @for (item of mitre.missing_telemetry; track item) {
                              <li>
                                <span class="material-symbols-outlined check-icon">check_box_outline_blank</span>
                                <span>{{ item }}</span>
                              </li>
                            }
                          </ul>
                        </div>
                      }
                    </div>
                  </div>
                }
              </div>
            </mat-tab>

            <!-- TAB 4: Defensive Advisories -->
            <mat-tab>
              <ng-template mat-tab-label>
                <span class="material-symbols-outlined tab-icon">security</span>
                <span>Defensive Advisories ({{ advisories.length }})</span>
              </ng-template>

              <div class="tab-pane">
                <!-- Human Validation Governance Reminder -->
                <div class="governance-reminder">
                  <span class="material-symbols-outlined gov-icon">gavel</span>
                  <div class="gov-text">
                    <span class="gov-title">Human Analyst Validation Enforced</span>
                    <span class="gov-desc">
                      ThreatLenz recommendations are strictly advisory and non-destructive. Automated block scripts are prohibited.
                    </span>
                  </div>
                </div>

                <div class="advisories-list">
                  @for (advisory of advisories; track advisory.id) {
                    <app-advisory-card [advisory]="advisory"></app-advisory-card>
                  } @empty {
                    <div class="empty-state">
                      <span class="material-symbols-outlined" style="font-size: 32px; color: var(--tl-text-muted);">verified</span>
                      <span>No active defensive advisories required for this profile.</span>
                    </div>
                  }
                </div>
              </div>
            </mat-tab>
          </mat-tab-group>
        </div>
      }
    </div>
  `,
  styles: [`
    .detail-container {
      display: flex;
      flex-direction: column;
      gap: 20px;
    }

    .top-nav {
      margin-bottom: -8px;
    }

    .back-link {
      font-size: 13px;
      color: var(--tl-cyan);
    }

    .profile-hero {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 20px;
      background: var(--tl-bg-surface);
      border: 1px solid var(--tl-border);
      border-radius: 8px;
      padding: 24px 28px;
    }

    .hero-left {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .hero-category-row {
      display: flex;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
    }

    .hero-title {
      font-size: 24px;
      font-weight: 700;
      color: var(--tl-text-primary);
      margin: 0;
      letter-spacing: -0.5px;
    }

    .hero-meta-row {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
      font-size: 12px;
      color: var(--tl-text-secondary);
    }

    .meta-label {
      color: var(--tl-text-muted);
      margin-right: 4px;
    }

    .meta-val {
      color: var(--tl-text-primary);
    }

    .meta-divider {
      color: var(--tl-text-muted);
    }

    .font-mono {
      font-family: monospace;
    }

    .tabs-card {
      background: var(--tl-bg-surface);
      border: 1px solid var(--tl-border);
      border-radius: 8px;
      overflow: hidden;
    }

    .threat-tabs {
      background: transparent;
    }

    .tab-icon {
      font-size: 18px;
      margin-right: 8px;
      vertical-align: middle;
    }

    .tab-pane {
      padding: 24px;
      display: flex;
      flex-direction: column;
      gap: 24px;
    }

    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
    }

    .overview-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 20px;
    }

    .info-block {
      background: var(--tl-bg-card);
      border: 1px solid var(--tl-border);
      border-radius: 6px;
      padding: 18px;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .block-title {
      font-size: 12px;
      font-weight: 700;
      color: var(--tl-cyan);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .kv-list {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .kv-row {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      font-size: 13px;
    }

    .kv-key {
      color: var(--tl-text-muted);
    }

    .kv-val {
      color: var(--tl-text-primary);
      text-align: right;
    }

    .risk-scorecard {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      background: var(--tl-bg-card);
      border: 1px solid var(--tl-border);
      border-radius: 6px;
      padding: 18px;
    }

    .scorecard-cell {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }

    .score-label {
      font-size: 11px;
      font-weight: 700;
      color: var(--tl-text-muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .score-val {
      font-size: 18px;
      font-weight: 700;
      display: flex;
      align-items: baseline;
      gap: 6px;
      flex-wrap: wrap;
    }

    .withheld-text {
      color: #FBBF24;
      font-size: 15px;
    }

    .confirmed-text {
      color: var(--tl-emerald);
    }

    .score-tag {
      font-size: 10px;
      font-weight: 700;
      background: rgba(245, 158, 11, 0.2);
      color: #FDE68A;
      padding: 2px 6px;
      border-radius: 4px;
    }

    .section-heading {
      font-size: 14px;
      font-weight: 700;
      color: var(--tl-text-primary);
      margin: 0 0 12px 0;
    }

    .factors-table {
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

      .factor-name {
        font-weight: 600;
      }

      .missing-row {
        background: rgba(245, 158, 11, 0.04);
      }
    }

    .missing-pill {
      font-size: 10px;
      font-weight: 700;
      background: rgba(245, 158, 11, 0.2);
      color: #FBBF24;
      padding: 1px 6px;
      border-radius: 3px;
      margin-left: 6px;
    }

    .mitre-card {
      background: var(--tl-bg-card);
      border: 1px solid var(--tl-border);
      border-radius: 6px;
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .mitre-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
      border-bottom: 1px solid var(--tl-border);
      padding-bottom: 14px;
    }

    .mitre-technique {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }

    .technique-link {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      font-size: 14px;
      font-weight: 700;
      color: var(--tl-cyan);
      text-decoration: none;
      background: rgba(6, 182, 212, 0.1);
      padding: 4px 8px;
      border-radius: 4px;
      border: 1px solid rgba(6, 182, 212, 0.3);

      &:hover {
        background: rgba(6, 182, 212, 0.2);
      }
    }

    .technique-name {
      font-size: 16px;
      font-weight: 600;
      color: var(--tl-text-primary);
    }

    .mitre-status-box {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .status-tag {
      font-size: 11px;
      font-weight: 700;
      padding: 3px 8px;
      border-radius: 4px;
    }

    .status-candidate {
      background: rgba(59, 130, 246, 0.2);
      color: #60A5FA;
      border: 1px solid rgba(59, 130, 246, 0.4);
    }

    .status-unverified {
      background: rgba(245, 158, 11, 0.2);
      color: #FBBF24;
      border: 1px solid rgba(245, 158, 11, 0.4);
    }

    .status-not_applicable {
      background: rgba(107, 114, 128, 0.2);
      color: #9CA3AF;
      border: 1px solid rgba(107, 114, 128, 0.4);
    }

    .unconfirmed-pill {
      font-size: 10px;
      font-weight: 700;
      background: rgba(239, 68, 68, 0.15);
      color: #F87171;
      border: 1px solid rgba(239, 68, 68, 0.3);
      padding: 3px 6px;
      border-radius: 4px;
    }

    .confirmed-pill {
      background: rgba(16, 185, 129, 0.15);
      color: #34D399;
      border-color: rgba(16, 185, 129, 0.3);
    }

    .mitre-body {
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .tactic-row {
      display: flex;
      gap: 8px;
      font-size: 13px;
    }

    .tactic-label {
      color: var(--tl-text-muted);
    }

    .tactic-val {
      color: var(--tl-text-primary);
      font-weight: 600;
    }

    .rationale-text {
      font-size: 13px;
      color: #D1D5DB;
      line-height: 1.6;
      margin: 4px 0 0 0;
    }

    .telemetry-intro {
      font-size: 12px;
      color: var(--tl-text-secondary);
      margin: 4px 0 8px 0;
    }

    .telemetry-list {
      margin: 0;
      padding: 0;
      list-style: none;
      display: flex;
      flex-direction: column;
      gap: 6px;

      li {
        display: flex;
        align-items: center;
        gap: 8px;
        font-size: 12px;
        color: #D1D5DB;

        .check-icon {
          font-size: 16px;
          color: var(--tl-cyan);
        }
      }
    }

    .governance-reminder {
      display: flex;
      align-items: center;
      gap: 12px;
      background: rgba(6, 182, 212, 0.08);
      border: 1px solid rgba(6, 182, 212, 0.25);
      border-radius: 6px;
      padding: 12px 16px;
    }

    .gov-icon {
      font-size: 24px;
      color: var(--tl-cyan);
    }

    .gov-text {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }

    .gov-title {
      font-size: 13px;
      font-weight: 700;
      color: var(--tl-cyan);
    }

    .gov-desc {
      font-size: 12px;
      color: var(--tl-text-secondary);
    }

    .advisories-list {
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .state-container {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      min-height: 400px;
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

    .empty-state {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 8px;
      padding: 40px;
      color: var(--tl-text-secondary);
      font-size: 13px;
    }
  `],
})
export class ProfileDetailComponent implements OnInit {
  @Input() id!: string;

  loading: boolean = true;
  errorMessage: string | null = null;

  profile: ThreatProfileSummary | null = null;
  risk: RiskAssessmentResponse | null = null;
  mitre: MitreMappingResponse | null = null;
  advisories: AdvisoryResponse[] = [];

  constructor(
    private readonly apiService: ThreatLenzApiService,
    private readonly route: ActivatedRoute
  ) {}

  ngOnInit(): void {
    const snapshotId = this.id || this.route.snapshot.paramMap.get('id');
    if (snapshotId) {
      this.loadProfileData(snapshotId);
    } else {
      this.errorMessage = 'No profile snapshot identifier was provided in route.';
      this.loading = false;
    }
  }

  loadProfileData(snapshotId: string): void {
    this.loading = true;
    this.errorMessage = null;

    forkJoin({
      profile: this.apiService.getProfileDetail(snapshotId),
      risk: this.apiService.getProfileRisk(snapshotId),
      mitre: this.apiService.getProfileMitre(snapshotId),
      advisories: this.apiService.getProfileAdvisories(snapshotId),
    }).subscribe({
      next: ({ profile, risk, mitre, advisories }) => {
        this.profile = profile;
        this.risk = risk;
        this.mitre = mitre;
        this.advisories = advisories.items;
        this.loading = false;
      },
      error: (err) => {
        this.errorMessage = err.message || `Failed to load intelligence profile '${snapshotId}'.`;
        this.loading = false;
      },
    });
  }

  formatBytes(bytes: number): string {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }
}
