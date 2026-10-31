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
                    <div class="factors-header">
                      <h3 class="section-heading">Multi-Factor TLRS Component Evidence Breakdown</h3>
                      <span class="evidence-legend">
                        Coverage: <strong>{{ (risk.evidence_coverage * 100).toFixed(0) }}%</strong> (Severity 40% + Frequency 25% + Recurrence 20%) | Target Impact 15% Withheld
                      </span>
                    </div>

                    <!-- Component Visual Evidence Contribution Bars -->
                    <div class="evidence-bars-grid">
                      <!-- Severity -->
                      <div class="evidence-bar-card">
                        <div class="bar-card-header">
                          <span class="factor-title">
                            <span class="material-symbols-outlined factor-icon sev-icon">report_problem</span>
                            Severity Contribution (40%)
                          </span>
                          <span class="factor-val font-mono">{{ (risk.severity_score * risk.weight_severity).toFixed(2) }} pts</span>
                        </div>
                        <div class="bar-track">
                          <div class="bar-fill sev-fill" [style.width.%]="risk.severity_score"></div>
                        </div>
                        <div class="bar-card-footer">
                          <span class="factor-sub">Prior Score: {{ risk.severity_score }} / 100</span>
                          <span class="factor-source">Class Prior Impact</span>
                        </div>
                      </div>

                      <!-- Frequency -->
                      <div class="evidence-bar-card">
                        <div class="bar-card-header">
                          <span class="factor-title">
                            <span class="material-symbols-outlined factor-icon freq-icon">speed</span>
                            Frequency Contribution (25%)
                          </span>
                          <span class="factor-val font-mono">{{ (risk.frequency_score * risk.weight_frequency).toFixed(2) }} pts</span>
                        </div>
                        <div class="bar-track">
                          <div class="bar-fill freq-fill" [style.width.%]="risk.frequency_score"></div>
                        </div>
                        <div class="bar-card-footer">
                          <span class="factor-sub">Score: {{ risk.frequency_score.toFixed(1) }} / 100</span>
                          <span class="factor-source">Log Netflow Count</span>
                        </div>
                      </div>

                      <!-- Recurrence -->
                      <div class="evidence-bar-card">
                        <div class="bar-card-header">
                          <span class="factor-title">
                            <span class="material-symbols-outlined factor-icon rec-icon">update</span>
                            Recurrence Contribution (20%)
                          </span>
                          <span class="factor-val font-mono">{{ (risk.recurrence_score * risk.weight_recurrence).toFixed(2) }} pts</span>
                        </div>
                        <div class="bar-track">
                          <div class="bar-fill rec-fill" [style.width.%]="risk.recurrence_score"></div>
                        </div>
                        <div class="bar-card-footer">
                          <span class="factor-sub">Score: {{ risk.recurrence_score.toFixed(1) }} / 100</span>
                          <span class="factor-source">Observation Units</span>
                        </div>
                      </div>

                      <!-- Target Impact (Unavailable / Insufficient Evidence) -->
                      <div class="evidence-bar-card unavailable-card">
                        <div class="bar-card-header">
                          <span class="factor-title text-amber">
                            <span class="material-symbols-outlined factor-icon amber-icon">warning_amber</span>
                            Target Impact (15%)
                          </span>
                          <span class="factor-status-badge">UNAVAILABLE (15%)</span>
                        </div>
                        <div class="bar-track unavailable-track">
                          <div class="bar-fill unavailable-fill" style="width: 0%;"></div>
                        </div>
                        <div class="bar-card-footer">
                          <span class="factor-sub text-amber">Insufficient Evidence (0 / 15 pts)</span>
                          <span class="factor-source">Missing Asset Criticality</span>
                        </div>
                      </div>
                    </div>

                    <div class="table-responsive">
                      <table class="factors-table">
                        <thead>
                          <tr>
                            <th>Scoring Component</th>
                            <th>Model Weight</th>
                            <th>Observed Score [0-100]</th>
                            <th>Weighted Contribution</th>
                            <th>Evidence Status &amp; Telemetry Source</th>
                          </tr>
                        </thead>
                        <tbody>
                          <tr>
                            <td class="factor-name">
                              <span class="component-bullet sev-bullet"></span>
                              Severity ($S_{{ '{' }}sev{{ '}' }}$)
                            </td>
                            <td class="font-mono">40% (0.40)</td>
                            <td class="font-mono">{{ risk.severity_score }}</td>
                            <td class="font-mono">{{ (risk.severity_score * risk.weight_severity).toFixed(2) }} / 40.00</td>
                            <td>
                              <span class="status-pill-sub observed-pill">OBSERVED</span>
                              Class Prior Threat Impact
                            </td>
                          </tr>
                          <tr>
                            <td class="factor-name">
                              <span class="component-bullet freq-bullet"></span>
                              Frequency ($S_{{ '{' }}freq{{ '}' }}$)
                            </td>
                            <td class="font-mono">25% (0.25)</td>
                            <td class="font-mono">{{ risk.frequency_score.toFixed(2) }}</td>
                            <td class="font-mono">{{ (risk.frequency_score * risk.weight_frequency).toFixed(2) }} / 25.00</td>
                            <td>
                              <span class="status-pill-sub observed-pill">OBSERVED</span>
                              Logarithmic Netflow Count
                            </td>
                          </tr>
                          <tr>
                            <td class="factor-name">
                              <span class="component-bullet rec-bullet"></span>
                              Recurrence ($S_{{ '{' }}rec{{ '}' }}$)
                            </td>
                            <td class="font-mono">20% (0.20)</td>
                            <td class="font-mono">{{ risk.recurrence_score.toFixed(2) }}</td>
                            <td class="font-mono">{{ (risk.recurrence_score * risk.weight_recurrence).toFixed(2) }} / 20.00</td>
                            <td>
                              <span class="status-pill-sub observed-pill">OBSERVED</span>
                              Active Observation Units
                            </td>
                          </tr>
                          <tr class="missing-row">
                            <td class="factor-name">
                              <span class="component-bullet missing-bullet"></span>
                              Target Impact ($S_{{ '{' }}target{{ '}' }}$)
                            </td>
                            <td class="font-mono">15% (0.15)</td>
                            <td class="font-mono text-muted">
                              Unavailable
                            </td>
                            <td class="font-mono text-muted">Withheld (0.00 / 15.00)</td>
                            <td>
                              <span class="missing-pill">UNAVAILABLE / INSUFFICIENT EVIDENCE (15%)</span>
                              <span class="missing-desc">Destination asset criticality evidence is missing in flow records. Operational TLRS withheld.</span>
                            </td>
                          </tr>
                        </tbody>
                      </table>
                    </div>

                    <!-- Explicit Evidence Safeguard Disclosure Notice -->
                    <div class="evidence-governance-notice">
                      <span class="material-symbols-outlined gov-flag-icon">verified_user</span>
                      <div class="gov-flag-content">
                        <strong>Evidence Safeguard Enforcement:</strong>
                        Destination host asset criticality telemetry is missing from captured Netflow data. ThreatLenz strictly withholds calculation of any operational overall TLRS score or operational risk band until CMDB or asset-criticality feeds provide the requisite 15% target impact evidence. The displayed partial score ({{ risk.tlrs_partial_diagnostic.toFixed(2) }}) and heuristic ({{ risk.tlrs_normalized_rounded }}) are diagnostic metrics only and must never be interpreted as operational risk scores.
                      </div>
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
                  <!-- Attribution Safeguard Notice -->
                  <div class="mitre-safeguard-banner" [ngClass]="'banner-' + mitre.mapping_status">
                    <div class="banner-icon-box">
                      <span class="material-symbols-outlined">{{ getMitreStatusIcon(mitre.mapping_status) }}</span>
                    </div>
                    <div class="banner-body">
                      <div class="banner-title-line">
                        <span class="banner-title">{{ getMitreStatusTitle(mitre.mapping_status) }}</span>
                        <span class="mitre-pill" [ngClass]="'pill-' + mitre.mapping_status">
                          {{ getMitreStatusLabel(mitre.mapping_status) }}
                        </span>
                      </div>
                      <p class="banner-desc">{{ getMitreStatusDescription(mitre.mapping_status) }}</p>
                    </div>
                  </div>

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
                        <div class="technique-meta">
                          <span class="technique-name">{{ mitre.technique_name || 'No Technique Mapped' }}</span>
                          <span class="technique-subtext">
                            @if (mitre.mapping_status === 'candidate') {
                              Behavioral Candidate Pattern (Unverified Attribution)
                            } @else if (mitre.mapping_status === 'unverified') {
                              Unverified Traffic Heuristic
                            } @else if (mitre.mapping_status === 'verified') {
                              Corroborated Telemetry Mapping
                            } @else {
                              Benign Baseline
                            }
                          </span>
                        </div>
                      </div>

                      <div class="mitre-status-box">
                        <div class="status-indicator-badge" [ngClass]="'indicator-' + mitre.mapping_status">
                          <span class="indicator-dot"></span>
                          <span>{{ getMitreStatusLabel(mitre.mapping_status) }}</span>
                        </div>
                        <span class="unconfirmed-pill" [class.confirmed-pill]="mitre.is_confirmed">
                          {{ mitre.is_confirmed ? 'VERIFIED ATTRIBUTION' : 'UNCONFIRMED EVIDENCE' }}
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
                          <div class="telemetry-header">
                            <span class="material-symbols-outlined info-icon">info</span>
                            <span class="block-title">Required Telemetry for Attribution Verification</span>
                          </div>
                          <p class="telemetry-intro">
                            Flow statistics provide behavioral correlation only, not verified threat attribution. The following host or payload telemetry is missing and required before this technique can be marked verified:
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
      margin: 0;
    }

    .factors-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 16px;
    }

    .evidence-legend {
      font-size: 12px;
      color: var(--tl-text-secondary);
      strong {
        color: var(--tl-cyan);
      }
    }

    .evidence-bars-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 20px;
    }

    .evidence-bar-card {
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--tl-border);
      border-radius: 6px;
      padding: 14px 16px;
      display: flex;
      flex-direction: column;
      gap: 10px;

      &.unavailable-card {
        background: rgba(245, 158, 11, 0.04);
        border: 1px dashed rgba(245, 158, 11, 0.4);
      }
    }

    .bar-card-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
    }

    .factor-title {
      font-size: 12px;
      font-weight: 700;
      color: var(--tl-text-primary);
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .factor-icon {
      font-size: 16px;
      &.sev-icon { color: #EF4444; }
      &.freq-icon { color: #3B82F6; }
      &.rec-icon { color: #10B981; }
      &.amber-icon { color: #F59E0B; }
    }

    .factor-val {
      font-size: 13px;
      font-weight: 700;
      color: var(--tl-text-primary);
    }

    .factor-status-badge {
      font-size: 10px;
      font-weight: 700;
      color: #FBBF24;
      background: rgba(245, 158, 11, 0.15);
      border: 1px solid rgba(245, 158, 11, 0.3);
      padding: 2px 6px;
      border-radius: 4px;
    }

    .bar-track {
      width: 100%;
      height: 8px;
      background: rgba(255, 255, 255, 0.06);
      border-radius: 4px;
      overflow: hidden;

      &.unavailable-track {
        background: rgba(245, 158, 11, 0.1);
        border: 1px dashed rgba(245, 158, 11, 0.3);
      }
    }

    .bar-fill {
      height: 100%;
      border-radius: 4px;
      transition: width 0.3s ease;

      &.sev-fill { background: linear-gradient(90deg, #EF4444, #F87171); }
      &.freq-fill { background: linear-gradient(90deg, #3B82F6, #60A5FA); }
      &.rec-fill { background: linear-gradient(90deg, #10B981, #34D399); }
    }

    .bar-card-footer {
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-size: 11px;
      color: var(--tl-text-muted);
    }

    .factor-source {
      font-size: 10px;
      background: rgba(255, 255, 255, 0.05);
      padding: 1px 6px;
      border-radius: 3px;
    }

    .text-amber {
      color: #FBBF24 !important;
    }

    .component-bullet {
      display: inline-block;
      width: 8px;
      height: 8px;
      border-radius: 50%;
      margin-right: 6px;

      &.sev-bullet { background: #EF4444; }
      &.freq-bullet { background: #3B82F6; }
      &.rec-bullet { background: #10B981; }
      &.missing-bullet { background: #F59E0B; }
    }

    .status-pill-sub {
      font-size: 10px;
      font-weight: 700;
      padding: 1px 5px;
      border-radius: 3px;
      margin-right: 6px;
      display: inline-block;

      &.observed-pill {
        background: rgba(16, 185, 129, 0.15);
        color: #34D399;
        border: 1px solid rgba(16, 185, 129, 0.3);
      }
    }

    .missing-desc {
      display: block;
      font-size: 11px;
      color: #9CA3AF;
      margin-top: 4px;
      line-height: 1.4;
    }

    .evidence-governance-notice {
      margin-top: 18px;
      padding: 14px 16px;
      border-radius: 6px;
      background: rgba(245, 158, 11, 0.08);
      border: 1px solid rgba(245, 158, 11, 0.3);
      display: flex;
      gap: 12px;
      align-items: flex-start;

      .gov-flag-icon {
        font-size: 22px;
        color: #F59E0B;
        margin-top: 2px;
      }

      .gov-flag-content {
        font-size: 12px;
        color: #D1D5DB;
        line-height: 1.5;

        strong {
          color: #FBBF24;
        }
      }
    }

    /* MITRE Attribution Safeguard Styles */
    .mitre-safeguard-banner {
      display: flex;
      align-items: flex-start;
      gap: 14px;
      padding: 14px 18px;
      border-radius: 6px;
      margin-bottom: 8px;

      &.banner-candidate {
        background: rgba(59, 130, 246, 0.08);
        border: 1px solid rgba(59, 130, 246, 0.3);
        .banner-icon-box { color: #60A5FA; }
      }

      &.banner-unverified {
        background: rgba(245, 158, 11, 0.08);
        border: 1px solid rgba(245, 158, 11, 0.3);
        .banner-icon-box { color: #FBBF24; }
      }

      &.banner-verified {
        background: rgba(16, 185, 129, 0.08);
        border: 1px solid rgba(16, 185, 129, 0.3);
        .banner-icon-box { color: #34D399; }
      }

      &.banner-not_applicable {
        background: rgba(107, 114, 128, 0.08);
        border: 1px solid rgba(107, 114, 128, 0.3);
        .banner-icon-box { color: #9CA3AF; }
      }
    }

    .banner-icon-box {
      font-size: 24px;
      margin-top: 2px;
    }

    .banner-body {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }

    .banner-title-line {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }

    .banner-title {
      font-size: 13px;
      font-weight: 700;
      color: var(--tl-text-primary);
    }

    .mitre-pill {
      font-size: 10px;
      font-weight: 700;
      padding: 2px 7px;
      border-radius: 4px;
      text-transform: uppercase;
      letter-spacing: 0.5px;

      &.pill-candidate {
        background: rgba(59, 130, 246, 0.2);
        color: #93C5FD;
        border: 1px solid rgba(59, 130, 246, 0.4);
      }

      &.pill-unverified {
        background: rgba(245, 158, 11, 0.2);
        color: #FDE68A;
        border: 1px solid rgba(245, 158, 11, 0.4);
      }

      &.pill-verified {
        background: rgba(16, 185, 129, 0.2);
        color: #6EE7B7;
        border: 1px solid rgba(16, 185, 129, 0.4);
      }

      &.pill-not_applicable {
        background: rgba(107, 114, 128, 0.2);
        color: #D1D5DB;
        border: 1px solid rgba(107, 114, 128, 0.4);
      }
    }

    .banner-desc {
      font-size: 12px;
      color: #9CA3AF;
      margin: 0;
      line-height: 1.4;
    }

    .technique-meta {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }

    .technique-subtext {
      font-size: 11px;
      color: var(--tl-text-muted);
    }

    .status-indicator-badge {
      display: flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;

      &.indicator-candidate {
        background: rgba(59, 130, 246, 0.15);
        color: #60A5FA;
        border: 1px solid rgba(59, 130, 246, 0.4);
        .indicator-dot { background: #3B82F6; box-shadow: 0 0 6px #3B82F6; }
      }

      &.indicator-unverified {
        background: rgba(245, 158, 11, 0.15);
        color: #FBBF24;
        border: 1px solid rgba(245, 158, 11, 0.4);
        .indicator-dot { background: #F59E0B; box-shadow: 0 0 6px #F59E0B; }
      }

      &.indicator-verified {
        background: rgba(16, 185, 129, 0.15);
        color: #34D399;
        border: 1px solid rgba(16, 185, 129, 0.4);
        .indicator-dot { background: #10B981; box-shadow: 0 0 6px #10B981; }
      }

      &.indicator-not_applicable {
        background: rgba(107, 114, 128, 0.15);
        color: #9CA3AF;
        border: 1px solid rgba(107, 114, 128, 0.4);
        .indicator-dot { background: #6B7280; }
      }
    }

    .indicator-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
    }

    .telemetry-header {
      display: flex;
      align-items: center;
      gap: 6px;
      margin-bottom: 4px;

      .info-icon {
        font-size: 16px;
        color: var(--tl-cyan);
      }
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

  getMitreStatusLabel(status: string): string {
    switch (status?.toLowerCase()) {
      case 'candidate':
        return 'Candidate Mapping';
      case 'unverified':
        return 'Unverified Mapping';
      case 'verified':
        return 'Verified Attribution';
      case 'not_applicable':
        return 'Not Applicable (Benign)';
      default:
        return status ? status.toUpperCase() : 'Unknown';
    }
  }

  getMitreStatusIcon(status: string): string {
    switch (status?.toLowerCase()) {
      case 'candidate':
        return 'explore';
      case 'unverified':
        return 'help_outline';
      case 'verified':
        return 'verified';
      case 'not_applicable':
        return 'remove_circle_outline';
      default:
        return 'info';
    }
  }

  getMitreStatusTitle(status: string): string {
    switch (status?.toLowerCase()) {
      case 'candidate':
        return 'Behavioral Pattern Candidate (Attribution Unverified)';
      case 'unverified':
        return 'Preliminary Correlation (Insufficient Telemetry)';
      case 'verified':
        return 'Empirically Verified Technique Attribution';
      case 'not_applicable':
        return 'Benign Baseline Traffic (No Adversary Technique)';
      default:
        return 'MITRE ATT&CK Mapping Status';
    }
  }

  getMitreStatusDescription(status: string): string {
    switch (status?.toLowerCase()) {
      case 'candidate':
        return 'This profile matches network signatures associated with the MITRE technique, but lacks host-level artifacts required for verified attribution. ThreatLenz strictly designates this as a Candidate mapping to avoid premature or speculative attribution.';
      case 'unverified':
        return 'Observed network flow telemetry demonstrates weak or incomplete alignment with known adversary behavior. Corroborating endpoint or application telemetry is absent.';
      case 'verified':
        return 'Adversary technique attribution has been corroborated by multiple independent host and network telemetry sources.';
      case 'not_applicable':
        return 'This network profile represents standard baseline traffic. Adversary tactical mappings are not applicable.';
      default:
        return 'Mapping telemetry status evaluated according to ThreatLenz governance rules.';
    }
  }
}
