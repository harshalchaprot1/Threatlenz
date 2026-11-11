import { Component, Input, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, RouterModule } from '@angular/router';
import { MatTabsModule } from '@angular/material/tabs';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { forkJoin, of } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { ThreatLenzApiService } from '../../core/services/api.service';
import {
  AdvisoryResponse,
  MitreMappingResponse,
  ModelDiagnosticsResponse,
  RiskAssessmentResponse,
  ThreatProfileSummary,
} from '../../core/models';
import { resolveReliabilityTier } from '../../core/utils/reliability.util';
import {
  AdvisoryCardComponent,
  ReliabilityBadgeComponent,
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
              <app-reliability-badge [reliability]="resolvedReliabilityTier"></app-reliability-badge>
            </div>
            <div class="hero-meta-row">
              <span class="meta-item">
                <span class="meta-label">Raw Label:</span>
                <span class="meta-val font-mono">{{ profile.raw_label }}</span>
              </span>
              <span class="meta-divider">•</span>
              <span class="meta-item">
                <span class="meta-label">Run ID:</span>
                <span class="meta-val font-mono">{{ profile.run_id }}</span>
              </span>
            </div>
          </div>
        </div>

        <!-- Executive Profile Summary Ribbon -->
        <div class="executive-summary-ribbon" role="region" aria-label="Executive Profile Summary">
          <!-- Total Flows -->
          <app-stat-card
            title="Total Network Flows"
            [value]="profile.flow_count | number"
            subtitle="Observed Netflow records for this category"
            icon="alt_route"
            badgeText="Category Volume"
            badgeType="info"
          ></app-stat-card>

          <!-- Byte Volume -->
          <app-stat-card
            title="Aggregated Byte Volume"
            [value]="formatBytes(profile.total_bytes)"
            subtitle="Observed payload and packet header volume"
            icon="data_usage"
            badgeText="Transfer Volume"
            badgeType="default"
          ></app-stat-card>

          <!-- Recurrence -->
          <app-stat-card
            title="Observation Recurrence"
            [value]="(profile.recurrence_ratio * 100).toFixed(1) + '%'"
            [subtitle]="profile.active_observation_units + ' of ' + profile.recurrence_denominator + ' capture dates with active flows'"
            icon="calendar_month"
            badgeText="Capture Persistence"
            badgeType="warning"
          ></app-stat-card>

          <!-- Model Reliability -->
          <app-stat-card
            title="Model Reliability Tier"
            [value]="getReliabilityDisplayLabel(resolvedReliabilityTier)"
            subtitle="Strict validation gating (§5 standard)"
            icon="verified"
            [badgeText]="getReliabilityBadgeText(resolvedReliabilityTier)"
            [badgeType]="getReliabilityBadgeType(resolvedReliabilityTier)"
          ></app-stat-card>

          <!-- Classification Context -->
          <app-stat-card
            title="Classification Context"
            [value]="profile.is_attack ? 'Malicious Traffic' : 'Benign Baseline'"
            subtitle="Behavioral Netflow classification; not verified attacker attribution"
            icon="policy"
            [badgeText]="profile.canonical_label"
            [badgeType]="profile.is_attack ? 'danger' : 'success'"
          ></app-stat-card>
        </div>

        <!-- 4-Tab Section -->
        <div class="tabs-card">
          <mat-tab-group [selectedIndex]="selectedTabIndex" (selectedIndexChange)="onTabChange($event)" animationDuration="0ms" class="threat-tabs">
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

                <div class="traffic-summary-panel">
                  <div class="panel-header">
                    <span class="material-symbols-outlined panel-icon">insights</span>
                    <div class="panel-title-group">
                      <span class="panel-title">Netflow Traffic Behavior &amp; Volume Profile</span>
                      <span class="panel-subtitle">Aggregated statistical characteristics captured across enterprise capture interfaces</span>
                    </div>
                  </div>
                  <div class="traffic-metrics-strip">
                    <div class="traffic-metric-item">
                      <span class="tm-label">Average Packet Size:</span>
                      <span class="tm-val font-mono">
                        {{ profile.total_packets > 0 ? (profile.total_bytes / profile.total_packets | number:'1.1-1') + ' B/pkt' : 'N/A' }}
                      </span>
                    </div>
                    <div class="tm-divider"></div>
                    <div class="traffic-metric-item">
                      <span class="tm-label">Flow Packet Density:</span>
                      <span class="tm-val font-mono">
                        {{ profile.flow_count > 0 ? (profile.total_packets / profile.flow_count | number:'1.1-1') + ' pkts/flow' : 'N/A' }}
                      </span>
                    </div>
                    <div class="tm-divider"></div>
                    <div class="traffic-metric-item">
                      <span class="tm-label">Flow Byte Density:</span>
                      <span class="tm-val font-mono">
                        {{ profile.flow_count > 0 ? formatBytes(profile.total_bytes / profile.flow_count) + '/flow' : 'N/A' }}
                      </span>
                    </div>
                    <div class="tm-divider"></div>
                    <div class="traffic-metric-item">
                      <span class="tm-label">Capture Day Spread:</span>
                      <span class="tm-val font-mono">{{ profile.active_observation_units }} active days</span>
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
                  <!-- Authoritative Operational Governance Safeguard Disclosure -->
                  <div class="tlrs-governance-card" [class.confirmed-governance]="risk.is_confirmed">
                    <div class="gov-card-header">
                      <div class="gov-title-group">
                        <span class="material-symbols-outlined gov-main-icon">policy</span>
                        <div class="gov-title-content">
                          <h2 class="gov-primary-title">
                            {{ risk.is_confirmed ? 'Operational Risk Assessment Confirmed' : 'Operational Rating Withheld by Governance Policy' }}
                          </h2>
                          <span class="gov-subtitle">
                            {{ risk.is_confirmed ? 'Complete multi-factor evidence established across all four scoring dimensions' : 'Target asset criticality evidence absent in Netflow capture' }}
                          </span>
                        </div>
                      </div>
                      <div class="gov-status-pill" [class.confirmed-pill]="risk.is_confirmed">
                        <span class="status-dot"></span>
                        <span>{{ risk.is_confirmed ? 'RATING CONFIRMED' : 'OPERATIONAL RATING WITHHELD' }}</span>
                      </div>
                    </div>

                    <p class="gov-explanation">
                      @if (risk.is_confirmed) {
                        Target impact telemetry and destination asset criticality feeds have been fully established. The operational risk score and band reflect complete multi-factor evidence.
                      } @else {
                        Destination asset criticality information is unavailable in the current telemetry. Consequently, the Target Impact component and overall operational risk rating cannot be established.
                      }
                    </p>

                    <div class="gov-evidence-scope">
                      <div class="scope-stat">
                        <span class="scope-label">Combined Available Weight:</span>
                        <span class="scope-val font-mono">{{ (risk.evidence_coverage * 100).toFixed(0) }}%</span>
                        <span class="scope-sub">(Severity 40% + Frequency 25% + Recurrence 20%)</span>
                      </div>
                      <div class="scope-divider"></div>
                      <div class="scope-stat">
                        <span class="scope-label">Missing Dimension Weight:</span>
                        <span class="scope-val font-mono text-amber">15%</span>
                        <span class="scope-sub">(Target Impact Withheld)</span>
                      </div>
                    </div>
                  </div>

                  <!-- TLRS Metric Summary Cards -->
                  <div class="tlrs-metrics-grid">
                    <!-- Operational Rating Cell -->
                    <div class="tlrs-metric-card primary-card">
                      <div class="metric-top">
                        <span class="metric-label">Operational Risk Band</span>
                        <span class="material-symbols-outlined metric-icon">shield</span>
                      </div>
                      <div class="metric-center">
                        <span class="metric-large-text" [ngClass]="risk.is_confirmed ? 'confirmed-text' : 'withheld-text'">
                          {{ risk.is_confirmed ? risk.risk_band : 'Withheld' }}
                        </span>
                      </div>
                      <div class="metric-bottom">
                        <span class="metric-desc">
                          {{ risk.is_confirmed ? 'Approved operational rating' : 'Withheld by Governance Policy' }}
                        </span>
                      </div>
                    </div>

                    <!-- Diagnostic Heuristic Cell (Explicitly Subordinated) -->
                    <div class="tlrs-metric-card diagnostic-subordinated-card">
                      <div class="metric-top">
                        <span class="metric-label">Diagnostic Heuristic &mdash; Non-Operational</span>
                        <span class="diagnostic-badge">NON-OPERATIONAL</span>
                      </div>
                      <div class="metric-center">
                        <span class="metric-diagnostic-val font-mono">
                          {{ risk.tlrs_normalized_rounded }}<span class="denom">/100</span>
                        </span>
                      </div>
                      <div class="metric-bottom">
                        <span class="metric-desc text-muted">
                          Normalized heuristic based on 85% observed component weight only. Not an approved operational score.
                        </span>
                      </div>
                    </div>

                    <!-- Observed Partial Sum Cell -->
                    <div class="tlrs-metric-card">
                      <div class="metric-top">
                        <span class="metric-label">Observed Partial Contribution</span>
                        <span class="material-symbols-outlined metric-icon">functions</span>
                      </div>
                      <div class="metric-center">
                        <span class="metric-value font-mono">{{ risk.tlrs_partial_diagnostic.toFixed(2) }}<span class="denom">/85.00</span></span>
                      </div>
                      <div class="metric-bottom">
                        <span class="metric-desc text-muted">
                          Weighted sum of the 3 available components without extrapolation.
                        </span>
                      </div>
                    </div>

                    <!-- Evidence Component Coverage Cell -->
                    <div class="tlrs-metric-card">
                      <div class="metric-top">
                        <span class="metric-label">TLRS Component Availability</span>
                        <span class="material-symbols-outlined metric-icon">pie_chart</span>
                      </div>
                      <div class="metric-center">
                        <span class="metric-value font-mono">{{ (risk.evidence_coverage * 100).toFixed(0) }}%</span>
                      </div>
                      <div class="metric-bottom">
                        <span class="metric-desc text-muted">
                          3 of 4 components available. Missing target asset telemetry (15%).
                        </span>
                      </div>
                    </div>
                  </div>

                  <!-- Component Factor Weights Table -->
                  <div class="factors-section">
                    <div class="factors-header">
                      <div class="factors-title-group">
                        <h3 class="section-heading">Multi-Factor TLRS Component Evidence Breakdown</h3>
                        <p class="section-subtext">
                          Explainable multi-factor risk model combining severity prior, logarithmic flow volume, temporal recurrence, and asset criticality.
                        </p>
                      </div>
                      <div class="coverage-breakdown-tags">
                        <span class="comp-status-tag available">
                          <span class="tag-dot dot-avail"></span>
                          Severity: Available (40%)
                        </span>
                        <span class="comp-status-tag available">
                          <span class="tag-dot dot-avail"></span>
                          Frequency: Available (25%)
                        </span>
                        <span class="comp-status-tag available">
                          <span class="tag-dot dot-avail"></span>
                          Recurrence: Available (20%)
                        </span>
                        <span class="comp-status-tag unavailable">
                          <span class="tag-dot dot-unavail"></span>
                          Target Impact: Unavailable (15%)
                        </span>
                      </div>
                    </div>

                    <!-- Component Visual Contribution Bars -->
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
                          <span class="factor-sub">Component Score: {{ risk.severity_score.toFixed(1) }} / 100</span>
                          <span class="factor-source">Class Prior Threat Impact</span>
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
                          <span class="factor-sub">Component Score: {{ risk.frequency_score.toFixed(1) }} / 100</span>
                          <span class="factor-source">Logarithmic Netflow Count</span>
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
                          <span class="factor-sub">Component Score: {{ risk.recurrence_score.toFixed(1) }} / 100</span>
                          <span class="factor-source">Observed Capture Days Ratio</span>
                        </div>
                      </div>

                      <!-- Target Impact (Unavailable / Withheld) -->
                      <div class="evidence-bar-card unavailable-card">
                        <div class="bar-card-header">
                          <span class="factor-title text-amber">
                            <span class="material-symbols-outlined factor-icon amber-icon">warning_amber</span>
                            Target Impact (15%)
                          </span>
                          <span class="factor-status-badge">UNAVAILABLE &mdash; WITHHELD</span>
                        </div>
                        <div class="bar-track unavailable-track">
                          <div class="bar-fill unavailable-fill" style="width: 0%;"></div>
                        </div>
                        <div class="bar-card-footer">
                          <span class="factor-sub text-amber">Withheld (0.00 / 15.00 pts)</span>
                          <span class="factor-source">Missing Asset Criticality Feeds</span>
                        </div>
                      </div>
                    </div>

                    <!-- Clean Formatted Factor Breakdown Table -->
                    <div class="table-responsive">
                      <table class="factors-table">
                        <thead>
                          <tr>
                            <th>Scoring Component</th>
                            <th>Component Weight</th>
                            <th>Raw Component Score</th>
                            <th>Weighted Contribution</th>
                            <th>Evidence Status &amp; Telemetry Source</th>
                          </tr>
                        </thead>
                        <tbody>
                          <tr>
                            <td class="factor-name">
                              <span class="component-bullet sev-bullet"></span>
                              <strong>Severity</strong>
                              <span class="component-symbol font-mono">(S_sev)</span>
                            </td>
                            <td class="font-mono">40% (0.40)</td>
                            <td class="font-mono">{{ risk.severity_score.toFixed(1) }} / 100</td>
                            <td class="font-mono font-bold">{{ (risk.severity_score * risk.weight_severity).toFixed(2) }} / 40.00 pts</td>
                            <td>
                              <span class="status-pill-sub observed-pill">AVAILABLE &bull; OBSERVED</span>
                              <span class="telemetry-source-desc">Class prior threat impact potential</span>
                            </td>
                          </tr>
                          <tr>
                            <td class="factor-name">
                              <span class="component-bullet freq-bullet"></span>
                              <strong>Frequency</strong>
                              <span class="component-symbol font-mono">(S_freq)</span>
                            </td>
                            <td class="font-mono">25% (0.25)</td>
                            <td class="font-mono">{{ risk.frequency_score.toFixed(2) }} / 100</td>
                            <td class="font-mono font-bold">{{ (risk.frequency_score * risk.weight_frequency).toFixed(2) }} / 25.00 pts</td>
                            <td>
                              <span class="status-pill-sub observed-pill">AVAILABLE &bull; OBSERVED</span>
                              <span class="telemetry-source-desc">Logarithmic volume scaling relative to 1,000,000 reference flows</span>
                            </td>
                          </tr>
                          <tr>
                            <td class="factor-name">
                              <span class="component-bullet rec-bullet"></span>
                              <strong>Recurrence</strong>
                              <span class="component-symbol font-mono">(S_rec)</span>
                            </td>
                            <td class="font-mono">20% (0.20)</td>
                            <td class="font-mono">{{ risk.recurrence_score.toFixed(2) }} / 100</td>
                            <td class="font-mono font-bold">{{ (risk.recurrence_score * risk.weight_recurrence).toFixed(2) }} / 20.00 pts</td>
                            <td>
                              <span class="status-pill-sub observed-pill">AVAILABLE &bull; OBSERVED</span>
                              <span class="telemetry-source-desc">Active observation days across the 8-day capture window</span>
                            </td>
                          </tr>
                          <tr class="missing-row">
                            <td class="factor-name">
                              <span class="component-bullet missing-bullet"></span>
                              <strong>Target Impact</strong>
                              <span class="component-symbol font-mono">(S_target)</span>
                            </td>
                            <td class="font-mono">15% (0.15)</td>
                            <td class="font-mono text-muted">Unavailable</td>
                            <td class="font-mono text-muted">Withheld (0.00 / 15.00 pts)</td>
                            <td>
                              <span class="status-pill-sub unavailable-pill">UNAVAILABLE &bull; WITHHELD</span>
                              <span class="missing-desc">
                                Destination asset criticality is absent from Netflow records. Weight is not redistributed.
                              </span>
                            </td>
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
                  @if (mitre.mapping_status === 'not_applicable') {
                    <!-- Benign baseline: no mapping applicable -->
                    <div class="mitre-info-notice">
                      <span class="material-symbols-outlined notice-icon">info</span>
                      <span>This profile represents benign baseline traffic. No adversary technique mapping applies.</span>
                    </div>
                  } @else if (!mitre.is_confirmed) {
                    <!-- Unverified/candidate: neutral contextual disclosure -->
                    <div class="mitre-info-notice">
                      <span class="material-symbols-outlined notice-icon">policy</span>
                      <span>No evidence-verified ATT&CK attribution is currently available for this profile. The mapping below is a behavioral candidate derived from L4 Netflow flow signatures. Host-level telemetry required for verified attribution is listed in the card.</span>
                    </div>
                  }

                  @if (mitre.mapping_status !== 'not_applicable') {
                  <div class="mitre-card">
                    <div class="mitre-header">
                      <div class="mitre-technique">
                        @if (mitre.technique_id) {
                          <a
                            [href]="'https://attack.mitre.org/techniques/' + mitre.technique_id.replace('.', '/')"
                            target="_blank"
                            rel="noopener"
                            class="technique-link"
                            title="View on MITRE ATT&CK Framework"
                          >
                            <span class="technique-id font-mono">{{ mitre.technique_id }}</span>
                            <span class="material-symbols-outlined" style="font-size: 15px;">open_in_new</span>
                          </a>
                        } @else {
                          <span class="technique-none font-mono">None (Baseline)</span>
                        }
                        <div class="technique-meta">
                          <span class="technique-name">{{ mitre.technique_name || 'No Technique Mapped' }}</span>
                          <span class="technique-subtext">
                            @if (mitre.mapping_status === 'candidate') {
                              Behavioral Candidate Pattern (Attribution Unverified)
                            } @else if (mitre.mapping_status === 'unverified') {
                              Unverified Traffic Correlation (Insufficient Telemetry)
                            } @else if (mitre.mapping_status === 'verified') {
                              Verified Technique Attribution
                            } @else {
                              Benign Baseline (No Adversary Technique Mapped)
                            }
                          </span>
                        </div>
                      </div>

                      <div class="mitre-status-box">
                        <span class="status-pill" [ngClass]="'status-' + mitre.mapping_status">
                          <span class="status-dot"></span>
                          <span>{{ getMitreStatusLabel(mitre.mapping_status) }}</span>
                        </span>
                      </div>
                    </div>

                    <div class="mitre-body">
                      <div class="tactic-row">
                        <span class="tactic-label">Enterprise ATT&CK Tactic:</span>
                        @if (mitre.tactic) {
                          <span class="tactic-tag">{{ mitre.tactic }}</span>
                        } @else {
                          <span class="tactic-none text-muted">&mdash;</span>
                        }
                      </div>

                      <div class="rationale-block">
                        <span class="block-title">Mapping Rationale &amp; Observable Evidence</span>
                        <p class="rationale-text">{{ mitre.rationale }}</p>
                      </div>

                      <div class="telemetry-block">
                        <div class="telemetry-header">
                          <span class="material-symbols-outlined info-icon">info</span>
                          <span class="block-title">Required Telemetry for Attribution Verification</span>
                        </div>
                        <p class="telemetry-intro">
                          Flow statistics provide behavioral correlation only, not verified threat attribution. The following host or payload telemetry is missing and required before this technique can be marked verified:
                        </p>
                        @if (mitre.missing_telemetry && mitre.missing_telemetry.length > 0) {
                          <div class="telemetry-tags-wrap">
                            @for (item of mitre.missing_telemetry; track item) {
                              <span class="tel-tag" [attr.title]="item">
                                <span class="material-symbols-outlined tel-icon">data_alert</span>
                                <span>{{ item }}</span>
                              </span>
                            }
                          </div>
                        } @else {
                          <span class="tel-none text-muted">Baseline non-malicious traffic (No host telemetry required)</span>
                        }
                      </div>
                    </div>

                    <div class="mitre-footer">
                      <div class="footer-note">
                        <span class="material-symbols-outlined note-icon">info</span>
                        <span>
                          Technique ID links directly to the official MITRE ATT&CK knowledge base. Mappings represent prospective tactical hypotheses based on Netflow flow signatures.
                        </span>
                      </div>
                    </div>
                  </div>
                  }
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
                    <span class="gov-title">Advisory recommendations — analyst review required before implementation.</span>
                    <span class="gov-desc">
                      ThreatLenz recommendations are strictly advisory and non-destructive. Automated firewall block scripts and configuration changes are prohibited without human authorization.
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

        <!-- Progressive Technical Disclosure Accordion -->
        <div class="provenance-accordion-wrapper">
          <details class="provenance-accordion" [open]="isProvenanceOpen" (toggle)="onProvenanceToggle($event)">
            <summary class="provenance-summary">
              <div class="summary-left">
                <span class="material-symbols-outlined summary-icon">code</span>
                <div class="summary-titles">
                  <span class="summary-main-title">Technical Provenance &amp; Execution Details</span>
                  <span class="summary-sub-title">Deterministic identity identifiers, manifest integrity hashes, and temporal partition semantics</span>
                </div>
              </div>
              <div class="summary-right">
                <span class="provenance-pill">
                  <span class="material-symbols-outlined pill-icon">lock</span>
                  <span>Pipeline Audit Trail</span>
                </span>
                <span class="material-symbols-outlined chevron-icon">expand_more</span>
              </div>
            </summary>

            <div class="provenance-content">
              <div class="provenance-grid">
                <!-- Group 1: Deterministic Identity Keys -->
                <div class="provenance-card">
                  <div class="pcard-header">
                    <span class="material-symbols-outlined pcard-icon">fingerprint</span>
                    <span class="pcard-title">Deterministic Identity Provenance</span>
                  </div>
                  <div class="pcard-list">
                    <div class="pcard-row">
                      <span class="pcard-key">Profile ID (Natural Key):</span>
                      <span class="pcard-val font-mono select-all" [attr.title]="profile.profile_id">
                        {{ profile.profile_id }}
                      </span>
                    </div>

                    <div class="pcard-row">
                      <span class="pcard-key">Execution Run ID:</span>
                      <span class="pcard-val font-mono select-all">
                        {{ profile.run_id }}
                      </span>
                    </div>
                    <div class="pcard-row">
                      <span class="pcard-key">Source Manifest SHA-256:</span>
                      <span class="pcard-val font-mono select-all break-all" [attr.title]="profile.source_manifest_hash">
                        {{ profile.source_manifest_hash }}
                      </span>
                    </div>
                    <div class="pcard-row">
                      <span class="pcard-key">Schema Version:</span>
                      <span class="pcard-val font-mono">
                        {{ profile.schema_version }}
                      </span>
                    </div>
                  </div>
                </div>

                <!-- Group 2: Temporal Observation Window & Semantics -->
                <div class="provenance-card">
                  <div class="pcard-header">
                    <span class="material-symbols-outlined pcard-icon">date_range</span>
                    <span class="pcard-title">Temporal Observation Window</span>
                  </div>
                  <div class="pcard-list">
                    <div class="pcard-row">
                      <span class="pcard-key">Window Type:</span>
                      <span class="pcard-val">{{ profile.window_type }}</span>
                    </div>
                    <div class="pcard-row">
                      <span class="pcard-key">Interval Start:</span>
                      <span class="pcard-val font-mono">{{ profile.window_start | date:'yyyy-MM-dd HH:mm:ss' }} UTC</span>
                    </div>
                    <div class="pcard-row">
                      <span class="pcard-key">Interval End:</span>
                      <span class="pcard-val font-mono">{{ profile.window_end | date:'yyyy-MM-dd HH:mm:ss' }} UTC</span>
                    </div>
                    <div class="pcard-row">
                      <span class="pcard-key">Interval Semantics:</span>
                      <span class="pcard-val font-mono">[window_start, window_end) half-open</span>
                    </div>
                    <div class="pcard-row">
                      <span class="pcard-key">Observation Partitions:</span>
                      <span class="pcard-val font-mono">{{ profile.active_observation_units }} of {{ profile.recurrence_denominator }} dates</span>
                    </div>
                  </div>
                </div>
              </div>

              <div class="provenance-footer-note">
                <span class="material-symbols-outlined note-icon">verified_user</span>
                <span>
                  All profile snapshots are deterministically generated by the PySpark analytical pipeline. Immutable snapshot hashes guarantee provenance verification against the source Netflow manifest.
                </span>
              </div>
            </div>
          </details>
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

    /* Traffic Summary Panel in Tab 1 */
    .traffic-summary-panel {
      background: var(--tl-bg-card);
      border: 1px solid var(--tl-border);
      border-radius: 6px;
      padding: 16px 18px;
      display: flex;
      flex-direction: column;
      gap: 14px;
    }

    .panel-header {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .panel-icon {
      font-size: 22px;
      color: var(--tl-cyan);
    }

    .panel-title-group {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }

    .panel-title {
      font-size: 13px;
      font-weight: 700;
      color: var(--tl-text-primary);
    }

    .panel-subtitle {
      font-size: 11.5px;
      color: var(--tl-text-muted);
    }

    .traffic-metrics-strip {
      display: flex;
      align-items: center;
      gap: 16px;
      background: rgba(0, 0, 0, 0.25);
      border: 1px solid rgba(255, 255, 255, 0.04);
      border-radius: 4px;
      padding: 10px 14px;
      flex-wrap: wrap;
    }

    .traffic-metric-item {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 12px;
    }

    .tm-label {
      color: var(--tl-text-muted);
      font-weight: 500;
    }

    .tm-val {
      color: var(--tl-text-primary);
      font-weight: 700;
    }

    .tm-divider {
      width: 1px;
      height: 16px;
      background: var(--tl-border);
    }

    /* Progressive Technical Disclosure Accordion */
    .provenance-accordion-wrapper {
      margin-top: 4px;
    }

    .provenance-accordion {
      background: var(--tl-bg-surface);
      border: 1px solid var(--tl-border);
      border-radius: 8px;
      overflow: hidden;
      transition: border-color 0.15s ease;

      &[open] {
        border-color: rgba(6, 182, 212, 0.3);

        .chevron-icon {
          transform: rotate(180deg);
        }
      }
    }

    .provenance-summary {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 14px 18px;
      background: rgba(15, 23, 42, 0.6);
      cursor: pointer;
      user-select: none;
      list-style: none;
      gap: 12px;
      transition: background 0.15s ease;

      &::-webkit-details-marker {
        display: none;
      }

      &:hover {
        background: rgba(15, 23, 42, 0.85);
      }
    }

    .summary-left {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .summary-icon {
      font-size: 20px;
      color: var(--tl-cyan);
    }

    .summary-titles {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }

    .summary-main-title {
      font-size: 13.5px;
      font-weight: 700;
      color: var(--tl-text-primary);
      letter-spacing: -0.2px;
    }

    .summary-sub-title {
      font-size: 11.5px;
      color: var(--tl-text-muted);
    }

    .summary-right {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .provenance-pill {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      font-size: 11px;
      font-weight: 600;
      color: var(--tl-cyan);
      background: rgba(6, 182, 212, 0.08);
      border: 1px solid rgba(6, 182, 212, 0.25);
      padding: 3px 8px;
      border-radius: 4px;

      .pill-icon {
        font-size: 13px;
      }
    }

    .chevron-icon {
      font-size: 20px;
      color: var(--tl-text-muted);
      transition: transform 0.2s ease;
    }

    .provenance-content {
      padding: 18px 20px;
      display: flex;
      flex-direction: column;
      gap: 16px;
      border-top: 1px solid var(--tl-border);
      background: rgba(15, 23, 42, 0.3);
    }

    .provenance-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
      gap: 16px;
    }

    .provenance-card {
      background: var(--tl-bg-card);
      border: 1px solid var(--tl-border);
      border-radius: 6px;
      padding: 14px 16px;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .pcard-header {
      display: flex;
      align-items: center;
      gap: 8px;
      padding-bottom: 6px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    }

    .pcard-icon {
      font-size: 18px;
      color: var(--tl-cyan);
    }

    .pcard-title {
      font-size: 12px;
      font-weight: 700;
      color: var(--tl-text-primary);
      text-transform: uppercase;
      letter-spacing: 0.4px;
    }

    .pcard-list {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .pcard-row {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 12px;
      font-size: 12px;
    }

    .pcard-key {
      color: var(--tl-text-muted);
      font-weight: 500;
      white-space: nowrap;
    }

    .pcard-val {
      color: var(--tl-text-primary);
      text-align: right;
      word-break: break-all;
    }

    .break-all {
      word-break: break-all;
      font-size: 11px;
      max-width: 240px;
    }

    .select-all {
      user-select: all;
    }

    .provenance-footer-note {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 11px;
      color: var(--tl-text-muted);
      line-height: 1.45;
      padding-top: 4px;

      .note-icon {
        font-size: 15px;
        color: var(--tl-cyan);
        flex-shrink: 0;
      }
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

    /* Executive Profile Summary Ribbon */
    .executive-summary-ribbon {
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 14px;
      margin-top: -6px;
      margin-bottom: 2px;
    }

    @media (max-width: 1400px) {
      .executive-summary-ribbon {
        grid-template-columns: repeat(3, 1fr);
      }
    }

    @media (max-width: 900px) {
      .executive-summary-ribbon {
        grid-template-columns: repeat(2, 1fr);
      }
    }

    @media (max-width: 600px) {
      .executive-summary-ribbon {
        grid-template-columns: 1fr;
      }
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

    /* Authoritative TLRS Governance Card */
    .tlrs-governance-card {
      background: rgba(15, 23, 42, 0.6);
      border: 1px solid rgba(245, 158, 11, 0.35);
      border-left: 4px solid #F59E0B;
      border-radius: 6px;
      padding: 16px 20px;
      display: flex;
      flex-direction: column;
      gap: 12px;

      &.confirmed-governance {
        border-color: rgba(16, 185, 129, 0.35);
        border-left-color: #10B981;
      }
    }

    .gov-card-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
    }

    .gov-title-group {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .gov-main-icon {
      font-size: 26px;
      color: #F59E0B;
    }

    .confirmed-governance .gov-main-icon {
      color: #10B981;
    }

    .gov-title-content {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }

    .gov-primary-title {
      font-size: 15px;
      font-weight: 700;
      color: var(--tl-text-primary);
      margin: 0;
      letter-spacing: -0.3px;
    }

    .gov-subtitle {
      font-size: 12px;
      color: var(--tl-text-muted);
    }

    .gov-status-pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: rgba(245, 158, 11, 0.12);
      border: 1px solid rgba(245, 158, 11, 0.35);
      color: #FBBF24;
      font-size: 11px;
      font-weight: 700;
      padding: 4px 10px;
      border-radius: 4px;
      letter-spacing: 0.4px;

      .status-dot {
        width: 6px;
        height: 6px;
        border-radius: 50%;
        background: #F59E0B;
      }

      &.confirmed-pill {
        background: rgba(16, 185, 129, 0.12);
        border-color: rgba(16, 185, 129, 0.35);
        color: #34D399;

        .status-dot {
          background: #10B981;
        }
      }
    }

    .gov-explanation {
      margin: 0;
      font-size: 12.5px;
      color: #CBD5E1;
      line-height: 1.55;
    }

    .gov-evidence-scope {
      display: flex;
      align-items: center;
      gap: 20px;
      background: rgba(0, 0, 0, 0.25);
      border: 1px solid rgba(255, 255, 255, 0.04);
      border-radius: 4px;
      padding: 10px 14px;
      flex-wrap: wrap;
    }

    .scope-stat {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 12px;
      color: var(--tl-text-secondary);
      flex-wrap: wrap;
    }

    .scope-label {
      font-weight: 600;
      color: var(--tl-text-muted);
    }

    .scope-val {
      font-size: 13px;
      font-weight: 700;
      color: var(--tl-text-primary);
    }

    .scope-sub {
      font-size: 11px;
      color: var(--tl-text-muted);
    }

    .scope-divider {
      width: 1px;
      height: 16px;
      background: var(--tl-border);
    }

    /* TLRS Metrics Grid */
    .tlrs-metrics-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 16px;
    }

    .tlrs-metric-card {
      background: var(--tl-bg-card);
      border: 1px solid var(--tl-border);
      border-radius: 6px;
      padding: 14px 16px;
      display: flex;
      flex-direction: column;
      gap: 8px;

      &.primary-card {
        border-color: rgba(245, 158, 11, 0.3);
        background: rgba(245, 158, 11, 0.03);
      }

      &.diagnostic-subordinated-card {
        background: rgba(15, 23, 42, 0.4);
        border: 1px dashed rgba(255, 255, 255, 0.12);
      }
    }

    .metric-top {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
    }

    .metric-label {
      font-size: 11px;
      font-weight: 700;
      color: var(--tl-text-muted);
      text-transform: uppercase;
      letter-spacing: 0.4px;
    }

    .metric-icon {
      font-size: 18px;
      color: var(--tl-text-muted);
    }

    .diagnostic-badge {
      font-size: 9.5px;
      font-weight: 700;
      padding: 1px 5px;
      border-radius: 3px;
      background: rgba(148, 163, 184, 0.15);
      border: 1px solid rgba(148, 163, 184, 0.3);
      color: #94A3B8;
      letter-spacing: 0.3px;
    }

    .metric-center {
      display: flex;
      align-items: baseline;
      gap: 4px;
    }

    .metric-large-text {
      font-size: 20px;
      font-weight: 700;
      letter-spacing: -0.3px;
    }

    .metric-diagnostic-val {
      font-size: 20px;
      font-weight: 700;
      color: #CBD5E1;
    }

    .metric-value {
      font-size: 20px;
      font-weight: 700;
      color: var(--tl-text-primary);
    }

    .denom {
      font-size: 13px;
      font-weight: 500;
      color: var(--tl-text-muted);
      margin-left: 2px;
    }

    .metric-bottom {
      margin-top: auto;
    }

    .metric-desc {
      font-size: 11px;
      color: var(--tl-text-secondary);
      line-height: 1.4;
    }

    /* Factors Section Refinement */
    .factors-title-group {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }

    .section-subtext {
      margin: 0;
      font-size: 12px;
      color: var(--tl-text-muted);
    }

    .coverage-breakdown-tags {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }

    .comp-status-tag {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: 11px;
      padding: 3px 8px;
      border-radius: 4px;
      font-weight: 500;

      .tag-dot {
        width: 6px;
        height: 6px;
        border-radius: 50%;
      }

      &.available {
        background: rgba(16, 185, 129, 0.08);
        border: 1px solid rgba(16, 185, 129, 0.25);
        color: #A7F3D0;
        .tag-dot { background: #10B981; }
      }

      &.unavailable {
        background: rgba(245, 158, 11, 0.08);
        border: 1px solid rgba(245, 158, 11, 0.25);
        color: #FDE68A;
        .tag-dot { background: #F59E0B; }
      }
    }

    .component-symbol {
      font-size: 11px;
      color: var(--tl-text-muted);
      margin-left: 4px;
    }

    .telemetry-source-desc {
      display: block;
      font-size: 11px;
      color: var(--tl-text-muted);
      margin-top: 3px;
    }

    .font-bold {
      font-weight: 700;
    }

    .unavailable-pill {
      background: rgba(245, 158, 11, 0.12);
      color: #FBBF24;
      border: 1px solid rgba(245, 158, 11, 0.3);
    }

    @media (max-width: 1200px) {
      .tlrs-metrics-grid {
        grid-template-columns: repeat(2, 1fr);
      }
    }

    @media (max-width: 640px) {
      .tlrs-metrics-grid {
        grid-template-columns: 1fr;
      }
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

    /* MITRE Telemetry Boundary & Attribution Safeguard Styles */
    .boundary-disclosure-panel {
      background: rgba(15, 23, 42, 0.5);
      border: 1px solid rgba(6, 182, 212, 0.25);
      border-left: 3px solid var(--tl-cyan);
      border-radius: 6px;
      padding: 14px 16px;
      display: flex;
      flex-direction: column;
      gap: 10px;
      margin-bottom: 8px;
    }

    .disclosure-header {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .boundary-icon {
      font-size: 20px;
      color: var(--tl-cyan);
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
      color: var(--tl-text-primary);
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
        color: var(--tl-text-primary);
      }
    }

    /* MITRE — contextual neutral notice (non-verified / candidate / benign) */
    .mitre-info-notice {
      display: flex;
      align-items: flex-start;
      gap: 10px;
      background: rgba(59, 130, 246, 0.07);
      border: 1px solid rgba(59, 130, 246, 0.2);
      border-radius: 6px;
      padding: 12px 16px;
      margin-bottom: 8px;
      font-size: 13px;
      color: var(--tl-text-secondary);
      line-height: 1.55;

      .notice-icon {
        font-size: 18px;
        color: #60A5FA;
        flex-shrink: 0;
        margin-top: 1px;
      }
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

    .status-pill {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      font-size: 11px;
      font-weight: 600;
      padding: 3px 9px;
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

    .mitre-body {
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .tactic-row {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 13px;
    }

    .tactic-label {
      color: var(--tl-text-muted);
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

    .rationale-text {
      font-size: 13px;
      color: #D1D5DB;
      line-height: 1.6;
      margin: 4px 0 0 0;
    }

    .telemetry-intro {
      font-size: 12px;
      color: var(--tl-text-secondary);
      margin: 4px 0 10px 0;
    }

    .telemetry-tags-wrap {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
    }

    .tel-tag {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      font-size: 11px;
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid rgba(255, 255, 255, 0.08);
      padding: 3px 8px;
      border-radius: 4px;
      color: #CBD5E1;
      line-height: 1.3;

      .tel-icon {
        font-size: 14px;
        color: var(--tl-amber, #F59E0B);
        opacity: 0.9;
      }
    }

    .tel-none {
      font-size: 12px;
    }

    .mitre-footer {
      border-top: 1px solid var(--tl-border);
      padding-top: 12px;
      margin-top: 4px;
    }

    .footer-note {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 11.5px;
      color: var(--tl-text-muted);

      .note-icon {
        font-size: 15px;
        color: var(--tl-cyan);
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
  isProvenanceOpen: boolean = false;

  profile: ThreatProfileSummary | null = null;
  risk: RiskAssessmentResponse | null = null;
  mitre: MitreMappingResponse | null = null;
  advisories: AdvisoryResponse[] = [];
  resolvedReliabilityTier: string | null = null;
  selectedTabIndex: number = 0;

  constructor(
    private readonly apiService: ThreatLenzApiService,
    private readonly route: ActivatedRoute
  ) {}

  ngOnInit(): void {
    const tabParam = this.route.snapshot.queryParamMap.get('tab');
    if (tabParam) {
      const tabNum = parseInt(tabParam, 10);
      if (!isNaN(tabNum) && tabNum >= 0 && tabNum <= 3) {
        this.selectedTabIndex = tabNum;
      } else if (tabParam.toLowerCase() === 'mitre') {
        this.selectedTabIndex = 2;
      }
    }
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
      diagnostics: this.apiService.getModelDiagnostics().pipe(
        catchError(() => of(null as ModelDiagnosticsResponse | null))
      ),
    }).subscribe({
      next: ({ profile, risk, mitre, advisories, diagnostics }) => {
        this.profile = profile;
        this.risk = risk;
        this.mitre = mitre;
        this.advisories = advisories.items;
        this.resolvedReliabilityTier = resolveReliabilityTier(profile, diagnostics);
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
        return 'Candidate Profile';
      case 'unverified':
        return 'Unverified Mapping';
      case 'verified':
        return 'Verified Attribution';
      case 'not_applicable':
        return 'Benign Baseline';
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

  getReliabilityDisplayLabel(rel?: string | null): string {
    if (rel === 'BASELINE') return 'Baseline (N/A)';
    if (rel === 'UNAVAILABLE') return 'Evaluation Unavailable';
    if (rel === 'UNMATCHED') return 'Unevaluated Class';
    switch (rel) {
      case 'HIGH_RELIABILITY': return 'High Reliability';
      case 'EVALUABLE': return 'Evaluable';
      case 'UNRELIABLE': return 'Unreliable (Excluded)';
      case 'NON_EVALUABLE': return 'Non-Evaluable';
      default: return rel ? String(rel) : 'Baseline (N/A)';
    }
  }

  getReliabilityBadgeType(rel?: string | null): 'default' | 'success' | 'warning' | 'danger' | 'info' {
    switch (rel) {
      case 'HIGH_RELIABILITY': return 'success';
      case 'EVALUABLE': return 'info';
      case 'UNRELIABLE': return 'warning';
      case 'NON_EVALUABLE': return 'danger';
      case 'UNMATCHED': return 'warning';
      case 'UNAVAILABLE':
      case 'BASELINE':
      default:
        return 'default';
    }
  }

  getReliabilityBadgeText(rel?: string | null): string {
    switch (rel) {
      case 'BASELINE': return 'Negative Baseline';
      case 'HIGH_RELIABILITY':
      case 'EVALUABLE':
      case 'UNRELIABLE':
      case 'NON_EVALUABLE':
        return 'Gated Benchmark';
      case 'UNAVAILABLE': return 'Telemetry Unavailable';
      case 'UNMATCHED': return 'No Evaluation Record';
      default: return 'Negative Baseline';
    }
  }

  onProvenanceToggle(event: Event): void {
    const details = event.target as HTMLDetailsElement;
    this.isProvenanceOpen = details.open;
  }

  onTabChange(index: number): void {
    this.selectedTabIndex = index;
  }
}
