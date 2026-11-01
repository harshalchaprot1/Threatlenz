import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { forkJoin } from 'rxjs';
import { ThreatLenzApiService } from '../../core/services/api.service';
import {
  DestinationPortAnalyticsResponse,
  FeatureRedundancyResponse,
  MitreMappingResponse,
  ThreatProfileSummary,
} from '../../core/models';
import {
  PortMatrixHeatmapComponent,
  FeatureRedundancyTableComponent,
  MitreCoverageSummaryComponent,
  MitreProfileSummaryItem,
  StatCardComponent,
} from '../../shared/components';

export type ReportTab = 'all' | 'ports' | 'redundancy' | 'mitre';

@Component({
  selector: 'app-reports',
  standalone: true,
  imports: [
    CommonModule,
    MatButtonModule,
    MatIconModule,
    MatProgressSpinnerModule,
    StatCardComponent,
    PortMatrixHeatmapComponent,
    FeatureRedundancyTableComponent,
    MitreCoverageSummaryComponent,
  ],
  template: `
    <div class="reports-container">
      <!-- Page Header -->
      <div class="page-header">
        <div class="header-titles">
          <h1 class="page-title">Analytical Intelligence Reports</h1>
          <p class="page-subtitle">
            Cross-campaign destination port concentrations, feature collinearity pruning, and enterprise MITRE ATT&CK candidate coverage.
          </p>
        </div>
        <div class="header-provenance">
          <span class="prov-tag">
            <span class="material-symbols-outlined prov-icon">dataset</span>
            Dataset: CSE-CIC-IDS2018 Enterprise Netflow
          </span>
        </div>
      </div>

      <!-- Loading State -->
      @if (loading) {
        <div class="state-container">
          <mat-spinner diameter="44"></mat-spinner>
          <span>Compiling cross-campaign analytical intelligence reports...</span>
        </div>
      }

      <!-- Error State -->
      @if (errorMessage && !loading) {
        <div class="state-container error-state" role="alert">
          <span class="material-symbols-outlined state-icon">error</span>
          <h3>Analytical Telemetry Unavailable</h3>
          <p>{{ errorMessage }}</p>
          <button mat-flat-button color="accent" (click)="loadReportsData()">
            Retry Report Queries
          </button>
        </div>
      }

      <!-- Main Reports Content -->
      @if (!loading && !errorMessage) {
        <!-- Executive Analytical KPI Strip -->
        <div class="kpi-grid">
          <app-stat-card
            title="Analyzed Network Flows"
            [value]="totalFlowsFormatted"
            subtitle="Complete CSE-CIC-IDS2018 dataset records"
            icon="analytics"
            badgeText="Full Ingestion"
            badgeType="info"
          ></app-stat-card>

          <app-stat-card
            title="Evaluated Categories"
            [value]="evaluatedCategoriesCount.toString()"
            subtitle="13 threat categories + 1 Benign baseline"
            icon="coronavirus"
            badgeText="14 Classes"
            badgeType="default"
          ></app-stat-card>

          <app-stat-card
            title="Evaluated Redundancy Pairs"
            [value]="evaluatedPairsCount.toString()"
            subtitle="Pearson correlation pairs audited (6 near-duplicate)"
            icon="compare_arrows"
            badgeText="9 Pairs Audited"
            badgeType="warning"
          ></app-stat-card>

          <app-stat-card
            title="MITRE Verified Attribution"
            [value]="verifiedMitreCount.toString()"
            subtitle="Netflow L4 boundary; host telemetry required"
            icon="verified_user"
            badgeText="0 Verified (13 Candidate)"
            badgeType="default"
          ></app-stat-card>
        </div>

        <!-- Section Navigation Tabs -->
        <div class="section-nav">
          <div class="nav-tabs" role="tablist" aria-label="Analytical Report Sections">
            <button
              class="nav-tab-btn"
              [class.active]="activeTab === 'all'"
              (click)="setActiveTab('all')"
              role="tab"
              [attr.aria-selected]="activeTab === 'all'"
            >
              <span class="material-symbols-outlined tab-icon">dashboard</span>
              <span>All Analytical Sections</span>
            </button>

            <button
              class="nav-tab-btn"
              [class.active]="activeTab === 'ports'"
              (click)="setActiveTab('ports')"
              role="tab"
              [attr.aria-selected]="activeTab === 'ports'"
            >
              <span class="material-symbols-outlined tab-icon">hub</span>
              <span>Network &amp; Port Concentration</span>
            </button>

            <button
              class="nav-tab-btn"
              [class.active]="activeTab === 'redundancy'"
              (click)="setActiveTab('redundancy')"
              role="tab"
              [attr.aria-selected]="activeTab === 'redundancy'"
            >
              <span class="material-symbols-outlined tab-icon">schema</span>
              <span>Feature Collinearity &amp; Redundancy</span>
            </button>

            <button
              class="nav-tab-btn"
              [class.active]="activeTab === 'mitre'"
              (click)="setActiveTab('mitre')"
              role="tab"
              [attr.aria-selected]="activeTab === 'mitre'"
            >
              <span class="material-symbols-outlined tab-icon">policy</span>
              <span>MITRE ATT&amp;CK Framework Mapping</span>
            </button>
          </div>
        </div>

        <div class="reports-grid">
          <!-- SECTION 1: Destination Port Concentration Heatmap -->
          @if (activeTab === 'all' || activeTab === 'ports') {
            <section class="report-section" aria-label="Network & Port Concentration">
              <app-port-matrix-heatmap
                [portData]="portData"
                [loading]="loading"
              ></app-port-matrix-heatmap>
            </section>
          }

          <!-- SECTION 2: Feature Redundancy & Correlation Pruning -->
          @if (activeTab === 'all' || activeTab === 'redundancy') {
            <section class="report-section" aria-label="Feature Collinearity & Redundancy">
              <app-feature-redundancy-table
                [redundancyData]="redundancyData"
                [loading]="loading"
              ></app-feature-redundancy-table>
            </section>
          }

          <!-- SECTION 3: MITRE ATT&CK Coverage & Telemetry Gap Analysis -->
          @if (activeTab === 'all' || activeTab === 'mitre') {
            <section class="report-section" aria-label="MITRE ATT&CK Framework Mapping">
              <app-mitre-coverage-summary
                [profilesWithMitre]="mitreItems"
                [loading]="loading"
              ></app-mitre-coverage-summary>
            </section>
          }
        </div>
      }
    </div>
  `,
  styles: [`
    .reports-container {
      display: flex;
      flex-direction: column;
      gap: 20px;
    }

    .page-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 16px;
    }

    .header-titles {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }

    .page-title {
      font-size: 20px;
      font-weight: 700;
      color: var(--tl-text-primary, #F8FAFC);
      margin: 0;
      letter-spacing: -0.5px;
    }

    .page-subtitle {
      font-size: 13px;
      color: var(--tl-text-secondary, #94A3B8);
      margin: 0;
    }

    .header-provenance {
      display: flex;
      align-items: center;
    }

    .prov-tag {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: rgba(6, 182, 212, 0.08);
      border: 1px solid rgba(6, 182, 212, 0.25);
      color: var(--tl-cyan, #06B6D4);
      padding: 4px 10px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;

      .prov-icon {
        font-size: 14px;
      }
    }

    /* Executive KPI Strip */
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 16px;
    }

    /* Section Navigation */
    .section-nav {
      display: flex;
      align-items: center;
      border-bottom: 1px solid var(--tl-border, rgba(255, 255, 255, 0.08));
      padding-bottom: 2px;
    }

    .nav-tabs {
      display: flex;
      gap: 8px;
      overflow-x: auto;
      scrollbar-width: none;
      -webkit-overflow-scrolling: touch;

      &::-webkit-scrollbar {
        display: none;
      }
    }

    .nav-tab-btn {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 8px 14px;
      border-radius: 6px;
      background: transparent;
      border: 1px solid transparent;
      color: var(--tl-text-secondary, #94A3B8);
      font-size: 13px;
      font-weight: 500;
      cursor: pointer;
      white-space: nowrap;
      transition: all 0.15s ease-in-out;

      .tab-icon {
        font-size: 16px;
        color: var(--tl-text-muted, #64748B);
      }

      &:hover {
        background: rgba(255, 255, 255, 0.04);
        color: var(--tl-text-primary, #F8FAFC);
        border-color: rgba(255, 255, 255, 0.06);

        .tab-icon {
          color: var(--tl-text-primary, #F8FAFC);
        }
      }

      &.active {
        background: rgba(6, 182, 212, 0.12);
        color: var(--tl-cyan, #06B6D4);
        border-color: rgba(6, 182, 212, 0.35);
        font-weight: 600;

        .tab-icon {
          color: var(--tl-cyan, #06B6D4);
        }
      }
    }

    .reports-grid {
      display: flex;
      flex-direction: column;
      gap: 24px;
    }

    .report-section {
      display: flex;
      flex-direction: column;
    }

    .state-container {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      min-height: 350px;
      gap: 16px;
      background: var(--tl-bg-surface, #1E293B);
      border: 1px solid var(--tl-border, rgba(255, 255, 255, 0.08));
      border-radius: 8px;
      color: var(--tl-text-secondary, #94A3B8);
    }

    .error-state {
      .state-icon {
        font-size: 44px;
        color: #EF4444;
      }
      h3 {
        color: var(--tl-text-primary, #F8FAFC);
        margin: 0;
      }
      p {
        margin: 0 0 16px 0;
        max-width: 480px;
        text-align: center;
      }
    }

    /* Responsive Breakpoints */
    @media (max-width: 1200px) {
      .kpi-grid {
        grid-template-columns: repeat(2, 1fr);
      }
    }

    @media (max-width: 640px) {
      .kpi-grid {
        grid-template-columns: 1fr;
      }
      .nav-tabs {
        width: 100%;
      }
    }
  `],
})
export class ReportsComponent implements OnInit {
  loading: boolean = true;
  errorMessage: string | null = null;

  activeTab: ReportTab = 'all';

  // KPI Strip Data
  readonly totalFlowsFormatted: string = '7,235,606';
  readonly evaluatedCategoriesCount: number = 14;
  readonly evaluatedPairsCount: number = 9;
  readonly verifiedMitreCount: number = 0;

  portData: DestinationPortAnalyticsResponse | null = null;
  redundancyData: FeatureRedundancyResponse | null = null;
  mitreItems: MitreProfileSummaryItem[] = [];

  constructor(private readonly apiService: ThreatLenzApiService) {}

  ngOnInit(): void {
    this.loadReportsData();
  }

  setActiveTab(tab: ReportTab): void {
    this.activeTab = tab;
  }

  loadReportsData(): void {
    this.loading = true;
    this.errorMessage = null;

    forkJoin({
      portAnalytics: this.apiService.getPortAnalytics(),
      redundancy: this.apiService.getFeatureRedundancy(),
      profiles: this.apiService.listProfiles({ limit: 50 }),
    }).subscribe({
      next: ({ portAnalytics, redundancy, profiles }) => {
        this.portData = portAnalytics;
        this.redundancyData = redundancy;

        const profileList = profiles.items || [];
        if (profileList.length === 0) {
          this.mitreItems = [];
          this.loading = false;
          return;
        }

        const mitreRequests = profileList.map((p) =>
          this.apiService.getProfileMitre(p.snapshot_id)
        );

        forkJoin(mitreRequests).subscribe({
          next: (mitreResponses: MitreMappingResponse[]) => {
            this.mitreItems = profileList.map((p, index) => ({
              category: p.canonical_label,
              mapping: mitreResponses[index],
            }));
            this.loading = false;
          },
          error: (_err) => {
            // Still present the other two reports even if mitre batch fails
            this.mitreItems = [];
            this.loading = false;
          },
        });
      },
      error: (err) => {
        this.errorMessage = err.message || 'Failed to retrieve analytical reports telemetry.';
        this.loading = false;
      },
    });
  }
}


