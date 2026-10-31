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
} from '../../shared/components';

@Component({
  selector: 'app-reports',
  standalone: true,
  imports: [
    CommonModule,
    MatButtonModule,
    MatIconModule,
    MatProgressSpinnerModule,
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
            Source: CSE-CIC-IDS2018 Spark Precomputed Analytics
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
        <div class="reports-grid">
          <!-- SECTION 1: Destination Port Concentration Heatmap -->
          <app-port-matrix-heatmap
            [portData]="portData"
            [loading]="loading"
          ></app-port-matrix-heatmap>

          <!-- SECTION 2: Feature Redundancy & Correlation Pruning -->
          <app-feature-redundancy-table
            [redundancyData]="redundancyData"
            [loading]="loading"
          ></app-feature-redundancy-table>

          <!-- SECTION 3: MITRE ATT&CK Coverage & Telemetry Gap Analysis -->
          <app-mitre-coverage-summary
            [profilesWithMitre]="mitreItems"
            [loading]="loading"
          ></app-mitre-coverage-summary>
        </div>
      }
    </div>
  `,
  styles: [`
    .reports-container {
      display: flex;
      flex-direction: column;
      gap: 24px;
    }

    .page-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 16px;
      margin-bottom: -4px;
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

    .reports-grid {
      display: flex;
      flex-direction: column;
      gap: 24px;
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
  `],
})
export class ReportsComponent implements OnInit {
  loading: boolean = true;
  errorMessage: string | null = null;

  portData: DestinationPortAnalyticsResponse | null = null;
  redundancyData: FeatureRedundancyResponse | null = null;
  mitreItems: MitreProfileSummaryItem[] = [];

  constructor(private readonly apiService: ThreatLenzApiService) {}

  ngOnInit(): void {
    this.loadReportsData();
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
          error: (err) => {
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

