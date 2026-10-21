import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatTableModule } from '@angular/material/table';
import { MatPaginatorModule, PageEvent } from '@angular/material/paginator';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { ThreatLenzApiService } from '../../core/services/api.service';
import { PipelineRunDetail, PipelineRunSummary } from '../../core/models';

@Component({
  selector: 'app-runs',
  standalone: true,
  imports: [
    CommonModule,
    MatTableModule,
    MatPaginatorModule,
    MatButtonModule,
    MatIconModule,
    MatProgressSpinnerModule,
  ],
  template: `
    <div class="runs-container">
      <!-- Header -->
      <div class="page-header">
        <h1 class="page-title">Pipeline Execution Runs &amp; Provenance</h1>
        <p class="page-subtitle">
          Auditable execution history, deterministic SHA-256 source content manifests, and interval semantics.
        </p>
      </div>

      <!-- Loading State -->
      @if (loading && !selectedRunDetail) {
        <div class="state-container">
          <mat-spinner diameter="40"></mat-spinner>
          <span>Loading pipeline execution history...</span>
        </div>
      }

      <!-- Error State -->
      @if (errorMessage && !loading) {
        <div class="state-container error-state" role="alert">
          <span class="material-symbols-outlined state-icon">error</span>
          <h3>Pipeline Run History Error</h3>
          <p>{{ errorMessage }}</p>
          <button mat-flat-button color="accent" (click)="fetchRuns()">
            Retry
          </button>
        </div>
      }

      <!-- Main Runs Table & Detail -->
      @if (!loading && !errorMessage) {
        <!-- Selected Run Detail Card -->
        @if (selectedRunDetail) {
          <div class="selected-run-card">
            <div class="detail-header">
              <div class="title-row">
                <span class="material-symbols-outlined run-icon">verified</span>
                <div>
                  <h2 class="run-title">Run Detail: {{ selectedRunDetail.run_id }}</h2>
                  <span class="run-subtitle">{{ selectedRunDetail.report_name }} (v{{ selectedRunDetail.pipeline_version }})</span>
                </div>
              </div>
              <button mat-icon-button (click)="selectedRunDetail = null" title="Close Details">
                <span class="material-symbols-outlined">close</span>
              </button>
            </div>

            <div class="provenance-grid">
              <div class="prov-box">
                <span class="prov-label">Source Manifest SHA-256</span>
                <span class="prov-val font-mono">{{ selectedRunDetail.source_manifest_hash }}</span>
              </div>
              <div class="prov-box">
                <span class="prov-label">Manifest Files &amp; Volume</span>
                <span class="prov-val font-mono">
                  {{ selectedRunDetail.manifest_files_count }} files ({{ formatBytes(selectedRunDetail.manifest_total_bytes) }})
                </span>
              </div>
              <div class="prov-box">
                <span class="prov-label">Execution Duration</span>
                <span class="prov-val font-mono">{{ selectedRunDetail.execution_duration_seconds }} seconds</span>
              </div>
              <div class="prov-box">
                <span class="prov-label">Window Interval Semantics</span>
                <span class="prov-val font-mono">{{ selectedRunDetail.interval_semantics }}</span>
              </div>
              <div class="prov-box">
                <span class="prov-label">Campaign Window</span>
                <span class="prov-val font-mono">
                  {{ selectedRunDetail.window_start | date:'shortDate' }} — {{ selectedRunDetail.window_end | date:'shortDate' }}
                </span>
              </div>
              <div class="prov-box">
                <span class="prov-label">Traffic Source</span>
                <span class="prov-val">{{ selectedRunDetail.traffic_source }}</span>
              </div>
            </div>

            <div class="counts-row">
              <span class="count-pill pill-total">Total Profiles: {{ selectedRunDetail.total_profiles }}</span>
              <span class="count-pill pill-attack">Attack Classes: {{ selectedRunDetail.attack_categories_count }}</span>
              <span class="count-pill pill-benign">Benign Baseline: {{ selectedRunDetail.benign_categories_count }}</span>
              <span class="count-pill pill-unknown">Unknown: {{ selectedRunDetail.unknown_categories_count }}</span>
              <span class="count-pill pill-target">Target Impact: {{ selectedRunDetail.target_impact_status }}</span>
            </div>
          </div>
        }

        <!-- Runs Table -->
        <div class="table-card">
          <div class="table-responsive">
            <table mat-table [dataSource]="runs" class="runs-table">
              <!-- Run ID Column -->
              <ng-container matColumnDef="run_id">
                <th mat-header-cell *matHeaderCellDef>Run ID</th>
                <td mat-cell *matCellDef="let row" class="font-mono">
                  {{ row.run_id }}
                </td>
              </ng-container>

              <!-- Timestamp Column -->
              <ng-container matColumnDef="run_timestamp">
                <th mat-header-cell *matHeaderCellDef>Execution Timestamp</th>
                <td mat-cell *matCellDef="let row">
                  {{ row.run_timestamp | date:'medium' }}
                </td>
              </ng-container>

              <!-- Duration Column -->
              <ng-container matColumnDef="duration">
                <th mat-header-cell *matHeaderCellDef>Duration</th>
                <td mat-cell *matCellDef="let row" class="font-mono">
                  {{ row.execution_duration_seconds }}s
                </td>
              </ng-container>

              <!-- Source Manifest Hash Column -->
              <ng-container matColumnDef="manifest_hash">
                <th mat-header-cell *matHeaderCellDef>Manifest Hash</th>
                <td mat-cell *matCellDef="let row" class="font-mono text-muted">
                  {{ row.source_manifest_hash }}
                </td>
              </ng-container>

              <!-- Total Profiles Column -->
              <ng-container matColumnDef="total_profiles">
                <th mat-header-cell *matHeaderCellDef>Profiles</th>
                <td mat-cell *matCellDef="let row" class="font-mono">
                  {{ row.total_profiles }}
                </td>
              </ng-container>

              <!-- Model Status Column -->
              <ng-container matColumnDef="model_status">
                <th mat-header-cell *matHeaderCellDef>Model Status</th>
                <td mat-cell *matCellDef="let row">
                  <span class="status-chip">{{ row.model_status }}</span>
                </td>
              </ng-container>

              <!-- Actions Column -->
              <ng-container matColumnDef="actions">
                <th mat-header-cell *matHeaderCellDef style="text-align: right;">Action</th>
                <td mat-cell *matCellDef="let row" style="text-align: right;">
                  <button
                    mat-stroked-button
                    color="primary"
                    (click)="selectRun(row.run_id)"
                    class="action-btn"
                  >
                    View Provenance
                  </button>
                </td>
              </ng-container>

              <tr mat-header-row *matHeaderRowDef="displayedColumns"></tr>
              <tr mat-row *matRowDef="let row; columns: displayedColumns" class="table-row"></tr>

              <!-- Empty State Row -->
              <tr class="mat-row" *matNoDataRow>
                <td class="mat-cell empty-cell" [attr.colspan]="displayedColumns.length">
                  <div class="empty-state">
                    <span class="material-symbols-outlined" style="font-size: 32px; color: var(--tl-text-muted);">history</span>
                    <span>No pipeline execution runs found in database.</span>
                  </div>
                </td>
              </tr>
            </table>
          </div>

          <!-- Paginator -->
          <mat-paginator
            [length]="totalCount"
            [pageSize]="pageSize"
            [pageSizeOptions]="[10, 20, 50]"
            [pageIndex]="pageIndex"
            (page)="onPageChange($event)"
            class="table-paginator"
            aria-label="Select page of runs"
          ></mat-paginator>
        </div>
      }
    </div>
  `,
  styles: [`
    .runs-container {
      display: flex;
      flex-direction: column;
      gap: 20px;
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

    .selected-run-card {
      background: var(--tl-bg-surface);
      border: 1px solid var(--tl-cyan);
      border-radius: 8px;
      padding: 24px;
      display: flex;
      flex-direction: column;
      gap: 16px;
      box-shadow: 0 4px 20px rgba(6, 182, 212, 0.1);
    }

    .detail-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      border-bottom: 1px solid var(--tl-border);
      padding-bottom: 14px;
    }

    .title-row {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .run-icon {
      font-size: 28px;
      color: var(--tl-cyan);
    }

    .run-title {
      font-size: 16px;
      font-weight: 700;
      color: var(--tl-text-primary);
      margin: 0 0 2px 0;
    }

    .run-subtitle {
      font-size: 12px;
      color: var(--tl-text-secondary);
    }

    .provenance-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 14px;
      background: var(--tl-bg-card);
      border: 1px solid var(--tl-border);
      border-radius: 6px;
      padding: 16px;
    }

    .prov-box {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }

    .prov-label {
      font-size: 10px;
      color: var(--tl-text-muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
      font-weight: 700;
    }

    .prov-val {
      font-size: 13px;
      color: var(--tl-text-primary);
    }

    .counts-row {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }

    .count-pill {
      font-size: 11px;
      font-weight: 600;
      padding: 4px 10px;
      border-radius: 4px;
      border: 1px solid var(--tl-border);
      background: var(--tl-bg-card);
    }

    .pill-total { color: var(--tl-cyan); }
    .pill-attack { color: #F87171; border-color: rgba(239, 68, 68, 0.3); }
    .pill-benign { color: #34D399; border-color: rgba(16, 185, 129, 0.3); }
    .pill-unknown { color: #C4B5FD; }
    .pill-target { color: #FBBF24; border-color: rgba(245, 158, 11, 0.3); }

    .table-card {
      background: var(--tl-bg-surface);
      border: 1px solid var(--tl-border);
      border-radius: 8px;
      overflow: hidden;
    }

    .table-responsive {
      overflow-x: auto;
    }

    .runs-table {
      width: 100%;
      background: transparent;

      th {
        color: var(--tl-text-muted);
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        border-bottom: 1px solid var(--tl-border);
      }

      td {
        border-bottom: 1px solid rgba(255, 255, 255, 0.04);
        color: var(--tl-text-primary);
        font-size: 13px;
      }
    }

    .table-row:hover {
      background: rgba(255, 255, 255, 0.02);
    }

    .font-mono {
      font-family: monospace;
    }

    .text-muted {
      color: var(--tl-text-secondary);
    }

    .status-chip {
      font-size: 11px;
      font-weight: 600;
      color: #FBBF24;
      background: rgba(245, 158, 11, 0.12);
      border: 1px solid rgba(245, 158, 11, 0.3);
      padding: 2px 8px;
      border-radius: 4px;
    }

    .action-btn {
      font-size: 12px;
      height: 30px;
      line-height: 30px;
    }

    .table-paginator {
      background: var(--tl-bg-surface);
      color: var(--tl-text-secondary);
      border-top: 1px solid var(--tl-border);
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

    .empty-cell {
      padding: 40px;
      text-align: center;
    }

    .empty-state {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 8px;
      color: var(--tl-text-secondary);
      font-size: 13px;
    }
  `],
})
export class RunsComponent implements OnInit {
  displayedColumns: string[] = [
    'run_id',
    'run_timestamp',
    'duration',
    'manifest_hash',
    'total_profiles',
    'model_status',
    'actions',
  ];

  runs: PipelineRunSummary[] = [];
  totalCount: number = 0;
  pageSize: number = 20;
  pageIndex: number = 0;

  selectedRunDetail: PipelineRunDetail | null = null;
  loading: boolean = true;
  errorMessage: string | null = null;

  constructor(private readonly apiService: ThreatLenzApiService) {}

  ngOnInit(): void {
    this.fetchRuns();
  }

  fetchRuns(): void {
    this.loading = true;
    this.errorMessage = null;

    const offset = this.pageIndex * this.pageSize;
    this.apiService.listRuns(this.pageSize, offset).subscribe({
      next: (response) => {
        this.runs = response.items;
        this.totalCount = response.total;
        this.loading = false;
      },
      error: (err) => {
        this.errorMessage = err.message || 'Failed to query pipeline run history.';
        this.loading = false;
      },
    });
  }

  selectRun(runId: string): void {
    this.apiService.getRunDetail(runId).subscribe({
      next: (detail) => {
        this.selectedRunDetail = detail;
      },
      error: (err) => {
        this.errorMessage = err.message || `Failed to load details for run '${runId}'.`;
      },
    });
  }

  onPageChange(event: PageEvent): void {
    this.pageIndex = event.pageIndex;
    this.pageSize = event.pageSize;
    this.fetchRuns();
  }

  formatBytes(bytes: number): string {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }
}
