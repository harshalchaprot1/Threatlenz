import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { MatTableModule } from '@angular/material/table';
import { MatPaginatorModule, PageEvent } from '@angular/material/paginator';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSelectModule } from '@angular/material/select';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { ThreatLenzApiService } from '../../core/services/api.service';
import { AttackStatus, ThreatProfileSummary } from '../../core/models';
import { ReliabilityBadgeComponent, StatusBadgeComponent } from '../../shared/components';

@Component({
  selector: 'app-explorer',
  standalone: true,
  imports: [
    CommonModule,
    RouterModule,
    FormsModule,
    MatTableModule,
    MatPaginatorModule,
    MatButtonModule,
    MatIconModule,
    MatInputModule,
    MatFormFieldModule,
    MatSelectModule,
    MatProgressSpinnerModule,
    StatusBadgeComponent,
    ReliabilityBadgeComponent,
  ],
  template: `
    <div class="explorer-container">
      <!-- Page Header -->
      <div class="page-header">
        <div>
          <h1 class="page-title">Threat Profile Explorer</h1>
          <p class="page-subtitle">
            Interactive repository of categorized network threat profiles derived from CSE-CIC-IDS2018 Netflow data.
          </p>
        </div>
      </div>

      <!-- Filter Controls Toolbar -->
      <div class="filter-toolbar">
        <mat-form-field appearance="outline" class="filter-field search-field">
          <mat-label>Search Threat Category</mat-label>
          <input
            matInput
            [(ngModel)]="searchCategory"
            (ngModelChange)="onSearchChange()"
            placeholder="Search by category name..."

          />
          @if (searchCategory) {
            <button matSuffix mat-icon-button aria-label="Clear" (click)="searchCategory = ''; onSearchChange()">
              <span class="material-symbols-outlined" style="font-size: 18px;">close</span>
            </button>
          }
        </mat-form-field>

        <mat-form-field appearance="outline" class="filter-field select-field">
          <mat-label>Attack Status</mat-label>
          <mat-select [(ngModel)]="selectedStatus" (selectionChange)="onStatusChange()">
            <mat-option value="ALL">All Statuses</mat-option>
            <mat-option value="ATTACK">Attack Only (ATTACK)</mat-option>
            <mat-option value="BENIGN">Benign Baseline (BENIGN)</mat-option>
          </mat-select>
        </mat-form-field>

        <button mat-stroked-button (click)="resetFilters()" class="reset-btn">
          <span class="material-symbols-outlined" style="font-size: 18px; margin-right: 4px;">filter_alt_off</span>
          Reset
        </button>
      </div>

      <!-- Loading State -->
      @if (loading) {
        <div class="state-container">
          <mat-spinner diameter="40"></mat-spinner>
          <span>Querying threat profiles...</span>
        </div>
      }

      <!-- Error State -->
      @if (errorMessage && !loading) {
        <div class="state-container error-state" role="alert">
          <span class="material-symbols-outlined state-icon">error</span>
          <h3>Query Failed</h3>
          <p>{{ errorMessage }}</p>
          <button mat-flat-button color="accent" (click)="fetchProfiles()">
            Retry
          </button>
        </div>
      }

      <!-- Table Content -->
      @if (!loading && !errorMessage) {
        <div class="table-card">
          <div class="table-responsive">
            <table mat-table [dataSource]="displayedProfiles" class="threat-table">
              <!-- Canonical Category Column -->
              <ng-container matColumnDef="canonical_label">
                <th mat-header-cell *matHeaderCellDef>Category</th>
                <td mat-cell *matCellDef="let row">
                  <div class="cat-cell">
                    <span class="cat-name">{{ row.canonical_label }}</span>
                    <span class="cat-raw">{{ row.raw_label }}</span>
                  </div>
                </td>
              </ng-container>

              <!-- Attack Status Column -->
              <ng-container matColumnDef="attack_status">
                <th mat-header-cell *matHeaderCellDef>Attack Status</th>
                <td mat-cell *matCellDef="let row">
                  <app-status-badge [status]="row.attack_status"></app-status-badge>
                </td>
              </ng-container>

              <!-- Flow Count Column -->
              <ng-container matColumnDef="flow_count">
                <th mat-header-cell *matHeaderCellDef>Flow Count</th>
                <td mat-cell *matCellDef="let row" class="font-mono">
                  {{ row.flow_count | number }}
                </td>
              </ng-container>

              <!-- Total Packets Column -->
              <ng-container matColumnDef="total_packets">
                <th mat-header-cell *matHeaderCellDef>Packets</th>
                <td mat-cell *matCellDef="let row" class="font-mono text-muted">
                  {{ row.total_packets | number }}
                </td>
              </ng-container>

              <!-- Recurrence Ratio Column -->
              <ng-container matColumnDef="recurrence">
                <th mat-header-cell *matHeaderCellDef>Recurrence</th>
                <td mat-cell *matCellDef="let row" class="font-mono">
                  {{ (row.recurrence_ratio * 100).toFixed(1) }}%
                  <span class="denom-hint">({{ row.active_observation_units }}/{{ row.recurrence_denominator }})</span>
                </td>
              </ng-container>

              <!-- Model Reliability Column -->
              <ng-container matColumnDef="model_reliability">
                <th mat-header-cell *matHeaderCellDef>Model Reliability</th>
                <td mat-cell *matCellDef="let row">
                  <app-reliability-badge [reliability]="row.model_reliability"></app-reliability-badge>
                </td>
              </ng-container>

              <!-- Snapshot ID Column -->
              <ng-container matColumnDef="snapshot_id">
                <th mat-header-cell *matHeaderCellDef>Snapshot ID</th>
                <td mat-cell *matCellDef="let row" class="font-mono text-muted">
                  {{ row.snapshot_id }}
                </td>
              </ng-container>

              <!-- Action Column -->
              <ng-container matColumnDef="actions">
                <th mat-header-cell *matHeaderCellDef style="text-align: right;">Action</th>
                <td mat-cell *matCellDef="let row" style="text-align: right;">
                  <a
                    mat-flat-button
                    color="primary"
                    [routerLink]="['/profiles', row.snapshot_id]"
                    class="action-btn"
                  >
                    Inspect Profile
                  </a>
                </td>
              </ng-container>

              <tr mat-header-row *matHeaderRowDef="displayedColumns"></tr>
              <tr mat-row *matRowDef="let row; columns: displayedColumns" class="table-row"></tr>

              <!-- Empty State Row -->
              <tr class="mat-row" *matNoDataRow>
                <td class="mat-cell empty-cell" [attr.colspan]="displayedColumns.length">
                  <div class="empty-state">
                    <span class="material-symbols-outlined" style="font-size: 32px; color: var(--tl-text-muted);">search_off</span>
                    <span>No threat profiles matched the selected criteria.</span>
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
            aria-label="Select page of threat profiles"
          ></mat-paginator>
        </div>
      }
    </div>
  `,
  styles: [`
    .explorer-container {
      display: flex;
      flex-direction: column;
      gap: 20px;
    }

    .page-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
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

    .filter-toolbar {
      display: flex;
      align-items: center;
      gap: 16px;
      flex-wrap: wrap;
      background: var(--tl-bg-surface);
      border: 1px solid var(--tl-border);
      border-radius: 8px;
      padding: 16px 20px 0 20px;
    }

    .filter-field {
      flex: 1 1 200px;
    }

    .select-field {
      flex: 0 1 250px;
    }

    .reset-btn {
      margin-bottom: 22px;
      height: 48px;
    }

    .table-card {
      background: var(--tl-bg-surface);
      border: 1px solid var(--tl-border);
      border-radius: 8px;
      overflow: hidden;
    }

    .table-responsive {
      overflow-x: auto;
    }

    .threat-table {
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

    .cat-cell {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }

    .cat-name {
      font-weight: 600;
      color: var(--tl-text-primary);
    }

    .cat-raw {
      font-size: 11px;
      color: var(--tl-text-muted);
    }

    .font-mono {
      font-family: monospace;
    }

    .text-muted {
      color: var(--tl-text-secondary);
    }

    .denom-hint {
      font-size: 11px;
      color: var(--tl-text-muted);
      margin-left: 4px;
    }

    .action-btn {
      font-size: 12px;
      height: 32px;
      line-height: 32px;
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
  `],
})
export class ExplorerComponent implements OnInit {
  displayedColumns: string[] = [
    'canonical_label',
    'attack_status',
    'flow_count',
    'total_packets',
    'recurrence',
    'model_reliability',
    'snapshot_id',
    'actions',
  ];

  displayedProfiles: ThreatProfileSummary[] = [];
  rawProfiles: ThreatProfileSummary[] = [];
  totalCount: number = 0;
  pageSize: number = 20;
  pageIndex: number = 0;

  searchCategory: string = '';
  selectedStatus: string = 'ALL';

  loading: boolean = true;
  errorMessage: string | null = null;

  constructor(private readonly apiService: ThreatLenzApiService) { }

  ngOnInit(): void {
    this.fetchProfiles();
  }

  fetchProfiles(): void {
    this.loading = true;
    this.errorMessage = null;

    // Fetch full set of campaign profiles to support client-side filtering and pagination
    this.apiService.listProfiles({ limit: 100, offset: 0 }).subscribe({
      next: (response) => {
        this.rawProfiles = response.items || [];
        this.applyFilterAndPagination();
        this.loading = false;
      },
      error: (err) => {
        this.errorMessage = err.message || 'Failed to query threat profiles.';
        this.loading = false;
      },
    });
  }

  applyFilterAndPagination(): void {
    const query = this.searchCategory.trim().toLowerCase();
    const status = this.selectedStatus;

    // 1. Filter against both canonical_label and raw_label + attack_status
    const filtered = this.rawProfiles.filter((p) => {
      const matchesSearch =
        !query ||
        (p.canonical_label && p.canonical_label.toLowerCase().includes(query)) ||
        (p.raw_label && p.raw_label.toLowerCase().includes(query));

      const matchesStatus =
        status === 'ALL' || p.attack_status === status;

      return matchesSearch && matchesStatus;
    });

    this.totalCount = filtered.length;

    // Ensure page index is within valid bounds
    const maxPageIndex = Math.max(0, Math.ceil(this.totalCount / this.pageSize) - 1);
    if (this.pageIndex > maxPageIndex) {
      this.pageIndex = 0;
    }

    // 2. Paginate filtered results
    const startIndex = this.pageIndex * this.pageSize;
    this.displayedProfiles = filtered.slice(startIndex, startIndex + this.pageSize);
  }

  onSearchChange(): void {
    this.pageIndex = 0;
    this.applyFilterAndPagination();
  }

  onStatusChange(): void {
    this.pageIndex = 0;
    this.applyFilterAndPagination();
  }

  onPageChange(event: PageEvent): void {
    this.pageIndex = event.pageIndex;
    this.pageSize = event.pageSize;
    this.applyFilterAndPagination();
  }

  resetFilters(): void {
    this.searchCategory = '';
    this.selectedStatus = 'ALL';
    this.pageIndex = 0;
    this.applyFilterAndPagination();
  }
}
