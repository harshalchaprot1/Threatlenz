import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { DestinationPortAnalyticsResponse, CategoryPortAnalysis, PortConcentrationItem } from '../../../core/models';

interface MatrixCell {
  port: number;
  flowCount: number;
  percentage: number;
  serviceName: string;
}

interface MatrixRow {
  category: string;
  totalFlows: number;
  cells: MatrixCell[];
}

@Component({
  selector: 'app-port-matrix-heatmap',
  standalone: true,
  imports: [CommonModule, FormsModule, MatProgressSpinnerModule],
  template: `
    <div class="matrix-card">
      <div class="matrix-header">
        <div class="header-titles">
          <div class="title-row">
            <span class="matrix-title">{{ title }}</span>
            <span class="coverage-pill">14 Categories &times; 12 Ports</span>
          </div>
          <span class="matrix-subtitle">{{ subtitle }}</span>
        </div>

        <div class="header-controls">
          <!-- Category Filter Selector -->
          <div class="filter-group">
            <label for="categoryFilter" class="filter-label">Category Filter:</label>
            <div class="select-wrapper">
              <select
                id="categoryFilter"
                class="filter-select"
                [ngModel]="selectedCategory"
                (ngModelChange)="onCategoryChange($event)"
              >
                <option value="ALL">All Categories (14)</option>
                @for (cat of allCategories; track cat) {
                  <option [value]="cat">{{ cat }}</option>
                }
              </select>
            </div>
            @if (selectedCategory !== 'ALL') {
              <button class="reset-filter-btn" (click)="resetCategoryFilter()" title="Reset to all categories">
                <span class="material-symbols-outlined reset-icon">close</span>
                <span>Reset</span>
              </button>
            }
          </div>

          <!-- Ephemeral Ports Toggle -->
          <button
            class="toggle-ephemeral-btn"
            [class.active]="showEphemeralPorts"
            (click)="toggleEphemeralPorts()"
            title="Toggle ephemeral and non-standard custom ports (50891, 50896, 50899)"
          >
            <span class="material-symbols-outlined btn-icon">
              {{ showEphemeralPorts ? 'unfold_less' : 'unfold_more' }}
            </span>
            <span>
              {{ showEphemeralPorts ? 'Hide Custom Ports (3)' : 'Show Custom Ports (3)' }}
            </span>
          </button>
        </div>
      </div>

      <!-- Legend & Info Bar -->
      <div class="meta-strip">
        <div class="header-legend">
          <span class="legend-label">Row Concentration:</span>
          <div class="legend-scale">
            <span class="scale-box s-0">0%</span>
            <span class="scale-box s-25">&lt;25%</span>
            <span class="scale-box s-50">&lt;50%</span>
            <span class="scale-box s-75">&lt;75%</span>
            <span class="scale-box s-100">&ge;75%</span>
          </div>
        </div>

        <div class="port-scope-indicator">
          <span class="material-symbols-outlined scope-icon">filter_alt</span>
          @if (showEphemeralPorts) {
            <span>Displaying all 12 ports (9 standard enterprise services + 3 custom/ephemeral ports)</span>
          } @else {
            <span>Displaying 9 standard enterprise ports (Ports 50891, 50896, 50899 collapsed into secondary view)</span>
          }
        </div>
      </div>

      <!-- Loading State -->
      @if (loading) {
        <div class="state-container">
          <mat-spinner diameter="36"></mat-spinner>
          <span>Aggregating cross-category port concentration telemetry...</span>
        </div>
      }

      <!-- Error State -->
      @if (errorMessage && !loading) {
        <div class="state-container error-state">
          <span class="material-symbols-outlined state-icon">error</span>
          <span>{{ errorMessage }}</span>
        </div>
      }

      <!-- Heatmap Grid -->
      @if (!loading && !errorMessage && filteredRows.length > 0) {
        <div class="matrix-wrapper">
          <table class="heatmap-table">
            <thead>
              <tr>
                <th class="sticky-col category-header">
                  <div class="header-cell-content">Threat Category</div>
                </th>
                <th class="sticky-col-2 total-header">Total Flows</th>
                @for (port of activePorts; track port) {
                  <th
                    class="port-col-header"
                    [class.ephemeral-col]="isEphemeralPort(port)"
                    [attr.title]="getPortTooltip(port)"
                  >
                    <div class="port-header-content">
                      <span class="port-number">P:{{ port }}</span>
                      <span class="port-service">{{ getPortShortName(port) }}</span>
                    </div>
                  </th>
                }
              </tr>
            </thead>
            <tbody>
              @for (row of filteredRows; track row.category) {
                <tr>
                  <td class="sticky-col category-cell" [attr.title]="row.category">
                    <span class="cat-name">{{ row.category }}</span>
                  </td>
                  <td class="sticky-col-2 total-cell font-mono">
                    {{ row.totalFlows | number }}
                  </td>
                  @for (cell of getVisibleCells(row); track cell.port) {
                    <td
                      class="heatmap-cell"
                      [ngClass]="getCellClass(cell.percentage)"
                      [class.ephemeral-cell]="isEphemeralPort(cell.port)"
                      [attr.title]="getCellTooltip(row.category, cell)"
                    >
                      @if (cell.flowCount > 0) {
                        <span class="cell-pct font-mono">{{ cell.percentage.toFixed(1) }}%</span>
                        <span class="cell-count font-mono">{{ cell.flowCount | number }}</span>
                      } @else {
                        <span class="cell-empty">&middot;</span>
                      }
                    </td>
                  }
                </tr>
              }
            </tbody>
          </table>
        </div>

        <div class="matrix-footer">
          <div class="footer-note">
            <span class="material-symbols-outlined note-icon">info</span>
            <span>
              Percentages reflect row-normalized flow concentration across destination ports in CSE-CIC-IDS2018.
              Hover over individual cells to inspect exact flow totals and verified class share.
            </span>
          </div>
          @if (selectedCategory !== 'ALL') {
            <span class="filter-active-hint">
              Showing 1 of 14 categories ({{ selectedCategory }})
            </span>
          }
        </div>
      }

      @if (!loading && !errorMessage && filteredRows.length === 0) {
        <div class="state-container">
          <span class="material-symbols-outlined state-icon">search_off</span>
          <span>No matching threat categories found for the selected filter.</span>
          <button class="reset-filter-btn" (click)="resetCategoryFilter()">Reset Category Filter</button>
        </div>
      }
    </div>
  `,
  styles: [`
    .matrix-card {
      background: var(--tl-bg-surface, #1E293B);
      border: 1px solid var(--tl-border, rgba(255, 255, 255, 0.08));
      border-radius: 8px;
      padding: 18px 20px;
      display: flex;
      flex-direction: column;
      gap: 14px;
    }

    .matrix-header {
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

    .matrix-title {
      font-size: 16px;
      font-weight: 700;
      color: var(--tl-text-primary, #F8FAFC);
    }

    .coverage-pill {
      font-size: 10px;
      font-weight: 600;
      color: var(--tl-cyan, #06B6D4);
      background: rgba(6, 182, 212, 0.1);
      border: 1px solid rgba(6, 182, 212, 0.25);
      border-radius: 4px;
      padding: 2px 8px;
    }

    .matrix-subtitle {
      font-size: 12px;
      color: var(--tl-text-secondary, #94A3B8);
    }

    .header-controls {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
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
      transition: border-color 0.15s ease;

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

      .reset-icon {
        font-size: 14px;
      }

      &:hover {
        background: rgba(239, 68, 68, 0.2);
        color: #FECACA;
      }
    }

    .toggle-ephemeral-btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 5px 10px;
      border-radius: 5px;
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid var(--tl-border, rgba(255, 255, 255, 0.12));
      color: var(--tl-text-secondary, #94A3B8);
      font-size: 12px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.15s ease;

      .btn-icon {
        font-size: 16px;
        color: var(--tl-text-muted, #64748B);
      }

      &:hover {
        background: rgba(255, 255, 255, 0.08);
        color: var(--tl-text-primary, #F8FAFC);
      }

      &.active {
        background: rgba(6, 182, 212, 0.12);
        border-color: rgba(6, 182, 212, 0.35);
        color: var(--tl-cyan, #06B6D4);

        .btn-icon {
          color: var(--tl-cyan, #06B6D4);
        }
      }
    }

    .meta-strip {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
      padding: 8px 12px;
      background: rgba(15, 23, 42, 0.4);
      border: 1px solid rgba(255, 255, 255, 0.04);
      border-radius: 5px;
    }

    .header-legend {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 11px;
      color: var(--tl-text-muted, #64748B);
    }

    .legend-scale {
      display: flex;
      gap: 3px;
    }

    .scale-box {
      padding: 2px 6px;
      border-radius: 3px;
      font-size: 10px;
      font-weight: 600;
      border: 1px solid rgba(255, 255, 255, 0.05);

      &.s-0 { background: rgba(255, 255, 255, 0.02); color: #64748B; }
      &.s-25 { background: rgba(6, 182, 212, 0.2); color: #67E8F9; }
      &.s-50 { background: rgba(59, 130, 246, 0.35); color: #93C5FD; }
      &.s-75 { background: rgba(139, 92, 246, 0.45); color: #C4B5FD; }
      &.s-100 { background: rgba(239, 68, 68, 0.55); color: #FCA5A5; }
    }

    .port-scope-indicator {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 11px;
      color: var(--tl-text-muted, #64748B);

      .scope-icon {
        font-size: 14px;
        color: var(--tl-cyan, #06B6D4);
      }
    }

    .matrix-wrapper {
      overflow-x: auto;
      border: 1px solid var(--tl-border, rgba(255, 255, 255, 0.08));
      border-radius: 6px;
      background: rgba(15, 23, 42, 0.6);
      max-height: 540px;
      position: relative;
    }

    .heatmap-table {
      width: 100%;
      border-collapse: separate;
      border-spacing: 0;
      font-size: 12px;

      th, td {
        border-bottom: 1px solid rgba(255, 255, 255, 0.04);
        border-right: 1px solid rgba(255, 255, 255, 0.04);
      }

      th {
        position: sticky;
        top: 0;
        background: #0F172A;
        z-index: 5;
        padding: 6px 4px;
      }
    }

    .sticky-col {
      position: sticky;
      left: 0;
      background: #0F172A !important;
      z-index: 4;
      width: 145px;
      min-width: 140px;
      max-width: 155px;
      padding: 6px 10px;
      text-align: left;
      box-shadow: 2px 0 6px rgba(0, 0, 0, 0.35);
    }

    .sticky-col-2 {
      position: sticky;
      left: 145px;
      background: #0F172A !important;
      z-index: 4;
      width: 85px;
      min-width: 80px;
      max-width: 90px;
      padding: 6px 8px;
      text-align: right;
      box-shadow: 2px 0 6px rgba(0, 0, 0, 0.35);
    }

    .category-header {
      font-size: 11px;
      font-weight: 700;
      color: var(--tl-cyan, #06B6D4);
      text-transform: uppercase;
      letter-spacing: 0.4px;
    }

    .total-header {
      font-size: 11px;
      font-weight: 700;
      color: var(--tl-text-muted, #64748B);
      text-transform: uppercase;
      letter-spacing: 0.4px;
    }

    .port-col-header {
      min-width: 58px;
      text-align: center;
      padding: 6px 4px;

      &.ephemeral-col {
        background: #131E33;
        border-right: 1px dashed rgba(255, 255, 255, 0.08);
      }
    }

    .port-header-content {
      display: flex;
      flex-direction: column;
      gap: 1px;
    }

    .port-number {
      font-size: 11px;
      font-weight: 700;
      color: var(--tl-text-primary, #F8FAFC);
      font-family: monospace;
    }

    .port-service {
      font-size: 9px;
      color: var(--tl-text-muted, #64748B);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      max-width: 65px;
    }

    .category-cell {
      .cat-name {
        font-weight: 600;
        color: var(--tl-text-primary, #F8FAFC);
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        display: block;
        font-size: 11.5px;
      }
    }

    .total-cell {
      color: var(--tl-text-secondary, #94A3B8);
      font-size: 11px;
    }

    .heatmap-cell {
      text-align: center;
      padding: 5px 3px;
      min-width: 58px;
      cursor: crosshair;
      transition: outline 0.1s ease;

      &.ephemeral-cell {
        border-right: 1px dashed rgba(255, 255, 255, 0.06);
      }

      &:hover {
        outline: 1px solid var(--tl-cyan, #06B6D4);
        position: relative;
        z-index: 3;
      }

      &.lvl-0 { background: rgba(255, 255, 255, 0.01); }
      &.lvl-25 { background: rgba(6, 182, 212, 0.18); }
      &.lvl-50 { background: rgba(59, 130, 246, 0.32); }
      &.lvl-75 { background: rgba(139, 92, 246, 0.45); }
      &.lvl-100 { background: rgba(239, 68, 68, 0.55); }
    }

    .cell-pct {
      display: block;
      font-size: 10px;
      font-weight: 700;
      color: #FFFFFF;
    }

    .cell-count {
      display: block;
      font-size: 8.5px;
      color: rgba(255, 255, 255, 0.65);
    }

    .cell-empty {
      color: rgba(255, 255, 255, 0.15);
      font-size: 12px;
    }

    .font-mono {
      font-family: monospace;
    }

    .matrix-footer {
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

    .filter-active-hint {
      font-size: 11px;
      color: var(--tl-cyan, #06B6D4);
      font-weight: 600;
    }

    .state-container {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      min-height: 200px;
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
export class PortMatrixHeatmapComponent {
  @Input() title: string = 'Destination Port × Threat Category Concentration Matrix';
  @Input() subtitle: string = 'Flow concentration percentages within each threat category across observed destination ports';
  @Input() loading: boolean = false;
  @Input() errorMessage: string | null = null;

  @Input() set portData(data: DestinationPortAnalyticsResponse | null | undefined) {
    this._portData = data;
    this.processData();
  }

  private _portData: DestinationPortAnalyticsResponse | null | undefined = null;

  // Primary standard enterprise ports
  readonly standardPorts: number[] = [0, 21, 22, 53, 80, 443, 445, 3389, 8080];
  // Secondary custom / ephemeral ports (low-volume anomalies observed in dataset)
  readonly ephemeralPorts: number[] = [50891, 50896, 50899];

  // All 12 ports
  readonly all12Ports: number[] = [0, 21, 22, 53, 80, 443, 445, 3389, 8080, 50891, 50896, 50899];

  portServiceMap: Record<number, string> = {
    0: 'Custom/0',
    21: 'FTP',
    22: 'SSH',
    53: 'DNS',
    80: 'HTTP',
    443: 'HTTPS',
    445: 'SMB',
    3389: 'RDP',
    8080: 'HTTP-Alt',
    50891: 'Custom/50891',
    50896: 'Custom/50896',
    50899: 'Custom/50899',
  };

  rows: MatrixRow[] = [];
  filteredRows: MatrixRow[] = [];
  allCategories: string[] = [];
  selectedCategory: string = 'ALL';
  showEphemeralPorts: boolean = false;

  get activePorts(): number[] {
    return this.showEphemeralPorts ? this.all12Ports : this.standardPorts;
  }

  private processData(): void {
    if (!this._portData || !this._portData.categories) {
      this.rows = [];
      this.filteredRows = [];
      this.allCategories = [];
      return;
    }

    const categoriesDict = this._portData.categories;
    const catKeys = Object.keys(categoriesDict);
    this.allCategories = [...catKeys];

    this.rows = catKeys.map((catKey) => {
      const catData: CategoryPortAnalysis = categoriesDict[catKey];
      const portLookup = new Map<number, PortConcentrationItem>();

      if (catData.top_ports) {
        catData.top_ports.forEach((p: PortConcentrationItem) => {
          portLookup.set(p.port, p);
          if (p.service_name && !this.portServiceMap[p.port]) {
            this.portServiceMap[p.port] = p.service_name;
          }
        });
      }

      // Populate cells for all 12 ports to preserve exact underlying data
      const cells: MatrixCell[] = this.all12Ports.map((port) => {
        const pInfo = portLookup.get(port);
        return {
          port,
          flowCount: pInfo ? pInfo.flow_count : 0,
          percentage: pInfo ? pInfo.percentage_within_class : 0,
          serviceName: pInfo?.service_name || this.portServiceMap[port] || `Port ${port}`,
        };
      });

      return {
        category: catKey,
        totalFlows: catData.total_flows,
        cells,
      };
    });

    this.applyFilter();
  }

  onCategoryChange(cat: string): void {
    this.selectedCategory = cat;
    this.applyFilter();
  }

  resetCategoryFilter(): void {
    this.selectedCategory = 'ALL';
    this.applyFilter();
  }

  toggleEphemeralPorts(): void {
    this.showEphemeralPorts = !this.showEphemeralPorts;
  }

  isEphemeralPort(port: number): boolean {
    return this.ephemeralPorts.includes(port);
  }

  private applyFilter(): void {
    if (this.selectedCategory === 'ALL') {
      this.filteredRows = [...this.rows];
    } else {
      this.filteredRows = this.rows.filter((r) => r.category === this.selectedCategory);
    }
  }

  getVisibleCells(row: MatrixRow): MatrixCell[] {
    if (this.showEphemeralPorts) {
      return row.cells;
    }
    return row.cells.filter((c) => this.standardPorts.includes(c.port));
  }

  getPortShortName(port: number): string {
    return this.portServiceMap[port] || `${port}`;
  }

  getPortTooltip(port: number): string {
    const isEph = this.isEphemeralPort(port);
    const suffix = isEph ? ' (Low-volume custom port in dataset)' : '';
    return `Destination Port ${port}: ${this.portServiceMap[port] || 'Unassigned'}${suffix}`;
  }

  getCellClass(pct: number): string {
    if (pct <= 0) return 'lvl-0';
    if (pct < 25) return 'lvl-25';
    if (pct < 50) return 'lvl-50';
    if (pct < 75) return 'lvl-75';
    return 'lvl-100';
  }

  getCellTooltip(category: string, cell: MatrixCell): string {
    if (cell.flowCount === 0) {
      return `${category} → Port ${cell.port} (${cell.serviceName}): 0 flows observed`;
    }
    return `${category} → Port ${cell.port} (${cell.serviceName}): ${cell.flowCount.toLocaleString()} flows (${cell.percentage.toFixed(2)}% of ${category})`;
  }
}

