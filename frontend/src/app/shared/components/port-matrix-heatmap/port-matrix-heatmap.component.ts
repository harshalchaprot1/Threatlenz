import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
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
  imports: [CommonModule, MatProgressSpinnerModule],
  template: `
    <div class="matrix-card">
      <div class="matrix-header">
        <div class="header-titles">
          <span class="matrix-title">{{ title }}</span>
          <span class="matrix-subtitle">{{ subtitle }}</span>
        </div>
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
      @if (!loading && !errorMessage && rows.length > 0) {
        <div class="matrix-wrapper">
          <table class="heatmap-table">
            <thead>
              <tr>
                <th class="sticky-col category-header">
                  <div class="header-cell-content">Threat Category (14)</div>
                </th>
                <th class="sticky-col-2 total-header">Total Flows</th>
                @for (port of distinctPorts; track port) {
                  <th class="port-col-header" [attr.title]="getPortTooltip(port)">
                    <div class="port-header-content">
                      <span class="port-number">P:{{ port }}</span>
                      <span class="port-service">{{ getPortShortName(port) }}</span>
                    </div>
                  </th>
                }
              </tr>
            </thead>
            <tbody>
              @for (row of rows; track row.category) {
                <tr>
                  <td class="sticky-col category-cell" [attr.title]="row.category">
                    <span class="cat-name">{{ row.category }}</span>
                  </td>
                  <td class="sticky-col-2 total-cell font-mono">
                    {{ row.totalFlows | number }}
                  </td>
                  @for (cell of row.cells; track cell.port) {
                    <td
                      class="heatmap-cell"
                      [ngClass]="getCellClass(cell.percentage)"
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
          <span class="footer-note">
            <span class="material-symbols-outlined note-icon">info</span>
            Percentages reflect within-category flow concentration across the 12 destination ports observed in the CSE-CIC-IDS2018 dataset. Hover over cells to inspect exact flow totals.
          </span>
        </div>
      }

      @if (!loading && !errorMessage && rows.length === 0) {
        <div class="state-container">
          <span class="material-symbols-outlined state-icon">dataset</span>
          <span>No destination port concentration telemetry available.</span>
        </div>
      }
    </div>
  `,
  styles: [`
    .matrix-card {
      background: var(--tl-bg-surface, #1E293B);
      border: 1px solid var(--tl-border, rgba(255, 255, 255, 0.08));
      border-radius: 8px;
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .matrix-header {
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

    .matrix-title {
      font-size: 16px;
      font-weight: 700;
      color: var(--tl-text-primary, #F8FAFC);
    }

    .matrix-subtitle {
      font-size: 12px;
      color: var(--tl-text-secondary, #94A3B8);
    }

    .header-legend {
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 11px;
      color: var(--tl-text-muted, #64748B);
    }

    .legend-scale {
      display: flex;
      gap: 4px;
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

    .matrix-wrapper {
      overflow-x: auto;
      border: 1px solid var(--tl-border, rgba(255, 255, 255, 0.08));
      border-radius: 6px;
      background: rgba(15, 23, 42, 0.6);
      max-height: 520px;
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
        padding: 8px 6px;
      }
    }

    .sticky-col {
      position: sticky;
      left: 0;
      background: #0F172A !important;
      z-index: 4;
      min-width: 150px;
      max-width: 170px;
      padding: 8px 12px;
      text-align: left;
    }

    .sticky-col-2 {
      position: sticky;
      left: 160px;
      background: #0F172A !important;
      z-index: 4;
      min-width: 90px;
      padding: 8px 10px;
      text-align: right;
    }

    .category-header {
      font-size: 11px;
      font-weight: 700;
      color: var(--tl-cyan, #06B6D4);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .total-header {
      font-size: 11px;
      font-weight: 700;
      color: var(--tl-text-muted, #64748B);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .port-col-header {
      min-width: 72px;
      max-width: 85px;
      text-align: center;
      padding: 6px 4px;
    }

    .port-header-content {
      display: flex;
      flex-direction: column;
      gap: 2px;
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
      max-width: 72px;
    }

    .category-cell {
      .cat-name {
        font-weight: 600;
        color: var(--tl-text-primary, #F8FAFC);
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        display: block;
      }
    }

    .total-cell {
      color: var(--tl-text-secondary, #94A3B8);
      font-size: 11px;
    }

    .heatmap-cell {
      text-align: center;
      padding: 6px 4px;
      min-width: 72px;
      cursor: crosshair;
      transition: outline 0.1s ease;

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
      font-size: 9px;
      color: rgba(255, 255, 255, 0.6);
    }

    .cell-empty {
      color: rgba(255, 255, 255, 0.15);
      font-size: 12px;
    }

    .font-mono {
      font-family: monospace;
    }

    .matrix-footer {
      padding-top: 8px;
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
      }
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

  distinctPorts: number[] = [0, 21, 22, 53, 80, 443, 445, 3389, 8080, 50891, 50896, 50899];
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

  private processData(): void {
    if (!this._portData || !this._portData.categories) {
      this.rows = [];
      return;
    }

    const categoriesDict = this._portData.categories;
    const catKeys = Object.keys(categoriesDict);

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

      const cells: MatrixCell[] = this.distinctPorts.map((port) => {
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
  }

  getPortShortName(port: number): string {
    return this.portServiceMap[port] || `${port}`;
  }

  getPortTooltip(port: number): string {
    return `Destination Port ${port}: ${this.portServiceMap[port] || 'Unassigned'}`;
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
