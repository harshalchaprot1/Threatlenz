import { Component, Input, Output, EventEmitter } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { ThreatProfileSummary } from '../../../core/models';

interface BarItem {
  snapshot_id: string;
  label: string;
  flowCount: number;
  formattedCount: string;
  percentage: number;
  barWidthPct: number;
  isAttack: boolean;
  attackStatus: string;
}

@Component({
  selector: 'app-category-bar-chart',
  standalone: true,
  imports: [CommonModule, RouterModule],
  template: `
    <div class="chart-container">
      <div class="chart-header">
        <div class="chart-title-group">
          <span class="chart-title">{{ title }}</span>
          <span class="chart-subtitle">{{ subtitle }}</span>
        </div>
        <div class="scale-mode-toggle">
          <button
            type="button"
            class="toggle-btn"
            [class.active]="scaleMode === 'log'"
            (click)="setScaleMode('log')"
            title="Logarithmic scale reveals low-volume attacks alongside high-volume benign traffic"
          >
            Log Scale
          </button>
          <button
            type="button"
            class="toggle-btn"
            [class.active]="scaleMode === 'linear'"
            (click)="setScaleMode('linear')"
            title="Linear scale shows absolute flow volume proportions"
          >
            Linear
          </button>
        </div>
      </div>

      <div class="bars-list">
        @for (item of processedItems; track item.snapshot_id) {
          <div class="bar-row" [routerLink]="['/profiles', item.snapshot_id]" role="button" tabindex="0">
            <div class="bar-label-col">
              <span class="item-name" [title]="item.label">{{ item.label }}</span>
              <span class="item-status" [ngClass]="item.isAttack ? 'status-attack' : 'status-benign'">
                {{ item.attackStatus }}
              </span>
            </div>

            <div class="bar-track-col">
              <div class="bar-track">
                <div
                  class="bar-fill"
                  [ngClass]="item.isAttack ? 'fill-attack' : 'fill-benign'"
                  [style.width.%]="item.barWidthPct"
                ></div>
              </div>
            </div>

            <div class="bar-metrics-col">
              <span class="item-count">{{ item.formattedCount }}</span>
              <span class="item-pct">{{ item.percentage < 0.01 ? '<0.01%' : item.percentage.toFixed(2) + '%' }}</span>
            </div>
          </div>
        }
      </div>

      <div class="chart-footer">
        <span class="footer-hint">
          <span class="material-symbols-outlined hint-icon">touch_app</span>
          Click any threat category to inspect profile telemetry, TLRS assessment, and MITRE mapping.
        </span>
      </div>
    </div>
  `,
  styles: [`
    .chart-container {
      background: var(--tl-bg-surface);
      border: 1px solid var(--tl-border);
      border-radius: 6px;
      padding: 18px 20px;
      display: flex;
      flex-direction: column;
      gap: 14px;
      height: 100%;
      box-sizing: border-box;
    }

    .chart-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
      padding-bottom: 10px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    }

    .chart-title-group {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }

    .chart-title {
      font-size: 13px;
      font-weight: 700;
      color: var(--tl-text-primary);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .chart-subtitle {
      font-size: 11px;
      color: var(--tl-text-muted);
    }

    .scale-mode-toggle {
      display: flex;
      background: rgba(0, 0, 0, 0.3);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 4px;
      padding: 2px;
    }

    .toggle-btn {
      background: transparent;
      border: none;
      color: var(--tl-text-muted);
      font-size: 10px;
      font-weight: 700;
      padding: 3px 8px;
      border-radius: 3px;
      cursor: pointer;
      text-transform: uppercase;
      letter-spacing: 0.4px;
      transition: all 0.15s ease;

      &:hover {
        color: var(--tl-text-primary);
      }

      &.active {
        background: rgba(6, 182, 212, 0.2);
        color: var(--tl-cyan, #06B6D4);
        border: 1px solid rgba(6, 182, 212, 0.3);
      }
    }

    .bars-list {
      display: flex;
      flex-direction: column;
      gap: 4px;
      flex: 1;
    }

    .bar-row {
      display: grid;
      grid-template-columns: 140px 1fr 110px;
      align-items: center;
      gap: 14px;
      padding: 4px 8px;
      border-radius: 4px;
      cursor: pointer;
      transition: background 0.12s ease;

      &:hover {
        background: rgba(255, 255, 255, 0.03);

        .item-name {
          color: var(--tl-cyan, #06B6D4);
        }
      }

      @media (max-width: 768px) {
        grid-template-columns: 110px 1fr 90px;
        gap: 8px;
      }
    }

    .bar-label-col {
      display: flex;
      flex-direction: column;
      gap: 1px;
      overflow: hidden;
    }

    .item-name {
      font-size: 12px;
      font-weight: 600;
      color: var(--tl-text-primary);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      transition: color 0.12s ease;
    }

    .item-status {
      font-size: 9px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.4px;

      &.status-attack {
        color: #EF4444;
      }

      &.status-benign {
        color: #10B981;
      }
    }

    .bar-track-col {
      width: 100%;
    }

    .bar-track {
      width: 100%;
      height: 8px;
      background: rgba(255, 255, 255, 0.04);
      border-radius: 4px;
      overflow: hidden;
      position: relative;
    }

    .bar-fill {
      height: 100%;
      border-radius: 4px;
      transition: width 0.3s ease;

      &.fill-attack {
        background: #EF4444;
      }

      &.fill-benign {
        background: #10B981;
      }
    }

    .bar-metrics-col {
      display: flex;
      align-items: baseline;
      justify-content: flex-end;
      gap: 8px;
    }

    .item-count {
      font-size: 11px;
      font-weight: 600;
      font-family: monospace;
      color: var(--tl-text-primary);
    }

    .item-pct {
      font-size: 10px;
      color: var(--tl-text-muted);
      min-width: 36px;
      text-align: right;
    }

    .chart-footer {
      padding-top: 8px;
      border-top: 1px solid rgba(255, 255, 255, 0.04);
    }

    .footer-hint {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 11px;
      color: var(--tl-text-muted);

      .hint-icon {
        font-size: 13px;
        color: var(--tl-cyan, #06B6D4);
      }
    }
  `],
})
export class CategoryBarChartComponent {
  @Input() title: string = 'Network Flow Volume by Threat Category';
  @Input() subtitle: string = 'Comparative volume across all evaluated categories in the active campaign window';
  @Input() set profiles(data: ThreatProfileSummary[]) {
    this._profiles = data || [];
    this.recompute();
  }

  private _profiles: ThreatProfileSummary[] = [];
  scaleMode: 'log' | 'linear' = 'log';
  processedItems: BarItem[] = [];

  setScaleMode(mode: 'log' | 'linear'): void {
    if (this.scaleMode !== mode) {
      this.scaleMode = mode;
      this.recompute();
    }
  }

  private recompute(): void {
    if (!this._profiles || this._profiles.length === 0) {
      this.processedItems = [];
      return;
    }

    // Sort descending by flow_count
    const sorted = [...this._profiles].sort((a, b) => (b.flow_count || 0) - (a.flow_count || 0));
    const totalFlows = sorted.reduce((sum, p) => sum + (p.flow_count || 0), 0);
    const maxFlows = sorted[0]?.flow_count || 1;

    // Log calculation with minimum floor for display
    const logMin = 0;
    const logMax = Math.log10(Math.max(maxFlows, 1));

    this.processedItems = sorted.map((p) => {
      const count = p.flow_count || 0;
      const pct = totalFlows > 0 ? (count / totalFlows) * 100 : 0;

      let barWidthPct = 0;
      if (this.scaleMode === 'linear') {
        barWidthPct = maxFlows > 0 ? (count / maxFlows) * 100 : 0;
      } else {
        // Log scale mapping: log10(count + 1) / log10(max + 1)
        const logVal = Math.log10(Math.max(count, 1));
        barWidthPct = logMax > 0 ? (logVal / logMax) * 100 : 0;
      }

      // Minimum visual threshold so small non-zero bars remain visible
      if (count > 0 && barWidthPct < 1.5) {
        barWidthPct = 1.5;
      }

      return {
        snapshot_id: p.snapshot_id,
        label: p.canonical_label,
        flowCount: count,
        formattedCount: count.toLocaleString('en-US'),
        percentage: pct,
        barWidthPct: Math.min(Math.max(barWidthPct, 0), 100),
        isAttack: p.attack_status === 'ATTACK',
        attackStatus: p.attack_status,
      };
    });
  }
}

