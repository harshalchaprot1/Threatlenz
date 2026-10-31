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
      border-radius: 8px;
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .chart-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
      padding-bottom: 12px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.06);
    }

    .chart-title-group {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }

    .chart-title {
      font-size: 14px;
      font-weight: 600;
      color: var(--tl-text-primary);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .chart-subtitle {
      font-size: 12px;
      color: var(--tl-text-secondary);
    }

    .scale-mode-toggle {
      display: flex;
      background: rgba(0, 0, 0, 0.25);
      border: 1px solid var(--tl-border);
      border-radius: 6px;
      padding: 2px;
    }

    .toggle-btn {
      background: transparent;
      border: none;
      color: var(--tl-text-muted);
      font-size: 11px;
      font-weight: 600;
      padding: 4px 10px;
      border-radius: 4px;
      cursor: pointer;
      transition: all 0.15s ease;

      &:hover {
        color: var(--tl-text-primary);
      }

      &.active {
        background: var(--tl-accent-cyan, #06B6D4);
        color: #0B1120;
      }
    }

    .bars-list {
      display: flex;
      flex-direction: column;
      gap: 10px;
    }

    .bar-row {
      display: grid;
      grid-template-columns: 180px 1fr 140px;
      align-items: center;
      gap: 16px;
      padding: 6px 10px;
      border-radius: 6px;
      cursor: pointer;
      transition: background 0.15s ease;

      &:hover {
        background: rgba(255, 255, 255, 0.04);

        .item-name {
          color: var(--tl-accent-cyan, #06B6D4);
        }
      }

      @media (max-width: 768px) {
        grid-template-columns: 130px 1fr 100px;
        gap: 10px;
      }
    }

    .bar-label-col {
      display: flex;
      flex-direction: column;
      gap: 2px;
      overflow: hidden;
    }

    .item-name {
      font-size: 13px;
      font-weight: 500;
      color: var(--tl-text-primary);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      transition: color 0.15s ease;
    }

    .item-status {
      font-size: 10px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.3px;

      &.status-attack {
        color: var(--tl-crimson, #EF4444);
      }

      &.status-benign {
        color: var(--tl-emerald, #10B981);
      }
    }

    .bar-track-col {
      width: 100%;
    }

    .bar-track {
      width: 100%;
      height: 12px;
      background: rgba(255, 255, 255, 0.05);
      border-radius: 6px;
      overflow: hidden;
      position: relative;
    }

    .bar-fill {
      height: 100%;
      border-radius: 6px;
      transition: width 0.3s cubic-bezier(0.4, 0, 0.2, 1);

      &.fill-attack {
        background: linear-gradient(90deg, #F87171, #EF4444);
      }

      &.fill-benign {
        background: linear-gradient(90deg, #34D399, #10B981);
      }
    }

    .bar-metrics-col {
      display: flex;
      flex-direction: column;
      align-items: flex-end;
      gap: 2px;
    }

    .item-count {
      font-size: 12px;
      font-weight: 600;
      font-family: monospace;
      color: var(--tl-text-primary);
    }

    .item-pct {
      font-size: 11px;
      color: var(--tl-text-muted);
    }

    .chart-footer {
      padding-top: 10px;
      border-top: 1px solid rgba(255, 255, 255, 0.04);
    }

    .footer-hint {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 11px;
      color: var(--tl-text-muted);

      .hint-icon {
        font-size: 14px;
        color: var(--tl-accent-cyan, #06B6D4);
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
        formattedCount: count.toLocaleString(),
        percentage: pct,
        barWidthPct: Math.min(Math.max(barWidthPct, 0), 100),
        isAttack: p.attack_status === 'ATTACK',
        attackStatus: p.attack_status,
      };
    });
  }
}
