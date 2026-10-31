import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FeatureImportanceItem } from '../../../core/models';

interface RenderedFeatureItem {
  featureName: string;
  cleanName: string;
  importance: number;
  percentage: number;
  barWidthPct: number;
}

@Component({
  selector: 'app-feature-importance-chart',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="fi-card">
      <div class="fi-header">
        <div class="header-left">
          <span class="fi-title">{{ title }}</span>
          <span class="fi-subtitle">{{ subtitle }}</span>
        </div>
        <div class="fi-badge">
          <span class="material-symbols-outlined badge-icon">science</span>
          <span>Leakage-Excluded Feature Benchmark</span>
        </div>
      </div>

      @if (loading) {
        <div class="state-box">
          <span class="state-label">Loading feature importance diagnostics...</span>
        </div>
      } @else if (errorMessage) {
        <div class="state-box error">
          <span class="material-symbols-outlined error-icon">warning</span>
          <span class="state-label">{{ errorMessage }}</span>
        </div>
      } @else if (items.length === 0) {
        <div class="state-box">
          <span class="state-label">No feature importance data available.</span>
        </div>
      } @else {
        <div class="fi-content">
          <div class="bars-container">
            @for (item of items; track item.featureName; let i = $index) {
              <div class="fi-row" [title]="item.cleanName + ': ' + item.importance.toFixed(6) + ' (' + item.percentage.toFixed(2) + '%)'">
                <!-- Rank & Feature Name Column -->
                <div class="label-col">
                  <span class="rank-badge">#{{ i + 1 }}</span>
                  <span class="feature-name font-mono" [title]="item.cleanName">{{ item.cleanName }}</span>
                </div>

                <!-- Bar Track Column -->
                <div class="track-col">
                  <div class="bar-track">
                    <div
                      class="bar-fill"
                      [style.width.%]="item.barWidthPct"
                    ></div>
                  </div>
                </div>

                <!-- Value Metrics Column -->
                <div class="metrics-col">
                  <span class="metric-val font-mono">{{ item.importance.toFixed(4) }}</span>
                  <span class="metric-pct font-mono">({{ item.percentage.toFixed(1) }}%)</span>
                </div>
              </div>
            }
          </div>

          <div class="fi-footer">
            <span class="footer-note">
              <span class="material-symbols-outlined note-icon">verified_user</span>
              Evaluated on verified, non-leaking network flow features. Target label indicators and metadata are strictly excluded.
            </span>
          </div>
        </div>
      }
    </div>
  `,
  styles: [`
    .fi-card {
      background: var(--tl-bg-surface);
      border: 1px solid var(--tl-border);
      border-radius: 8px;
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .fi-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
      padding-bottom: 12px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.06);
    }

    .header-left {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }

    .fi-title {
      font-size: 14px;
      font-weight: 600;
      color: var(--tl-text-primary);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .fi-subtitle {
      font-size: 12px;
      color: var(--tl-text-secondary);
    }

    .fi-badge {
      display: flex;
      align-items: center;
      gap: 6px;
      background: rgba(16, 185, 129, 0.08);
      border: 1px solid rgba(16, 185, 129, 0.25);
      color: var(--tl-emerald, #10B981);
      padding: 4px 10px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;

      .badge-icon {
        font-size: 14px;
      }
    }

    .state-box {
      min-height: 180px;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      color: var(--tl-text-muted);
      font-size: 12px;

      &.error {
        color: #EF4444;
      }
    }

    .fi-content {
      display: flex;
      flex-direction: column;
      gap: 14px;
    }

    .bars-container {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .fi-row {
      display: grid;
      grid-template-columns: 220px 1fr 120px;
      align-items: center;
      gap: 16px;
      padding: 6px 10px;
      border-radius: 6px;
      background: rgba(255, 255, 255, 0.015);
      border: 1px solid rgba(255, 255, 255, 0.03);
      transition: background 0.15s ease;

      &:hover {
        background: rgba(255, 255, 255, 0.04);

        .feature-name {
          color: var(--tl-cyan, #06B6D4);
        }
      }

      @media (max-width: 768px) {
        grid-template-columns: 150px 1fr 90px;
        gap: 10px;
      }
    }

    .label-col {
      display: flex;
      align-items: center;
      gap: 8px;
      overflow: hidden;
    }

    .rank-badge {
      font-size: 10px;
      font-weight: 700;
      color: var(--tl-text-muted);
      font-family: monospace;
      min-width: 20px;
    }

    .feature-name {
      font-size: 12px;
      font-weight: 500;
      color: var(--tl-text-primary);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      transition: color 0.15s ease;
    }

    .track-col {
      width: 100%;
    }

    .bar-track {
      width: 100%;
      height: 10px;
      background: rgba(255, 255, 255, 0.05);
      border-radius: 5px;
      overflow: hidden;
    }

    .bar-fill {
      height: 100%;
      border-radius: 5px;
      background: linear-gradient(90deg, #10B981, #06B6D4);
      transition: width 0.3s ease;
    }

    .metrics-col {
      display: flex;
      align-items: center;
      justify-content: flex-end;
      gap: 6px;
    }

    .metric-val {
      font-size: 12px;
      font-weight: 600;
      color: var(--tl-text-primary);
    }

    .metric-pct {
      font-size: 11px;
      color: var(--tl-text-muted);
    }

    .fi-footer {
      padding-top: 10px;
      border-top: 1px solid rgba(255, 255, 255, 0.04);
    }

    .footer-note {
      display: flex;
      align-items: flex-start;
      gap: 6px;
      font-size: 11px;
      color: var(--tl-text-muted);

      .note-icon {
        font-size: 14px;
        color: var(--tl-emerald, #10B981);
        margin-top: 1px;
      }

      code {
        background: rgba(255, 255, 255, 0.06);
        padding: 1px 4px;
        border-radius: 3px;
        color: var(--tl-cyan, #06B6D4);
      }
    }
  `],
})
export class FeatureImportanceChartComponent {
  @Input() title: string = 'Random Forest Feature Importance (Top 10)';
  @Input() subtitle: string = 'Relative Gini feature importances evaluated on leakage-excluded statistical flow features';
  @Input() loading: boolean = false;
  @Input() errorMessage: string | null = null;

  @Input() set featureImportances(data: FeatureImportanceItem[] | null | undefined) {
    this._data = data || [];
    this.recompute();
  }

  private _data: FeatureImportanceItem[] = [];
  items: RenderedFeatureItem[] = [];

  private recompute(): void {
    if (!this._data || this._data.length === 0) {
      this.items = [];
      return;
    }

    // Sort descending by importance
    const sorted = [...this._data].sort((a, b) => b.importance - a.importance);
    const maxVal = sorted[0]?.importance || 1;
    const totalImp = sorted.reduce((sum, f) => sum + f.importance, 0);

    this.items = sorted.map((f) => {
      const pct = totalImp > 0 ? (f.importance / totalImp) * 100 : 0;
      const barWidth = maxVal > 0 ? (f.importance / maxVal) * 100 : 0;

      return {
        featureName: f.feature_name,
        cleanName: f.clean_feature_name,
        importance: f.importance,
        percentage: pct,
        barWidthPct: Math.min(Math.max(barWidth, 2), 100),
      };
    });
  }
}

