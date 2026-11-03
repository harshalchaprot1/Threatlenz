import { Component, Input, OnChanges } from '@angular/core';
import { CommonModule } from '@angular/common';
import { NgxEchartsDirective } from 'ngx-echarts';
import type { EChartsOption } from 'echarts';
import { FeatureImportanceItem } from '../../../core/models';

@Component({
  selector: 'app-feature-importance-chart',
  standalone: true,
  imports: [CommonModule, NgxEchartsDirective],
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
      } @else if (!hasData) {
        <div class="state-box">
          <span class="state-label">No feature importance data available.</span>
        </div>
      } @else {
        <div class="fi-content">
          <div
            echarts
            [options]="chartOptions"
            class="fi-chart"
          ></div>

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

      .badge-icon { font-size: 14px; }
    }

    .state-box {
      min-height: 180px;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      color: var(--tl-text-muted);
      font-size: 12px;

      &.error { color: #EF4444; }
    }

    .fi-content {
      display: flex;
      flex-direction: column;
      gap: 14px;
    }

    .fi-chart {
      width: 100%;
      height: 320px;
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
    }
  `],
})
export class FeatureImportanceChartComponent implements OnChanges {
  @Input() title: string = 'Random Forest Feature Importance (Top 10)';
  @Input() subtitle: string = 'Relative Gini feature importances evaluated on leakage-excluded statistical flow features';
  @Input() loading: boolean = false;
  @Input() errorMessage: string | null = null;
  @Input() featureImportances: FeatureImportanceItem[] | null | undefined = null;

  chartOptions: EChartsOption = {};
  hasData = false;

  ngOnChanges(): void {
    this.recompute();
  }

  private recompute(): void {
    const data = this.featureImportances || [];
    if (!data.length) {
      this.hasData = false;
      this.chartOptions = {};
      return;
    }

    this.hasData = true;

    // Sort descending by importance, take top 10
    const sorted = [...data]
      .sort((a, b) => b.importance - a.importance)
      .slice(0, 10);

    const totalImp = sorted.reduce((s, f) => s + f.importance, 0);
    const labels = sorted.map((f, i) => `#${i + 1} ${f.clean_feature_name}`).reverse();
    const values = sorted.map(f => f.importance).reverse();
    const percentages = sorted.map(f =>
      totalImp > 0 ? (f.importance / totalImp) * 100 : 0
    ).reverse();

    this.chartOptions = {
      backgroundColor: 'transparent',
      grid: { left: 180, right: 100, top: 8, bottom: 8 },
      tooltip: {
        trigger: 'axis',
        axisPointer: { type: 'none' },
        backgroundColor: '#1E293B',
        borderColor: 'rgba(255,255,255,0.12)',
        textStyle: { color: '#F8FAFC', fontSize: 12 },
        formatter: (params: any) => {
          const p = Array.isArray(params) ? params[0] : params;
          const idx = sorted.length - 1 - p.dataIndex;
          const f = sorted[idx];
          const pct = percentages[p.dataIndex];
          return `<strong>${f.clean_feature_name}</strong><br/>Importance: ${f.importance.toFixed(6)}<br/>Share: ${pct.toFixed(1)}%`;
        },
      },
      xAxis: {
        type: 'value',
        axisLabel: {
          color: '#64748B',
          fontSize: 10,
          formatter: (val: number) => val.toFixed(3),
        },
        splitLine: { lineStyle: { color: 'rgba(255,255,255,0.04)' } },
        axisLine: { lineStyle: { color: 'rgba(255,255,255,0.06)' } },
      },
      yAxis: {
        type: 'category',
        data: labels,
        axisLabel: {
          color: '#CBD5E1',
          fontSize: 11,
          width: 170,
          overflow: 'truncate',
          fontFamily: 'monospace',
        },
        axisLine: { lineStyle: { color: 'rgba(255,255,255,0.06)' } },
        axisTick: { show: false },
      },
      series: [
        {
          type: 'bar',
          data: values.map((v, i) => ({
            value: v,
            itemStyle: {
              color: {
                type: 'linear',
                x: 0, y: 0, x2: 1, y2: 0,
                colorStops: [
                  { offset: 0, color: '#10B981' },
                  { offset: 1, color: '#06B6D4' },
                ],
              } as any,
              borderRadius: [0, 3, 3, 0],
            },
          })),
          barMaxWidth: 18,
          label: {
            show: true,
            position: 'right',
            color: '#94A3B8',
            fontSize: 10,
            fontFamily: 'monospace',
            formatter: (p: any) => {
              const imp = p.value as number;
              const pct = percentages[p.dataIndex];
              return `${imp.toFixed(4)}  (${pct.toFixed(1)}%)`;
            },
          },
          emphasis: {
            itemStyle: { opacity: 0.8 },
          },
        },
      ],
    };
  }
}
