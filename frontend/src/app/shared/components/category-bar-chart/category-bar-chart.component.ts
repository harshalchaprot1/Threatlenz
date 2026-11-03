import { Component, Input, OnChanges, OnDestroy, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router } from '@angular/router';
import { NgxEchartsDirective } from 'ngx-echarts';
import type { EChartsOption } from 'echarts';
import { ThreatProfileSummary } from '../../../core/models';

@Component({
  selector: 'app-category-bar-chart',
  standalone: true,
  imports: [CommonModule, NgxEchartsDirective],
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

      <div
        echarts
        [options]="chartOptions"
        class="bar-chart"
        (chartClick)="onChartClick($event)"
      ></div>

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

      &:hover { color: var(--tl-text-primary); }

      &.active {
        background: rgba(6, 182, 212, 0.2);
        color: var(--tl-cyan, #06B6D4);
        border: 1px solid rgba(6, 182, 212, 0.3);
      }
    }

    .bar-chart {
      width: 100%;
      flex: 1;
      min-height: 320px;
      cursor: pointer;
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
export class CategoryBarChartComponent implements OnChanges {
  private readonly router = inject(Router);

  @Input() title: string = 'Network Flow Volume by Threat Category';
  @Input() subtitle: string = 'Comparative volume across all evaluated categories in the active campaign window';
  @Input() profiles: ThreatProfileSummary[] = [];

  scaleMode: 'log' | 'linear' = 'log';
  chartOptions: EChartsOption = {};

  // Map label → snapshot_id for click navigation
  private labelToSnapshotId = new Map<string, string>();

  ngOnChanges(): void {
    this.recompute();
  }

  setScaleMode(mode: 'log' | 'linear'): void {
    if (this.scaleMode !== mode) {
      this.scaleMode = mode;
      this.recompute();
    }
  }

  onChartClick(event: any): void {
    const snapshotId = this.labelToSnapshotId.get(event.name);
    if (snapshotId) {
      this.router.navigate(['/profiles', snapshotId]);
    }
  }

  private recompute(): void {
    const data = this.profiles || [];
    if (!data.length) {
      this.chartOptions = {};
      return;
    }

    // Sort descending by flow_count
    const sorted = [...data].sort((a, b) => (b.flow_count || 0) - (a.flow_count || 0));

    this.labelToSnapshotId.clear();
    sorted.forEach(p => this.labelToSnapshotId.set(p.canonical_label, p.snapshot_id));

    const labels = sorted.map(p => p.canonical_label);
    const values = sorted.map(p => p.flow_count || 0);
    const colors = sorted.map(p =>
      p.attack_status === 'ATTACK' ? '#EF4444' : '#10B981'
    );
    const totalFlows = values.reduce((s, v) => s + v, 0);

    this.chartOptions = {
      backgroundColor: 'transparent',
      grid: { left: 130, right: 90, top: 8, bottom: 8, containLabel: false },
      tooltip: {
        trigger: 'axis',
        axisPointer: { type: 'none' },
        backgroundColor: '#1E293B',
        borderColor: 'rgba(255,255,255,0.12)',
        textStyle: { color: '#F8FAFC', fontSize: 12 },
        formatter: (params: any) => {
          const p = Array.isArray(params) ? params[0] : params;
          const count = (p.value as number).toLocaleString('en-US');
          const pct = totalFlows > 0 ? ((p.value as number / totalFlows) * 100).toFixed(2) : '0.00';
          const status = sorted[p.dataIndex]?.attack_status ?? '';
          return `<strong>${p.name}</strong> <span style="color:#94A3B8;font-size:10px">${status}</span><br/>${count} flows (${pct}%)`;
        },
      },
      xAxis: {
        type: this.scaleMode === 'log' ? 'log' : 'value',
        logBase: 10,
        min: this.scaleMode === 'log' ? 1 : 0,
        axisLabel: {
          color: '#64748B',
          fontSize: 10,
          formatter: (val: number) => {
            if (val >= 1000000) return (val / 1000000).toFixed(1) + 'M';
            if (val >= 1000) return (val / 1000).toFixed(0) + 'K';
            return String(val);
          },
        },
        splitLine: { lineStyle: { color: 'rgba(255,255,255,0.04)' } },
        axisLine: { lineStyle: { color: 'rgba(255,255,255,0.06)' } },
      } as any,
      yAxis: {
        type: 'category',
        data: [...labels].reverse(),
        axisLabel: {
          color: '#CBD5E1',
          fontSize: 11,
          width: 120,
          overflow: 'truncate',
        },
        axisLine: { lineStyle: { color: 'rgba(255,255,255,0.06)' } },
        axisTick: { show: false },
      },
      series: [
        {
          type: 'bar',
          data: [...values].reverse().map((v, i) => ({
            value: v,
            itemStyle: { color: [...colors].reverse()[i], borderRadius: [0, 3, 3, 0] },
          })),
          barMaxWidth: 22,
          label: {
            show: true,
            position: 'right',
            color: '#94A3B8',
            fontSize: 10,
            fontFamily: 'monospace',
            formatter: (params: any) => {
              const val = params.value as number;
              const pct = totalFlows > 0 ? ((val / totalFlows) * 100) : 0;
              const fmtPct = pct < 0.01 ? '<0.01%' : pct.toFixed(2) + '%';
              const fmtCount = val >= 1000000
                ? (val / 1000000).toFixed(1) + 'M'
                : val >= 1000 ? (val / 1000).toFixed(0) + 'K' : String(val);
              return `${fmtCount}  ${fmtPct}`;
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
