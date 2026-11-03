import { Component, Input, OnChanges } from '@angular/core';
import { CommonModule } from '@angular/common';
import { NgxEchartsDirective } from 'ngx-echarts';
import type { EChartsOption } from 'echarts';
import { ThreatProfileSummary } from '../../../core/models';

@Component({
  selector: 'app-recurrence-heatmap',
  standalone: true,
  imports: [CommonModule, NgxEchartsDirective],
  template: `
    <div class="recurrence-card">
      <div class="recurrence-header">
        <div class="recurrence-title-group">
          <span class="recurrence-title">{{ title }}</span>
          <span class="recurrence-subtitle">{{ subtitle }}</span>
        </div>
        <div class="horizon-badge">
          <span class="material-symbols-outlined horizon-icon">date_range</span>
          <span>Observation Horizon: H={{ observationHorizon }} Days</span>
        </div>
      </div>

      @if (hasData) {
        <div
          echarts
          [options]="chartOptions"
          class="heatmap-chart"
        ></div>
      }

      <div class="recurrence-footer">
        <span class="footer-note">
          <span class="material-symbols-outlined note-icon">schedule</span>
          Recurrence ratio feeds directly into TLRS risk assessment formula: R = d / H (where H={{ observationHorizon }} observed campaign days).
        </span>
      </div>
    </div>
  `,
  styles: [`
    .recurrence-card {
      background: var(--tl-bg-surface);
      border: 1px solid var(--tl-border);
      border-radius: 6px;
      padding: 18px 20px;
      display: flex;
      flex-direction: column;
      gap: 14px;
    }

    .recurrence-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
      padding-bottom: 10px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    }

    .recurrence-title-group {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }

    .recurrence-title {
      font-size: 13px;
      font-weight: 700;
      color: var(--tl-text-primary);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .recurrence-subtitle {
      font-size: 11px;
      color: var(--tl-text-muted);
    }

    .horizon-badge {
      display: flex;
      align-items: center;
      gap: 6px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid rgba(255, 255, 255, 0.08);
      color: var(--tl-text-secondary);
      padding: 3px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 500;

      .horizon-icon {
        font-size: 14px;
        color: var(--tl-cyan, #06B6D4);
      }
    }

    .heatmap-chart {
      width: 100%;
      height: 320px;
    }

    .recurrence-footer {
      padding-top: 8px;
      border-top: 1px solid rgba(255, 255, 255, 0.04);
    }

    .footer-note {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 11px;
      color: var(--tl-text-muted);

      .note-icon {
        font-size: 13px;
        color: var(--tl-cyan, #06B6D4);
      }
    }
  `],
})
export class RecurrenceHeatmapComponent implements OnChanges {
  @Input() title: string = 'Campaign Temporal Recurrence & Persistence';
  @Input() subtitle: string = 'Active observation units across the 8-day CSE-CIC-IDS2018 campaign calendar';
  @Input() profiles: ThreatProfileSummary[] = [];

  chartOptions: EChartsOption = {};
  observationHorizon: number = 8;
  hasData = false;

  ngOnChanges(): void {
    this.recompute();
  }

  private getPersistenceLabel(ratio: number): string {
    if (ratio >= 0.8) return 'Continuous';
    if (ratio >= 0.5) return 'Frequent';
    if (ratio >= 0.25) return 'Intermittent';
    return 'Sparse';
  }

  private recompute(): void {
    const data = this.profiles || [];
    if (!data.length) {
      this.hasData = false;
      this.chartOptions = {};
      return;
    }

    this.hasData = true;
    this.observationHorizon = data[0]?.recurrence_denominator || 8;
    const H = this.observationHorizon;

    // Sort: attacks first, then descending active days
    const sorted = [...data].sort((a, b) => {
      if (a.attack_status !== b.attack_status) {
        return a.attack_status === 'ATTACK' ? -1 : 1;
      }
      return (b.active_observation_units || 0) - (a.active_observation_units || 0);
    });

    const categoryLabels = sorted.map(p => p.canonical_label);
    const dayLabels = Array.from({ length: H }, (_, i) => `D${i + 1}`);

    // Build heatmap data: [dayIndex, categoryIndex, active(0/1), isAttack]
    const heatData: [number, number, number][] = [];
    sorted.forEach((p, catIdx) => {
      const activeDays = p.active_observation_units || 0;
      for (let d = 0; d < H; d++) {
        heatData.push([d, catIdx, d < activeDays ? 1 : 0]);
      }
    });

    // Per-item colour based on attack status
    const seriesData = heatData.map(([d, c, active]) => {
      const isAttack = sorted[c]?.attack_status === 'ATTACK';
      return {
        value: [d, c, active],
        itemStyle: {
          color: active === 1
            ? (isAttack ? '#EF4444' : '#10B981')
            : 'rgba(255,255,255,0.04)',
          borderRadius: 2,
          borderWidth: 1,
          borderColor: 'rgba(0,0,0,0.25)',
        },
      };
    });

    this.chartOptions = {
      backgroundColor: 'transparent',
      grid: { left: 130, right: 90, top: 8, bottom: 24 },
      // visualMap is required by ECharts heatmap to drive cell rendering.
      // show:false keeps it invisible; seriesIndex:0 scopes it to this series.
      // The actual cell colours are applied per-item via series data itemStyle.color.
      visualMap: {
        type: 'continuous',
        show: false,
        min: 0,
        max: 1,
        seriesIndex: 0,
        inRange: {
          // Fallback colour range used only when itemStyle.color is absent.
          color: ['rgba(255,255,255,0.04)', '#10B981'],
        },
      },
      tooltip: {
        trigger: 'item',
        backgroundColor: '#1E293B',
        borderColor: 'rgba(255,255,255,0.12)',
        textStyle: { color: '#F8FAFC', fontSize: 12 },
        formatter: (params: any) => {
          const [d, c, active] = params.value as [number, number, number];
          const p = sorted[c];
          if (!p) return '';
          const units = p.active_observation_units || 0;
          const denom = p.recurrence_denominator || H;
          const ratio = denom > 0 ? units / denom : 0;
          const pct = (ratio * 100).toFixed(1);
          const persistence = this.getPersistenceLabel(ratio);
          return [
            `<strong>${p.canonical_label}</strong>`,
            `Active: ${units} / ${denom} days (${pct}% persistence)`,
            `Status: <span style="color:${active ? (p.attack_status === 'ATTACK' ? '#F87171' : '#34D399') : '#64748B'}">${active ? 'Active' : 'Inactive'} on Day ${d + 1}</span>`,
            `Persistence: ${persistence}`,
          ].join('<br/>');
        },
      },
      xAxis: {
        type: 'category',
        data: dayLabels,
        axisLabel: { color: '#64748B', fontSize: 10 },
        axisLine: { lineStyle: { color: 'rgba(255,255,255,0.06)' } },
        axisTick: { show: false },
        splitLine: { show: false },
      },
      yAxis: {
        type: 'category',
        data: categoryLabels,
        axisLabel: {
          color: '#CBD5E1',
          fontSize: 11,
          width: 120,
          overflow: 'truncate',
        },
        axisLine: { lineStyle: { color: 'rgba(255,255,255,0.06)' } },
        axisTick: { show: false },
        splitLine: { show: false },
      },
      series: [
        {
          type: 'heatmap',
          data: seriesData as any,
          itemStyle: { borderRadius: 2 },
          emphasis: {
            itemStyle: { shadowBlur: 6, shadowColor: 'rgba(0,0,0,0.4)' },
          },
          label: { show: false },
        },
      ],
    };
  }
}
