import { Component, Input, OnChanges } from '@angular/core';
import { CommonModule } from '@angular/common';
import { NgxEchartsDirective } from 'ngx-echarts';
import type { EChartsOption } from 'echarts';
import { TemporalDateSummary } from '../../../core/models';

@Component({
  selector: 'app-captured-day-bar',
  standalone: true,
  imports: [CommonModule, NgxEchartsDirective],
  template: `
    <div class="card-container">
      <div class="card-header">
        <div class="header-left">
          <span class="card-title">{{ title }}</span>
          <span class="card-subtitle">{{ subtitle }}</span>
        </div>
        <div class="header-badge">
          <span class="material-symbols-outlined badge-icon">calendar_month</span>
          <span>8 Captured Days (Non-Contiguous)</span>
        </div>
      </div>

      @if (loading) {
        <div class="state-box">
          <span class="state-label">Loading captured-day analytics...</span>
        </div>
      } @else if (errorMessage) {
        <div class="state-box error">
          <span class="material-symbols-outlined error-icon">warning</span>
          <span class="state-label">{{ errorMessage }}</span>
        </div>
      } @else if (!chartOptions || !hasData) {
        <div class="state-box">
          <span class="state-label">No campaign date records available.</span>
        </div>
      } @else {
        <div class="chart-content">
          <div
            echarts
            [options]="chartOptions"
            class="day-bar-chart"
          ></div>

          <div class="card-footer">
            <span class="footer-note">
              <span class="material-symbols-outlined note-icon">info</span>
              Data displays flow totals for all 8 captured observation dates in CSE-CIC-IDS2018 (Feb 14 – Mar 2). Preserves actual non-contiguous sampling dates without synthetic interpolation.
            </span>
          </div>
        </div>
      }
    </div>
  `,
  styles: [`
    .card-container {
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

    .card-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
      padding-bottom: 10px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    }

    .header-left {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }

    .card-title {
      font-size: 13px;
      font-weight: 700;
      color: var(--tl-text-primary);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .card-subtitle {
      font-size: 11px;
      color: var(--tl-text-muted);
    }

    .header-badge {
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

      .badge-icon {
        font-size: 14px;
        color: var(--tl-cyan, #06B6D4);
      }
    }

    .state-box {
      min-height: 220px;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      color: var(--tl-text-muted);
      font-size: 12px;

      &.error { color: #EF4444; }
    }

    .chart-content {
      display: flex;
      flex-direction: column;
      gap: 14px;
      flex: 1;
    }

    .day-bar-chart {
      width: 100%;
      height: 260px;
    }

    .card-footer {
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
export class CapturedDayBarComponent implements OnChanges {
  @Input() title: string = 'Campaign Captured-Day Flow Volume';
  @Input() subtitle: string = 'Daily traffic volume across all 8 non-contiguous observation dates in CSE-CIC-IDS2018';
  @Input() loading: boolean = false;
  @Input() errorMessage: string | null = null;
  @Input() eventDateTotals: TemporalDateSummary[] | null | undefined = null;

  chartOptions: EChartsOption = {};
  hasData = false;

  ngOnChanges(): void {
    this.recompute();
  }

  private formatCompact(num: number): string {
    if (num >= 1000000) return (num / 1000000).toFixed(2) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(0) + 'K';
    return num.toString();
  }

  private recompute(): void {
    const raw = this.eventDateTotals || [];
    if (!raw.length) {
      this.hasData = false;
      this.chartOptions = {};
      return;
    }

    this.hasData = true;

    // Sort chronologically
    const sorted = [...raw].sort((a, b) => a.event_date.localeCompare(b.event_date));

    const labels = sorted.map(d => {
      const parts = d.event_date.split('-');
      const dateObj = new Date(d.event_date + 'T00:00:00Z');
      const dow = isNaN(dateObj.getTime())
        ? ''
        : dateObj.toLocaleDateString('en-US', { weekday: 'short', timeZone: 'UTC' });
      return `${parts[1]}/${parts[2]}\n${dow}`;
    });

    const values = sorted.map(d => d.total_flows);

    this.chartOptions = {
      backgroundColor: 'transparent',
      grid: { left: 55, right: 16, top: 30, bottom: 48 },
      tooltip: {
        trigger: 'axis',
        backgroundColor: '#1E293B',
        borderColor: 'rgba(255,255,255,0.12)',
        textStyle: { color: '#F8FAFC', fontSize: 12 },
        formatter: (params: any) => {
          const p = Array.isArray(params) ? params[0] : params;
          const d = sorted[p.dataIndex];
          return `<strong>${d.event_date}</strong><br/>${d.total_flows.toLocaleString('en-US')} total flows`;
        },
      },
      xAxis: {
        type: 'category',
        data: labels,
        axisLabel: {
          color: '#94A3B8',
          fontSize: 10,
          lineHeight: 14,
          interval: 0,
        },
        axisLine: { lineStyle: { color: 'rgba(255,255,255,0.06)' } },
        axisTick: { show: false },
      },
      yAxis: {
        type: 'value',
        axisLabel: {
          color: '#64748B',
          fontSize: 10,
          fontFamily: 'monospace',
          formatter: (val: number) => this.formatCompact(val),
        },
        splitLine: { lineStyle: { color: 'rgba(255,255,255,0.05)', type: 'dashed' } },
        axisLine: { show: false },
      },
      series: [
        {
          type: 'bar',
          data: values.map(v => ({
            value: v,
            itemStyle: { color: '#0284C7', borderRadius: [3, 3, 0, 0] },
          })),
          barMaxWidth: 48,
          label: {
            show: true,
            position: 'top',
            color: '#64748B',
            fontSize: 10,
            fontFamily: 'monospace',
            formatter: (p: any) => this.formatCompact(p.value as number),
          },
          emphasis: {
            itemStyle: { color: '#38BDF8' },
            label: { color: '#06B6D4' },
          },
        },
      ],
    };
  }
}
