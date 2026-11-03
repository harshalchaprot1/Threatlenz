import { Component, Input, OnChanges } from '@angular/core';
import { CommonModule } from '@angular/common';
import { NgxEchartsDirective } from 'ngx-echarts';
import type { EChartsOption } from 'echarts';
import { ThreatProfileSummary } from '../../../core/models';

@Component({
  selector: 'app-composition-donut-chart',
  standalone: true,
  imports: [CommonModule, NgxEchartsDirective],
  template: `
    <div class="donut-card">
      <div class="donut-header">
        <span class="donut-title">{{ title }}</span>
        <span class="donut-subtitle">{{ subtitle }}</span>
      </div>

      <div class="donut-content">
        <div
          echarts
          [options]="chartOptions"
          class="donut-chart"
          [style.height.px]="260"
        ></div>

        <div class="composition-note">
          <span class="material-symbols-outlined note-icon">info</span>
          <span>Accurate composition derived directly from evaluated campaign Netflow partitions.</span>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .donut-card {
      background: var(--tl-bg-surface);
      border: 1px solid var(--tl-border);
      border-radius: 6px;
      padding: 18px 20px;
      display: flex;
      flex-direction: column;
      gap: 16px;
      height: 100%;
      box-sizing: border-box;
    }

    .donut-header {
      display: flex;
      flex-direction: column;
      gap: 2px;
      padding-bottom: 10px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    }

    .donut-title {
      font-size: 13px;
      font-weight: 700;
      color: var(--tl-text-primary);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .donut-subtitle {
      font-size: 11px;
      color: var(--tl-text-muted);
    }

    .donut-content {
      display: flex;
      flex-direction: column;
      gap: 12px;
      flex: 1;
    }

    .donut-chart {
      width: 100%;
    }

    .composition-note {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 11px;
      color: var(--tl-text-muted);
      padding-top: 8px;
      border-top: 1px solid rgba(255, 255, 255, 0.04);

      .note-icon {
        font-size: 14px;
        color: var(--tl-cyan, #06B6D4);
      }
    }
  `],
})
export class CompositionDonutChartComponent implements OnChanges {
  @Input() title: string = 'Traffic Composition (Attack vs. Benign)';
  @Input() subtitle: string = 'Aggregate volume distribution across classified campaign flows';
  @Input() profiles: ThreatProfileSummary[] = [];

  chartOptions: EChartsOption = {};

  ngOnChanges(): void {
    this.recompute();
  }

  private recompute(): void {
    const data = this.profiles || [];

    let benignFlows = 0;
    let attackFlows = 0;
    let unknownFlows = 0;

    for (const p of data) {
      const count = p.flow_count || 0;
      if (p.attack_status === 'BENIGN') {
        benignFlows += count;
      } else if (p.attack_status === 'ATTACK') {
        attackFlows += count;
      } else {
        unknownFlows += count;
      }
    }

    const total = benignFlows + attackFlows + unknownFlows;
    const totalLabel = total > 1000000
      ? (total / 1000000).toFixed(2) + 'M'
      : total.toLocaleString('en-US');

    const seriesData = [
      { value: benignFlows, name: 'Benign Baseline', itemStyle: { color: '#10B981' } },
      { value: attackFlows, name: 'Adversarial Attacks', itemStyle: { color: '#EF4444' } },
      ...(unknownFlows > 0
        ? [{ value: unknownFlows, name: 'Unclassified / Unknown', itemStyle: { color: '#9CA3AF' } }]
        : []),
    ];

    this.chartOptions = {
      backgroundColor: 'transparent',
      tooltip: {
        trigger: 'item',
        backgroundColor: '#1E293B',
        borderColor: 'rgba(255,255,255,0.12)',
        textStyle: { color: '#F8FAFC', fontSize: 12 },
        formatter: (params: any) => {
          const pct = total > 0 ? ((params.value / total) * 100).toFixed(1) : '0.0';
          const count = (params.value as number).toLocaleString('en-US');
          return `<strong>${params.name}</strong><br/>${count} flows (${pct}%)`;
        },
      },
      legend: {
        orient: 'vertical',
        bottom: 0,
        left: 'center',
        textStyle: { color: '#94A3B8', fontSize: 11 },
        itemWidth: 10,
        itemHeight: 10,
        icon: 'circle',
      },
      series: [
        {
          type: 'pie',
          radius: ['45%', '68%'],
          center: ['50%', '42%'],
          avoidLabelOverlap: false,
          label: {
            show: true,
            position: 'center',
            formatter: () => `{total|${totalLabel}}\n{sub|Total Flows}`,
            rich: {
              total: {
                fontSize: 18,
                fontWeight: 700,
                color: '#F8FAFC',
                fontFamily: 'monospace',
                lineHeight: 24,
              },
              sub: {
                fontSize: 10,
                color: '#64748B',
              },
            },
          },
          emphasis: {
            label: { show: true },
            itemStyle: { shadowBlur: 8, shadowColor: 'rgba(0,0,0,0.4)' },
          },
          labelLine: { show: false },
          data: seriesData,
        },
      ],
    };
  }
}
