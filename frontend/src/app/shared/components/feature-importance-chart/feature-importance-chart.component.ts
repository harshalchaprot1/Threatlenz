import { Component, Input, OnChanges } from '@angular/core';
import { CommonModule } from '@angular/common';
import { NgxEchartsDirective } from 'ngx-echarts';
import type { EChartsOption } from 'echarts';
import { RankedFeatureImportanceItem } from '../../../core/models';

interface FeatureMeta {
  rawCol: string;
  label: string;
  explanation: string;
}

const FEATURE_METADATA_MAP: Record<string, FeatureMeta> = {
  init_fwd_win_byts: {
    rawCol: 'Init Fwd Win Byts',
    label: 'Initial Forward TCP Window Size',
    explanation: 'Number of bytes allocated to the initial TCP window header in the forward direction.',
  },
  fwd_seg_size_min: {
    rawCol: 'Fwd Seg Size Min',
    label: 'Minimum Forward Segment Size',
    explanation: 'Minimum observed TCP header or segment size in the forward direction in bytes.',
  },
  flow_duration: {
    rawCol: 'Flow Duration',
    label: 'Flow Duration',
    explanation: 'Total elapsed lifetime duration of the bidirectional network flow in microseconds.',
  },
  fwd_header_len: {
    rawCol: 'Fwd Header Len',
    label: 'Total Forward Header Length',
    explanation: 'Total bytes used for protocol headers across all packets in the forward direction.',
  },
  flow_iat_mean: {
    rawCol: 'Flow IAT Mean',
    label: 'Mean Flow Inter-Arrival Time',
    explanation: 'Mean time elapsed between consecutive packets in the flow in microseconds.',
  },
  bwd_pkts_s: {
    rawCol: 'Bwd Pkts/s',
    label: 'Backward Packets Per Second',
    explanation: 'Rate of packets transmitted in the backward (server-to-client) direction per second.',
  },
  flow_iat_max: {
    rawCol: 'Flow IAT Max',
    label: 'Maximum Flow Inter-Arrival Time',
    explanation: 'Maximum observed time gap between consecutive packets in the flow in microseconds.',
  },
  fwd_iat_tot: {
    rawCol: 'Fwd IAT Tot',
    label: 'Total Forward Inter-Arrival Time',
    explanation: 'Sum of all time intervals between consecutive packets in the forward direction in microseconds.',
  },
  init_bwd_win_byts: {
    rawCol: 'Init Bwd Win Byts',
    label: 'Initial Backward TCP Window Size',
    explanation: 'Number of bytes allocated to the initial TCP window header in the backward direction.',
  },
  flow_pkts_s: {
    rawCol: 'Flow Pkts/s',
    label: 'Total Flow Packets Per Second',
    explanation: 'Total number of forward and backward packets transmitted divided by flow duration in seconds.',
  },
  fwd_act_data_pkts: {
    rawCol: 'Fwd Act Data Pkts',
    label: 'Forward Data Packets Count',
    explanation: 'Count of forward packets containing at least 1 byte of TCP payload data.',
  },
  fwd_iat_min: {
    rawCol: 'Fwd IAT Min',
    label: 'Minimum Forward Inter-Arrival Time',
    explanation: 'Minimum observed time interval between consecutive forward packets in microseconds.',
  },
  tot_fwd_pkts: {
    rawCol: 'Tot Fwd Pkts',
    label: 'Total Forward Packets',
    explanation: 'Total count of packets transmitted in the forward direction.',
  },
  flow_iat_min: {
    rawCol: 'Flow IAT Min',
    label: 'Minimum Flow Inter-Arrival Time',
    explanation: 'Minimum observed time interval between any two consecutive packets in the flow in microseconds.',
  },
  fwd_pkts_s: {
    rawCol: 'Fwd Pkts/s',
    label: 'Forward Packets Per Second',
    explanation: 'Rate of packets transmitted in the forward (client-to-server) direction per second.',
  },
  totlen_fwd_pkts: {
    rawCol: 'TotLen Fwd Pkts',
    label: 'Total Forward Payload Volume',
    explanation: 'Total volume in bytes across all packet payloads in the forward direction.',
  },
  fwd_iat_max: {
    rawCol: 'Fwd IAT Max',
    label: 'Maximum Forward Inter-Arrival Time',
    explanation: 'Maximum observed time interval between consecutive forward packets in microseconds.',
  },
  fwd_iat_mean: {
    rawCol: 'Fwd IAT Mean',
    label: 'Mean Forward Inter-Arrival Time',
    explanation: 'Mean time elapsed between consecutive forward packets in microseconds.',
  },
  pkt_len_std: {
    rawCol: 'Pkt Len Std',
    label: 'Packet Length Standard Deviation',
    explanation: 'Standard deviation of packet lengths observed across the entire bidirectional flow.',
  },
  bwd_pkt_len_max: {
    rawCol: 'Bwd Pkt Len Max',
    label: 'Maximum Backward Packet Length',
    explanation: 'Maximum packet length in bytes observed in the backward direction.',
  },
  bwd_pkt_len_mean: {
    rawCol: 'Bwd Pkt Len Mean',
    label: 'Mean Backward Packet Length',
    explanation: 'Mean packet length in bytes observed in the backward direction.',
  },
  bwd_header_len: {
    rawCol: 'Bwd Header Len',
    label: 'Total Backward Header Length',
    explanation: 'Total bytes used for protocol headers across all packets in the backward direction.',
  },
  rst_flag_cnt: {
    rawCol: 'RST Flag Cnt',
    label: 'TCP Reset Flag Count',
    explanation: 'Total count of TCP packets with the RST (Reset) flag set.',
  },
  flow_iat_std: {
    rawCol: 'Flow IAT Std',
    label: 'Flow Inter-Arrival Time Std Dev',
    explanation: 'Standard deviation of packet inter-arrival times across the flow in microseconds.',
  },
  fwd_pkt_len_max: {
    rawCol: 'Fwd Pkt Len Max',
    label: 'Maximum Forward Packet Length',
    explanation: 'Maximum packet length in bytes observed in the forward direction.',
  },
  flow_byts_s: {
    rawCol: 'Flow Byts/s',
    label: 'Total Flow Bytes Per Second',
    explanation: 'Total volume of bytes transmitted divided by flow duration in seconds.',
  },
  pkt_len_var: {
    rawCol: 'Pkt Len Var',
    label: 'Packet Length Variance',
    explanation: 'Statistical variance of packet lengths observed across the entire bidirectional flow.',
  },
  pkt_len_min: {
    rawCol: 'Pkt Len Min',
    label: 'Minimum Packet Length',
    explanation: 'Minimum packet length in bytes observed across the bidirectional flow.',
  },
  bwd_pkt_len_std: {
    rawCol: 'Bwd Pkt Len Std',
    label: 'Backward Packet Length Std Dev',
    explanation: 'Standard deviation of packet lengths observed in the backward direction.',
  },
  pkt_len_max: {
    rawCol: 'Pkt Len Max',
    label: 'Maximum Overall Packet Length',
    explanation: 'Maximum packet length in bytes observed across the bidirectional flow.',
  },
  bwd_iat_max: {
    rawCol: 'Bwd IAT Max',
    label: 'Maximum Backward Inter-Arrival Time',
    explanation: 'Maximum observed time interval between consecutive backward packets in microseconds.',
  },
  fwd_iat_std: {
    rawCol: 'Fwd IAT Std',
    label: 'Forward Inter-Arrival Time Std Dev',
    explanation: 'Standard deviation of time intervals between consecutive forward packets in microseconds.',
  },
  tot_bwd_pkts: {
    rawCol: 'Tot Bwd Pkts',
    label: 'Total Backward Packets',
    explanation: 'Total count of packets transmitted in the backward direction.',
  },
  totlen_bwd_pkts: {
    rawCol: 'TotLen Bwd Pkts',
    label: 'Total Backward Payload Volume',
    explanation: 'Total volume in bytes across all packet payloads in the backward direction.',
  },
  bwd_iat_mean: {
    rawCol: 'Bwd IAT Mean',
    label: 'Mean Backward Inter-Arrival Time',
    explanation: 'Mean time elapsed between consecutive backward packets in microseconds.',
  },
  fwd_pkt_len_std: {
    rawCol: 'Fwd Pkt Len Std',
    label: 'Forward Packet Length Std Dev',
    explanation: 'Standard deviation of packet lengths observed in the forward direction.',
  },
  fwd_pkt_len_mean: {
    rawCol: 'Fwd Pkt Len Mean',
    label: 'Mean Forward Packet Length',
    explanation: 'Mean packet length in bytes observed in the forward direction.',
  },
  pkt_size_avg: {
    rawCol: 'Pkt Size Avg',
    label: 'Average Packet Size',
    explanation: 'Average size of packets observed across the bidirectional flow in bytes.',
  },
  bwd_iat_tot: {
    rawCol: 'Bwd IAT Tot',
    label: 'Total Backward Inter-Arrival Time',
    explanation: 'Sum of all time intervals between consecutive packets in the backward direction in microseconds.',
  },
  pkt_len_mean: {
    rawCol: 'Pkt Len Mean',
    label: 'Mean Packet Length',
    explanation: 'Mean packet length in bytes observed across the bidirectional flow.',
  },
  ece_flag_cnt: {
    rawCol: 'ECE Flag Cnt',
    label: 'ECE Flag Count',
    explanation: 'Total count of TCP packets with the ECN-Echo (ECE) flag set.',
  },
  bwd_iat_min: {
    rawCol: 'Bwd IAT Min',
    label: 'Minimum Backward Inter-Arrival Time',
    explanation: 'Minimum observed time interval between consecutive backward packets in microseconds.',
  },
  urg_flag_cnt: {
    rawCol: 'URG Flag Cnt',
    label: 'TCP Urgent Flag Count',
    explanation: 'Total count of TCP packets with the Urgent (URG) flag set.',
  },
  bwd_iat_std: {
    rawCol: 'Bwd IAT Std',
    label: 'Backward Inter-Arrival Time Std Dev',
    explanation: 'Standard deviation of time intervals between consecutive backward packets in microseconds.',
  },
  idle_max: {
    rawCol: 'Idle Max',
    label: 'Maximum Flow Idle Time',
    explanation: 'Maximum continuous idle time in microseconds between active packet bursts.',
  },
  ack_flag_cnt: {
    rawCol: 'ACK Flag Cnt',
    label: 'TCP Acknowledge Flag Count',
    explanation: 'Total count of TCP packets with the Acknowledgment (ACK) flag set.',
  },
  fwd_pkt_len_min: {
    rawCol: 'Fwd Pkt Len Min',
    label: 'Minimum Forward Packet Length',
    explanation: 'Minimum packet length in bytes observed in the forward direction.',
  },
  protocol: {
    rawCol: 'Protocol',
    label: 'IP Protocol Identifier',
    explanation: 'Transport layer protocol numerical identifier (for example, TCP=6, UDP=17).',
  },
  psh_flag_cnt: {
    rawCol: 'PSH Flag Cnt',
    label: 'TCP Push Flag Count',
    explanation: 'Total count of TCP packets with the Push (PSH) flag set.',
  },
  down_up_ratio: {
    rawCol: 'Down/Up Ratio',
    label: 'Download / Upload Ratio',
    explanation: 'Ratio of backward (download) packets to forward (upload) packets.',
  },
  active_mean: {
    rawCol: 'Active Mean',
    label: 'Mean Active Period Duration',
    explanation: 'Mean time duration in microseconds that the flow remained active before transitioning to idle.',
  },
  active_min: {
    rawCol: 'Active Min',
    label: 'Minimum Active Period Duration',
    explanation: 'Minimum time duration in microseconds that the flow remained active before transitioning to idle.',
  },
  syn_flag_cnt: {
    rawCol: 'SYN Flag Cnt',
    label: 'TCP Synchronize Flag Count',
    explanation: 'Total count of TCP packets with the Synchronize (SYN) flag set.',
  },
  idle_min: {
    rawCol: 'Idle Min',
    label: 'Minimum Flow Idle Time',
    explanation: 'Minimum continuous idle time in microseconds between active packet bursts.',
  },
  idle_mean: {
    rawCol: 'Idle Mean',
    label: 'Mean Flow Idle Time',
    explanation: 'Mean continuous idle time in microseconds between active packet bursts.',
  },
  active_std: {
    rawCol: 'Active Std',
    label: 'Active Period Duration Std Dev',
    explanation: 'Standard deviation of active period durations in microseconds before idle periods.',
  },
  fwd_psh_flags: {
    rawCol: 'Fwd PSH Flags',
    label: 'Forward TCP Push Flags',
    explanation: 'Count of TCP packets in the forward direction with the Push (PSH) flag set.',
  },
  active_max: {
    rawCol: 'Active Max',
    label: 'Maximum Active Period Duration',
    explanation: 'Maximum time duration in microseconds that the flow remained active before transitioning to idle.',
  },
  idle_std: {
    rawCol: 'Idle Std',
    label: 'Flow Idle Time Std Dev',
    explanation: 'Standard deviation of idle time intervals in microseconds between active bursts.',
  },
  bwd_pkt_len_min: {
    rawCol: 'Bwd Pkt Len Min',
    label: 'Minimum Backward Packet Length',
    explanation: 'Minimum packet length in bytes observed in the backward direction.',
  },
  fin_flag_cnt: {
    rawCol: 'FIN Flag Cnt',
    label: 'TCP Finish Flag Count',
    explanation: 'Total count of TCP packets with the Finish (FIN) flag set.',
  },
  fwd_urg_flags: {
    rawCol: 'Fwd URG Flags',
    label: 'Forward TCP Urgent Flags',
    explanation: 'Count of TCP packets in the forward direction with the Urgent (URG) flag set.',
  },
  cwe_flag_count: {
    rawCol: 'CWE Flag Count',
    label: 'CWE Flag Count',
    explanation: 'Total count of TCP packets with the Congestion Window Reduced (CWR) / CWE flag set.',
  },
};

@Component({
  selector: 'app-feature-importance-chart',
  standalone: true,
  imports: [CommonModule, NgxEchartsDirective],
  template: `
    <div class="fi-card">
      <div class="fi-header">
        <div class="header-left">
          <div class="title-row">
            <span class="fi-title">{{ title }}</span>
            <span class="feature-count-badge">All 63 Features Evaluated</span>
          </div>
          <span class="fi-subtitle">{{ subtitle }}</span>
        </div>

        <div class="header-controls">
          <div class="pagination-panel">
            <button
              type="button"
              class="page-btn"
              [disabled]="!hasData || currentPage === 1"
              (click)="prevPage()"
              aria-label="Previous Page"
              title="Previous Page"
            >
              <span class="material-symbols-outlined page-icon">chevron_left</span>
            </button>
            <span class="page-indicator">
              Page <strong>{{ currentPage }}</strong> of <strong>{{ totalPages }}</strong>
              <span class="rank-range">({{ rankRangeText }})</span>
            </span>
            <button
              type="button"
              class="page-btn"
              [disabled]="!hasData || currentPage === totalPages"
              (click)="nextPage()"
              aria-label="Next Page"
              title="Next Page"
            >
              <span class="material-symbols-outlined page-icon">chevron_right</span>
            </button>
          </div>

          <div class="fi-badge">
            <span class="material-symbols-outlined badge-icon">science</span>
            <span>Leakage-Excluded Benchmark</span>
          </div>
        </div>
      </div>

      @if (loading) {
        <div class="state-box">
          <span class="state-label">Loading full 63-feature importance diagnostics...</span>
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
              <span class="material-symbols-outlined note-icon">policy</span>
              <strong>Governance Disclosures:</strong>
              Feature importance represents mean Gini impurity reduction across 30 decision trees in the clean evaluation model.
              Higher importance indicates stronger statistical discrimination signal in flow partitions; it does not imply causation.
              Live pipeline inference remains quarantined under governance policy.
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
      gap: 14px;
      padding-bottom: 12px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.06);
    }

    .header-left {
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

    .fi-title {
      font-size: 14px;
      font-weight: 600;
      color: var(--tl-text-primary);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .feature-count-badge {
      font-size: 11px;
      font-family: monospace;
      padding: 2px 8px;
      border-radius: 4px;
      background: rgba(6, 182, 212, 0.12);
      border: 1px solid rgba(6, 182, 212, 0.3);
      color: var(--tl-cyan, #06B6D4);
      font-weight: 600;
    }

    .fi-subtitle {
      font-size: 12px;
      color: var(--tl-text-secondary);
    }

    .header-controls {
      display: flex;
      align-items: center;
      gap: 16px;
      flex-wrap: wrap;
    }

    .pagination-panel {
      display: flex;
      align-items: center;
      gap: 6px;
      background: rgba(0, 0, 0, 0.35);
      border: 1px solid var(--tl-border);
      border-radius: 6px;
      padding: 2px 8px;
    }

    .page-btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 28px;
      height: 28px;
      padding: 0;
      border: none;
      background: transparent;
      border-radius: 4px;
      cursor: pointer;
      color: var(--tl-text-primary);
      transition: background 0.15s;

      &:hover:not(:disabled) {
        background: rgba(255, 255, 255, 0.08);
      }

      &:disabled {
        color: var(--tl-text-muted);
        opacity: 0.4;
        cursor: default;
      }
    }

    .page-icon {
      font-size: 20px;
      line-height: 1;
      user-select: none;
    }

    .page-indicator {
      font-size: 11px;
      color: var(--tl-text-secondary);
      user-select: none;

      strong {
        color: var(--tl-text-primary);
        font-family: monospace;
      }
    }

    .rank-range {
      font-size: 10px;
      color: var(--tl-text-muted);
      margin-left: 4px;
      font-family: monospace;
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
      min-height: 220px;
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
      height: 380px;
    }

    .fi-footer {
      padding-top: 10px;
      border-top: 1px solid rgba(255, 255, 255, 0.04);
    }

    .footer-note {
      display: flex;
      align-items: flex-start;
      gap: 8px;
      font-size: 11px;
      color: var(--tl-text-muted);
      line-height: 1.5;

      .note-icon {
        font-size: 16px;
        color: var(--tl-amber, #F59E0B);
        margin-top: 1px;
      }

      strong {
        color: var(--tl-text-primary);
      }

      em {
        color: var(--tl-text-secondary);
        font-style: normal;
        text-decoration: underline;
      }
    }
  `],
})
export class FeatureImportanceChartComponent implements OnChanges {
  @Input() title: string = 'Random Forest Feature Importance (All 63 Features)';
  @Input() subtitle: string = 'Weighted Gini impurity reduction evaluated on 63 leakage-excluded NetFlow statistical features';
  @Input() loading: boolean = false;
  @Input() errorMessage: string | null = null;
  @Input() allFeatures: RankedFeatureImportanceItem[] | null | undefined = null;

  chartOptions: EChartsOption = {};
  hasData = false;

  currentPage = 1;
  readonly pageSize = 10;
  totalPages = 1;

  ngOnChanges(): void {
    this.recompute();
  }

  get rankRangeText(): string {
    const list = this.sortedFeatures;
    if (!list.length) return '';
    const start = (this.currentPage - 1) * this.pageSize + 1;
    const end = Math.min(this.currentPage * this.pageSize, list.length);
    return `Ranks ${start}–${end}`;
  }

  get sortedFeatures(): RankedFeatureImportanceItem[] {
    const data = this.allFeatures || [];
    return [...data].sort((a, b) => b.importance - a.importance);
  }

  prevPage(): void {
    if (this.currentPage > 1) {
      this.currentPage--;
      this.renderCurrentPage();
    }
  }

  nextPage(): void {
    if (this.currentPage < this.totalPages) {
      this.currentPage++;
      this.renderCurrentPage();
    }
  }

  private recompute(): void {
    const data = this.sortedFeatures;
    if (!data.length) {
      this.hasData = false;
      this.totalPages = 1;
      this.currentPage = 1;
      this.chartOptions = {};
      return;
    }

    this.hasData = true;
    this.totalPages = Math.max(1, Math.ceil(data.length / this.pageSize));
    if (this.currentPage > this.totalPages) {
      this.currentPage = 1;
    }
    this.renderCurrentPage();
  }

  private renderCurrentPage(): void {
    const data = this.sortedFeatures;
    if (!data.length) return;

    const startIdx = (this.currentPage - 1) * this.pageSize;
    const pageSlice = data.slice(startIdx, startIdx + this.pageSize);

    // Reversed for horizontal bar chart (top rank on top)
    const reversedSlice = [...pageSlice].reverse();

    const yAxisLabels = reversedSlice.map(item => {
      const meta = FEATURE_METADATA_MAP[item.clean_feature_name];
      const displayName = meta ? meta.label : item.clean_feature_name;
      return `#${item.rank} ${displayName}`;
    });

    const values = reversedSlice.map(item => item.importance);

    this.chartOptions = {
      backgroundColor: 'transparent',
      grid: { left: 240, right: 110, top: 12, bottom: 20 },
      tooltip: {
        trigger: 'axis',
        axisPointer: { type: 'none' },
        backgroundColor: '#0F172A',
        borderColor: 'rgba(255,255,255,0.15)',
        borderWidth: 1,
        padding: [12, 14],
        textStyle: { color: '#F8FAFC', fontSize: 12 },
        formatter: (params: any) => {
          const p = Array.isArray(params) ? params[0] : params;
          const targetIndex = reversedSlice.length - 1 - p.dataIndex;
          const item = pageSlice[targetIndex];
          if (!item) return '';

          const meta = FEATURE_METADATA_MAP[item.clean_feature_name];
          const rawCol = meta ? meta.rawCol : item.feature_name;
          const label = meta ? meta.label : item.clean_feature_name;
          const explanation = meta ? meta.explanation : 'Derived NetFlow statistical feature.';
          const pct = (item.importance * 100).toFixed(3);

          return `
            <div style="font-family: inherit; max-width: 340px;">
              <div style="font-size: 13px; font-weight: 700; color: #38BDF8; margin-bottom: 2px;">
                #${item.rank} ${label}
              </div>
              <div style="font-size: 10px; font-family: monospace; color: #94A3B8; margin-bottom: 8px;">
                Dataset Feature: <code>${item.clean_feature_name}</code> | Raw Col: <code>${rawCol}</code> (Index: ${item.training_index})
              </div>
              <div style="display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 4px;">
                <span style="color: #CBD5E1;">Gini Impurity Reduction:</span>
                <span style="font-family: monospace; font-weight: 600; color: #34D399;">${item.importance.toFixed(6)}</span>
              </div>
              <div style="display: flex; justify-content: space-between; font-size: 11px; margin-bottom: 8px;">
                <span style="color: #64748B;">Global Normalized Share:</span>
                <span style="font-family: monospace; color: #E2E8F0;">${pct}%</span>
              </div>
              <div style="font-size: 11px; color: #94A3B8; line-height: 1.4; border-top: 1px solid rgba(255,255,255,0.08); padding-top: 6px;">
                ${explanation}
              </div>
            </div>
          `;
        },
      },
      xAxis: {
        type: 'value',
        max: 0.10, // Fixed scale for stable visual comparison across all 7 pages
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
        data: yAxisLabels,
        axisLabel: {
          color: '#E2E8F0',
          fontSize: 11,
          width: 230,
          overflow: 'truncate',
          fontWeight: 500,
        },
        axisLine: { lineStyle: { color: 'rgba(255,255,255,0.06)' } },
        axisTick: { show: false },
      },
      series: [
        {
          type: 'bar',
          data: values.map(v => ({
            value: v,
            itemStyle: {
              color: {
                type: 'linear',
                x: 0, y: 0, x2: 1, y2: 0,
                colorStops: [
                  { offset: 0, color: '#06B6D4' },
                  { offset: 1, color: '#10B981' },
                ],
              } as any,
              borderRadius: [0, 3, 3, 0],
            },
          })),
          barMaxWidth: 16,
          label: {
            show: true,
            position: 'right',
            color: '#94A3B8',
            fontSize: 10,
            fontFamily: 'monospace',
            formatter: (p: any) => {
              const imp = p.value as number;
              return `${imp.toFixed(4)} (${(imp * 100).toFixed(2)}%)`;
            },
          },
          emphasis: {
            itemStyle: { opacity: 0.85 },
          },
        },
      ],
    };
  }
}
