import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ThreatProfileSummary } from '../../../core/models';

interface Segment {
  label: string;
  count: number;
  formattedCount: string;
  percentage: number;
  color: string;
  dashArray: string;
  dashOffset: number;
}

@Component({
  selector: 'app-composition-donut-chart',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="donut-card">
      <div class="donut-header">
        <span class="donut-title">{{ title }}</span>
        <span class="donut-subtitle">{{ subtitle }}</span>
      </div>

      <div class="donut-content">
        <!-- SVG Donut Graphic -->
        <div class="svg-wrapper">
          <svg viewBox="0 0 160 160" class="donut-svg" aria-label="Traffic composition chart" role="img">
            <!-- Background circle -->
            <circle
              cx="80"
              cy="80"
              r="60"
              class="donut-bg-ring"
              fill="transparent"
              stroke-width="22"
            />

            <!-- Data Segments -->
            @for (seg of segments; track seg.label) {
              <circle
                cx="80"
                cy="80"
                r="60"
                fill="transparent"
                [attr.stroke]="seg.color"
                stroke-width="22"
                [attr.stroke-dasharray]="seg.dashArray"
                [attr.stroke-dashoffset]="seg.dashOffset"
                class="donut-segment"
              />
            }
          </svg>

          <!-- Centered Summary Text -->
          <div class="donut-center-text">
            <span class="center-val">{{ totalFormatted }}</span>
            <span class="center-label">Total Flows</span>
          </div>
        </div>

        <!-- Legend / Breakdown List -->
        <div class="donut-legend">
          @for (seg of segments; track seg.label) {
            <div class="legend-row">
              <div class="legend-left">
                <span class="color-dot" [style.background-color]="seg.color"></span>
                <span class="legend-name">{{ seg.label }}</span>
              </div>
              <div class="legend-right">
                <span class="legend-count">{{ seg.formattedCount }}</span>
                <span class="legend-pct">{{ seg.percentage.toFixed(1) }}%</span>
              </div>
            </div>
          }

          <div class="composition-note">
            <span class="material-symbols-outlined note-icon">info</span>
            <span>Accurate composition derived directly from evaluated campaign Netflow partitions.</span>
          </div>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .donut-card {
      background: var(--tl-bg-surface);
      border: 1px solid var(--tl-border);
      border-radius: 8px;
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 16px;
      height: 100%;
    }

    .donut-header {
      display: flex;
      flex-direction: column;
      gap: 2px;
      padding-bottom: 12px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.06);
    }

    .donut-title {
      font-size: 14px;
      font-weight: 600;
      color: var(--tl-text-primary);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .donut-subtitle {
      font-size: 12px;
      color: var(--tl-text-secondary);
    }

    .donut-content {
      display: flex;
      align-items: center;
      gap: 28px;
      flex-wrap: wrap;

      @media (max-width: 600px) {
        flex-direction: column;
        gap: 20px;
      }
    }

    .svg-wrapper {
      position: relative;
      width: 170px;
      height: 170px;
      flex-shrink: 0;
      margin: 0 auto;
    }

    .donut-svg {
      width: 100%;
      height: 100%;
      transform: rotate(-90deg);
      border-radius: 50%;
    }

    .donut-bg-ring {
      stroke: rgba(255, 255, 255, 0.05);
    }

    .donut-segment {
      transition: stroke-dasharray 0.5s cubic-bezier(0.4, 0, 0.2, 1);
    }

    .donut-center-text {
      position: absolute;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      display: flex;
      flex-direction: column;
      align-items: center;
      text-align: center;
      pointer-events: none;
    }

    .center-val {
      font-size: 14px;
      font-weight: 700;
      font-family: monospace;
      color: var(--tl-text-primary);
      line-height: 1.2;
    }

    .center-label {
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--tl-text-muted);
    }

    .donut-legend {
      display: flex;
      flex-direction: column;
      gap: 12px;
      flex: 1;
      min-width: 220px;
    }

    .legend-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 6px 8px;
      background: rgba(255, 255, 255, 0.02);
      border-radius: 6px;
      border: 1px solid rgba(255, 255, 255, 0.04);
    }

    .legend-left {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .color-dot {
      width: 10px;
      height: 10px;
      border-radius: 50%;
      flex-shrink: 0;
    }

    .legend-name {
      font-size: 13px;
      font-weight: 500;
      color: var(--tl-text-primary);
    }

    .legend-right {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .legend-count {
      font-size: 12px;
      font-family: monospace;
      color: var(--tl-text-secondary);
    }

    .legend-pct {
      font-size: 12px;
      font-weight: 600;
      color: var(--tl-text-primary);
      min-width: 42px;
      text-align: right;
    }

    .composition-note {
      display: flex;
      align-items: flex-start;
      gap: 6px;
      font-size: 11px;
      color: var(--tl-text-muted);
      margin-top: 4px;

      .note-icon {
        font-size: 14px;
        color: var(--tl-accent-cyan, #06B6D4);
        margin-top: 1px;
      }
    }
  `],
})
export class CompositionDonutChartComponent {
  @Input() title: string = 'Traffic Composition (Attack vs. Benign)';
  @Input() subtitle: string = 'Aggregate volume distribution across classified campaign flows';
  @Input() set profiles(data: ThreatProfileSummary[]) {
    this._profiles = data || [];
    this.recompute();
  }

  private _profiles: ThreatProfileSummary[] = [];
  segments: Segment[] = [];
  totalFormatted: string = '0';

  private recompute(): void {
    if (!this._profiles || this._profiles.length === 0) {
      this.segments = [];
      this.totalFormatted = '0';
      return;
    }

    let benignFlows = 0;
    let attackFlows = 0;
    let unknownFlows = 0;

    for (const p of this._profiles) {
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
    this.totalFormatted = total > 1000000 ? (total / 1000000).toFixed(2) + 'M' : total.toLocaleString();

    // Circumference of radius 60 circle = 2 * PI * 60 = 376.99
    const circumference = 2 * Math.PI * 60;
    let currentOffset = 0;

    const rawSegments = [
      {
        label: 'Benign Baseline',
        count: benignFlows,
        color: '#10B981', // emerald
      },
      {
        label: 'Adversarial Attacks',
        count: attackFlows,
        color: '#EF4444', // crimson
      },
    ];

    if (unknownFlows > 0) {
      rawSegments.push({
        label: 'Unclassified / Unknown',
        count: unknownFlows,
        color: '#9CA3AF',
      });
    }

    this.segments = rawSegments.map((item) => {
      const pct = total > 0 ? (item.count / total) * 100 : 0;
      const strokeLen = (pct / 100) * circumference;
      const dashArray = `${strokeLen.toFixed(2)} ${(circumference - strokeLen).toFixed(2)}`;
      const dashOffset = -currentOffset;
      currentOffset += strokeLen;

      return {
        label: item.label,
        count: item.count,
        formattedCount: item.count.toLocaleString(),
        percentage: pct,
        color: item.color,
        dashArray: dashArray,
        dashOffset: dashOffset,
      };
    });
  }
}
