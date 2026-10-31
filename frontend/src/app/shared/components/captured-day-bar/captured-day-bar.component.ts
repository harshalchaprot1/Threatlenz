import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { TemporalDateSummary } from '../../../core/models';

interface DayBarItem {
  date: string;
  formattedDate: string;
  dayOfWeek: string;
  totalFlows: number;
  formattedFlows: string;
  barHeightPct: number;
}

@Component({
  selector: 'app-captured-day-bar',
  standalone: true,
  imports: [CommonModule],
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
      } @else if (bars.length === 0) {
        <div class="state-box">
          <span class="state-label">No campaign date records available.</span>
        </div>
      } @else {
        <div class="chart-content">
          <div class="chart-stage">
            <!-- Reference Guidelines -->
            <div class="grid-lines">
              <div class="grid-line"><span class="line-label">1.0M</span></div>
              <div class="grid-line"><span class="line-label">500K</span></div>
              <div class="grid-line"><span class="line-label">0</span></div>
            </div>

            <!-- Vertical Bars for Each Captured Day -->
            <div class="bars-container">
              @for (bar of bars; track bar.date) {
                <div class="bar-column" [title]="bar.date + ' (' + bar.dayOfWeek + '): ' + bar.formattedFlows + ' total flows'">
                  <!-- Flow Value Label (Above Bar) -->
                  <div class="bar-value-label">
                    {{ formatCompactNumber(bar.totalFlows) }}
                  </div>

                  <!-- Bar Track & Fill -->
                  <div class="bar-track">
                    <div
                      class="bar-fill"
                      [style.height.%]="bar.barHeightPct"
                    ></div>
                  </div>

                  <!-- Date & Day Labels (Below Bar) -->
                  <div class="bar-label-group">
                    <span class="bar-date">{{ bar.formattedDate }}</span>
                    <span class="bar-dow">{{ bar.dayOfWeek }}</span>
                  </div>
                </div>
              }
            </div>
          </div>

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

      &.error {
        color: #EF4444;
      }
    }

    .chart-content {
      display: flex;
      flex-direction: column;
      gap: 14px;
      flex: 1;
    }

    .chart-stage {
      position: relative;
      height: 250px;
      display: flex;
      align-items: flex-end;
      padding-left: 42px;
      padding-bottom: 30px;
    }

    .grid-lines {
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      bottom: 30px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      pointer-events: none;
    }

    .grid-line {
      width: 100%;
      border-bottom: 1px dashed rgba(255, 255, 255, 0.06);
      position: relative;

      .line-label {
        position: absolute;
        left: 0;
        top: -8px;
        font-size: 10px;
        font-family: monospace;
        color: var(--tl-text-muted);
      }
    }

    .bars-container {
      width: 100%;
      height: 100%;
      display: grid;
      grid-template-columns: repeat(8, 1fr);
      gap: 16px;
      align-items: flex-end;
      position: relative;
      z-index: 2;

      @media (max-width: 600px) {
        gap: 6px;
      }
    }

    .bar-column {
      display: flex;
      flex-direction: column;
      align-items: center;
      height: 100%;
      justify-content: flex-end;
      cursor: pointer;

      &:hover {
        .bar-fill {
          background: #38BDF8;
        }
        .bar-value-label {
          color: var(--tl-cyan, #06B6D4);
        }
      }
    }

    .bar-value-label {
      font-size: 11px;
      font-family: monospace;
      font-weight: 600;
      color: var(--tl-text-muted);
      margin-bottom: 6px;
      transition: color 0.12s ease;
      text-align: center;
      white-space: nowrap;

      @media (max-width: 640px) {
        font-size: 9px;
      }
    }

    .bar-track {
      width: 100%;
      max-width: 48px;
      height: 100%;
      background: rgba(255, 255, 255, 0.03);
      border-radius: 3px 3px 0 0;
      display: flex;
      align-items: flex-end;
      overflow: hidden;
    }

    .bar-fill {
      width: 100%;
      border-radius: 3px 3px 0 0;
      background: #0284C7;
      transition: height 0.3s ease;
    }

    .bar-label-group {
      position: absolute;
      bottom: 0;
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 1px;
      transform: translateY(100%);
    }

    .bar-date {
      font-size: 11px;
      font-family: monospace;
      font-weight: 600;
      color: var(--tl-text-primary);
      white-space: nowrap;

      @media (max-width: 640px) {
        font-size: 9px;
      }
    }

    .bar-dow {
      font-size: 9px;
      color: var(--tl-text-muted);
      text-transform: uppercase;
      letter-spacing: 0.3px;
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
export class CapturedDayBarComponent {
  @Input() title: string = 'Campaign Captured-Day Flow Volume';
  @Input() subtitle: string = 'Daily traffic volume across all 8 non-contiguous observation dates in CSE-CIC-IDS2018';
  @Input() loading: boolean = false;
  @Input() errorMessage: string | null = null;

  @Input() set eventDateTotals(data: TemporalDateSummary[] | null | undefined) {
    this._data = data || [];
    this.recompute();
  }

  private _data: TemporalDateSummary[] = [];
  bars: DayBarItem[] = [];

  formatCompactNumber(num: number): string {
    if (num >= 1000000) {
      return (num / 1000000).toFixed(2) + 'M';
    }
    if (num >= 1000) {
      return (num / 1000).toFixed(0) + 'K';
    }
    return num.toString();
  }

  private recompute(): void {
    if (!this._data || this._data.length === 0) {
      this.bars = [];
      return;
    }

    // Sort chronologically by ISO date string
    const sorted = [...this._data].sort((a, b) => a.event_date.localeCompare(b.event_date));
    const maxFlow = Math.max(...sorted.map((d) => d.total_flows), 1);

    this.bars = sorted.map((d) => {
      // Parse ISO date string (YYYY-MM-DD)
      const parts = d.event_date.split('-');
      const month = parts[1] || '02';
      const day = parts[2] || '01';
      const formattedDate = `${month}/${day}`;

      // Calculate Day of Week
      const dateObj = new Date(d.event_date + 'T00:00:00Z');
      const dayOfWeek = isNaN(dateObj.getTime())
        ? ''
        : dateObj.toLocaleDateString('en-US', { weekday: 'short', timeZone: 'UTC' });

      const heightPct = Math.min(Math.max((d.total_flows / maxFlow) * 100, 2), 100);

      return {
        date: d.event_date,
        formattedDate,
        dayOfWeek,
        totalFlows: d.total_flows,
        formattedFlows: d.total_flows.toLocaleString(),
        barHeightPct: heightPct,
      };
    });
  }
}

