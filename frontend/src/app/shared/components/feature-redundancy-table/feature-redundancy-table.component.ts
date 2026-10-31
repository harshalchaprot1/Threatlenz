import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { FeatureRedundancyResponse, EvaluatedCorrelationPair } from '../../../core/models';

@Component({
  selector: 'app-feature-redundancy-table',
  standalone: true,
  imports: [CommonModule, MatProgressSpinnerModule],
  template: `
    <div class="redundancy-card">
      <div class="redundancy-header">
        <div class="header-titles">
          <span class="redundancy-title">{{ title }}</span>
          <span class="redundancy-subtitle">{{ subtitle }}</span>
        </div>
        <div class="redundancy-stats">
          <span class="stat-pill near-duplicate">
            <span class="pill-dot dot-dup"></span>
            6 Near-Duplicates (r &ge; 0.999999)
          </span>
          <span class="stat-pill collinear">
            <span class="pill-dot dot-col"></span>
            2 Strongly Collinear (0.99 &le; r &lt; 0.999999)
          </span>
          <span class="stat-pill non-collinear">
            <span class="pill-dot dot-non"></span>
            1 Non-Collinear (r = 0.28)
          </span>
        </div>
      </div>

      <!-- Loading State -->
      @if (loading) {
        <div class="state-container">
          <mat-spinner diameter="36"></mat-spinner>
          <span>Evaluating Pearson correlation matrix...</span>
        </div>
      }

      <!-- Error State -->
      @if (errorMessage && !loading) {
        <div class="state-container error-state">
          <span class="material-symbols-outlined state-icon">error</span>
          <span>{{ errorMessage }}</span>
        </div>
      }

      <!-- Redundancy Table -->
      @if (!loading && !errorMessage && pairs.length > 0) {
        <div class="table-responsive">
          <table class="redundancy-table">
            <thead>
              <tr>
                <th>Evaluated Pair</th>
                <th>Pair Description</th>
                <th>Pearson r</th>
                <th>Classification</th>
                <th>Engineering Recommendation</th>
              </tr>
            </thead>
            <tbody>
              @for (pair of pairs; track pair.feature_1 + '-' + pair.feature_2) {
                <tr [ngClass]="getRowClass(pair)">
                  <td class="features-cell">
                    <span class="feat-tag font-mono">{{ pair.feature_1 }}</span>
                    <span class="corr-arrow">&harr;</span>
                    <span class="feat-tag font-mono">{{ pair.feature_2 }}</span>
                  </td>
                  <td class="desc-cell">{{ pair.description }}</td>
                  <td class="corr-cell font-mono">
                    <div class="corr-gauge">
                      <span class="corr-num">{{ pair.pearson_correlation.toFixed(6) }}</span>
                      <div class="gauge-bar">
                        <div
                          class="gauge-fill"
                          [style.width.%]="pair.pearson_correlation * 100"
                          [ngClass]="getGaugeFillClass(pair)"
                        ></div>
                      </div>
                    </div>
                  </td>
                  <td>
                    @if (pair.is_near_duplicate) {
                      <span class="class-pill pill-duplicate">Near-Duplicate</span>
                    } @else if (pair.is_strongly_collinear) {
                      <span class="class-pill pill-collinear">Strongly Collinear</span>
                    } @else {
                      <span class="class-pill pill-non-collinear">Non-Collinear</span>
                    }
                  </td>
                  <td class="rec-cell">
                    <span class="rec-icon material-symbols-outlined">{{ getRecIcon(pair) }}</span>
                    <span class="rec-text">{{ pair.recommendation }}</span>
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>

        <div class="redundancy-footer">
          <span class="footer-note">
            <span class="material-symbols-outlined note-icon">tips_and_updates</span>
            <strong>Pipeline Pruning Strategy:</strong> Of the 9 evaluated feature pairs, exactly 8 exhibit collinearity. The 6 near-duplicate pairs (Pearson r &ge; 0.999999) represent mathematical redundancy between subflow aggregates and total counters; dropping them reduces model training memory and tree splits without information loss.
          </span>
        </div>
      }

      @if (!loading && !errorMessage && pairs.length === 0) {
        <div class="state-container">
          <span class="material-symbols-outlined state-icon">tune</span>
          <span>No feature redundancy telemetry available.</span>
        </div>
      }
    </div>
  `,
  styles: [`
    .redundancy-card {
      background: var(--tl-bg-surface, #1E293B);
      border: 1px solid var(--tl-border, rgba(255, 255, 255, 0.08));
      border-radius: 8px;
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .redundancy-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 14px;
    }

    .header-titles {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }

    .redundancy-title {
      font-size: 16px;
      font-weight: 700;
      color: var(--tl-text-primary, #F8FAFC);
    }

    .redundancy-subtitle {
      font-size: 12px;
      color: var(--tl-text-secondary, #94A3B8);
    }

    .redundancy-stats {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }

    .stat-pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;

      &.near-duplicate {
        background: rgba(239, 68, 68, 0.12);
        color: #F87171;
        border: 1px solid rgba(239, 68, 68, 0.3);
      }

      &.collinear {
        background: rgba(245, 158, 11, 0.12);
        color: #FBBF24;
        border: 1px solid rgba(245, 158, 11, 0.3);
      }

      &.non-collinear {
        background: rgba(16, 185, 129, 0.12);
        color: #34D399;
        border: 1px solid rgba(16, 185, 129, 0.3);
      }
    }

    .pill-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      &.dot-dup { background: #EF4444; }
      &.dot-col { background: #F59E0B; }
      &.dot-non { background: #10B981; }
    }

    .table-responsive {
      overflow-x: auto;
      border: 1px solid var(--tl-border, rgba(255, 255, 255, 0.08));
      border-radius: 6px;
    }

    .redundancy-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;

      th {
        text-align: left;
        padding: 10px 14px;
        background: rgba(15, 23, 42, 0.8);
        color: var(--tl-text-muted, #64748B);
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        border-bottom: 1px solid var(--tl-border, rgba(255, 255, 255, 0.08));
      }

      td {
        padding: 12px 14px;
        border-bottom: 1px solid rgba(255, 255, 255, 0.04);
        color: var(--tl-text-primary, #F8FAFC);
        vertical-align: middle;
      }

      tr.row-duplicate {
        background: rgba(239, 68, 68, 0.03);
      }

      tr.row-collinear {
        background: rgba(245, 158, 11, 0.03);
      }

      tr.row-non-collinear {
        background: rgba(16, 185, 129, 0.03);
      }
    }

    .features-cell {
      white-space: nowrap;
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .feat-tag {
      background: rgba(255, 255, 255, 0.06);
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 11px;
      color: var(--tl-cyan, #06B6D4);
    }

    .corr-arrow {
      color: var(--tl-text-muted, #64748B);
      font-size: 12px;
    }

    .desc-cell {
      font-size: 12px;
      color: var(--tl-text-secondary, #94A3B8);
    }

    .corr-cell {
      min-width: 130px;
    }

    .corr-gauge {
      display: flex;
      flex-direction: column;
      gap: 3px;
    }

    .corr-num {
      font-size: 11px;
      font-weight: 700;
      color: var(--tl-text-primary, #F8FAFC);
    }

    .gauge-bar {
      width: 100%;
      height: 4px;
      background: rgba(255, 255, 255, 0.08);
      border-radius: 2px;
      overflow: hidden;
    }

    .gauge-fill {
      height: 100%;
      border-radius: 2px;
      &.fill-dup { background: #EF4444; }
      &.fill-col { background: #F59E0B; }
      &.fill-non { background: #10B981; }
    }

    .class-pill {
      display: inline-block;
      font-size: 10px;
      font-weight: 700;
      padding: 2px 7px;
      border-radius: 4px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      white-space: nowrap;

      &.pill-duplicate {
        background: rgba(239, 68, 68, 0.15);
        color: #F87171;
        border: 1px solid rgba(239, 68, 68, 0.3);
      }

      &.pill-collinear {
        background: rgba(245, 158, 11, 0.15);
        color: #FBBF24;
        border: 1px solid rgba(245, 158, 11, 0.3);
      }

      &.pill-non-collinear {
        background: rgba(16, 185, 129, 0.15);
        color: #34D399;
        border: 1px solid rgba(16, 185, 129, 0.3);
      }
    }

    .rec-cell {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 12px;
      color: #D1D5DB;
    }

    .rec-icon {
      font-size: 16px;
      color: var(--tl-cyan, #06B6D4);
    }

    .font-mono {
      font-family: monospace;
    }

    .redundancy-footer {
      padding-top: 8px;
    }

    .footer-note {
      display: flex;
      align-items: flex-start;
      gap: 8px;
      font-size: 11px;
      color: var(--tl-text-muted, #64748B);
      line-height: 1.5;

      .note-icon {
        font-size: 16px;
        color: var(--tl-amber, #F59E0B);
        margin-top: 1px;
      }

      strong {
        color: var(--tl-text-primary, #F8FAFC);
      }
    }

    .state-container {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      min-height: 180px;
      gap: 12px;
      color: var(--tl-text-secondary, #94A3B8);
      font-size: 13px;
    }

    .error-state {
      color: #EF4444;
      .state-icon { font-size: 32px; }
    }
  `],
})
export class FeatureRedundancyTableComponent {
  @Input() title: string = 'Statistical Feature Redundancy & Correlation Pruning';
  @Input() subtitle: string = 'Pearson correlation evaluation across 9 feature pairs from CSE-CIC-IDS2018 Spark analytics';
  @Input() loading: boolean = false;
  @Input() errorMessage: string | null = null;

  @Input() set redundancyData(data: FeatureRedundancyResponse | null | undefined) {
    this._data = data;
    this.pairs = data?.all_evaluated_correlations || [];
  }

  private _data: FeatureRedundancyResponse | null | undefined = null;
  pairs: EvaluatedCorrelationPair[] = [];

  getRowClass(pair: EvaluatedCorrelationPair): string {
    if (pair.is_near_duplicate) return 'row-duplicate';
    if (pair.is_strongly_collinear) return 'row-collinear';
    return 'row-non-collinear';
  }

  getGaugeFillClass(pair: EvaluatedCorrelationPair): string {
    if (pair.is_near_duplicate) return 'fill-dup';
    if (pair.is_strongly_collinear) return 'fill-col';
    return 'fill-non';
  }

  getRecIcon(pair: EvaluatedCorrelationPair): string {
    if (pair.is_near_duplicate) return 'delete_sweep';
    if (pair.is_strongly_collinear) return 'visibility';
    return 'check_circle';
  }
}
