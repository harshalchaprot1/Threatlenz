import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { SplitMetricsSummary } from '../../../core/models';

@Component({
  selector: 'app-confusion-matrix-grid',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="cm-card">
      <div class="cm-header">
        <div class="header-left">
          <span class="cm-title">{{ title }}</span>
          <span class="cm-subtitle">{{ subtitle }}</span>
        </div>

        <div class="header-controls">
          <!-- Split Toggle: Validation vs Held-out Test -->
          <div class="toggle-group">
            <button
              type="button"
              class="toggle-btn"
              [class.active]="activeSplit === 'val'"
              (click)="activeSplit = 'val'"
              title="Validation set used for threshold policy selection and reliability tuning"
            >
              Validation Split
            </button>
            <button
              type="button"
              class="toggle-btn"
              [class.active]="activeSplit === 'test'"
              (click)="activeSplit = 'test'"
              title="Held-out test set (March 1–2) used for final model evaluation benchmark"
            >
              Held-out Test Split
            </button>
          </div>

          <!-- Format Toggle: Normalized vs Raw Counts -->
          <div class="toggle-group">
            <button
              type="button"
              class="toggle-btn"
              [class.active]="formatMode === 'normalized'"
              (click)="formatMode = 'normalized'"
              title="Row-normalized proportions (Recall per true class)"
            >
              Normalized (%)
            </button>
            <button
              type="button"
              class="toggle-btn"
              [class.active]="formatMode === 'raw'"
              (click)="formatMode = 'raw'"
              title="Raw flow prediction counts"
            >
              Raw Counts
            </button>
          </div>
        </div>
      </div>

      @if (loading) {
        <div class="state-box">
          <span class="state-label">Loading confusion matrix benchmark...</span>
        </div>
      } @else if (errorMessage) {
        <div class="state-box error">
          <span class="material-symbols-outlined error-icon">warning</span>
          <span class="state-label">{{ errorMessage }}</span>
        </div>
      } @else if (!currentMetrics || !currentMetrics.confusion_matrix) {
        <div class="state-box">
          <span class="state-label">No confusion matrix data available.</span>
        </div>
      } @else {
        <div class="cm-content">
          <!-- Split Summary Banner -->
          <div class="split-summary-bar">
            <div class="summary-pill">
              <span class="pill-label">Evaluated Split:</span>
              <span class="pill-val font-mono uppercase">{{ currentMetrics.evaluated_split }}</span>
            </div>
            <div class="summary-pill">
              <span class="pill-label">Evaluated Flows:</span>
              <span class="pill-val font-mono">{{ currentMetrics.total_evaluated_samples | number }}</span>
            </div>
            <div class="summary-pill">
              <span class="pill-label">Overall Accuracy:</span>
              <span class="pill-val font-mono text-emerald">{{ (currentMetrics.overall_accuracy * 100).toFixed(2) }}%</span>
            </div>
            <div class="summary-pill">
              <span class="pill-label">Macro F1:</span>
              <span class="pill-val font-mono text-cyan">{{ currentMetrics.macro_f1.toFixed(4) }}</span>
            </div>
            <div class="summary-pill">
              <span class="pill-label">Balanced Accuracy:</span>
              <span class="pill-val font-mono">{{ (currentMetrics.balanced_accuracy * 100).toFixed(2) }}%</span>
            </div>
          </div>

          <!-- Matrix Table with Horizontal Scroll -->
          <div class="matrix-wrapper">
            <div class="axis-y-label">
              <span>TRUE LABEL &darr;</span>
            </div>

            <div class="table-scroll-container">
              <div class="axis-x-label">
                <span>PREDICTED LABEL &rarr;</span>
              </div>

              <table class="cm-table">
                <thead>
                  <tr>
                    <th class="corner-header">True \ Pred</th>
                    @for (label of labels; track label) {
                      <th class="col-header" [title]="'Predicted: ' + label">
                        <span class="header-text">{{ label }}</span>
                      </th>
                    }
                  </tr>
                </thead>
                <tbody>
                  @for (trueLabel of labels; track trueLabel; let r = $index) {
                    <tr>
                      <td class="row-header" [title]="'True: ' + trueLabel">
                        <span class="row-text">{{ trueLabel }}</span>
                      </td>
                      @for (predLabel of labels; track predLabel; let c = $index) {
                        <td
                          class="matrix-cell"
                          [style.background-color]="getCellBg(r, c)"
                          [title]="'True: ' + trueLabel + ' | Pred: ' + predLabel + ' | Value: ' + getCellTooltip(r, c)"
                        >
                          <span class="cell-val font-mono" [ngClass]="r === c ? 'val-diag' : 'val-off'">
                            {{ getCellValue(r, c) }}
                          </span>
                        </td>
                      }
                    </tr>
                  }
                </tbody>
              </table>
            </div>
          </div>

          <div class="cm-footer">
            <span class="footer-note">
              <span class="material-symbols-outlined note-icon">policy</span>
              <strong>Academic Governance Benchmark:</strong> Confusion matrices represent clean Random Forest pilot evaluations across 14 classes. Live pipeline inference remains quarantined under ThreatLenz governance policy pending formal Phase 6 production validation certification.
            </span>
          </div>
        </div>
      }
    </div>
  `,
  styles: [`
    .cm-card {
      background: var(--tl-bg-surface);
      border: 1px solid var(--tl-border);
      border-radius: 8px;
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .cm-header {
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
      gap: 2px;
    }

    .cm-title {
      font-size: 14px;
      font-weight: 600;
      color: var(--tl-text-primary);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .cm-subtitle {
      font-size: 12px;
      color: var(--tl-text-secondary);
    }

    .header-controls {
      display: flex;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
    }

    .toggle-group {
      display: flex;
      background: rgba(0, 0, 0, 0.3);
      border: 1px solid var(--tl-border);
      border-radius: 6px;
      padding: 2px;
    }

    .toggle-btn {
      background: transparent;
      border: none;
      color: var(--tl-text-muted);
      font-size: 11px;
      font-weight: 600;
      padding: 4px 10px;
      border-radius: 4px;
      cursor: pointer;
      transition: all 0.15s ease;

      &:hover {
        color: var(--tl-text-primary);
      }

      &.active {
        background: var(--tl-cyan, #06B6D4);
        color: #0B1120;
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

    .cm-content {
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .split-summary-bar {
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid rgba(255, 255, 255, 0.04);
      border-radius: 6px;
      padding: 8px 14px;
    }

    .summary-pill {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 11px;
    }

    .pill-label {
      color: var(--tl-text-muted);
      text-transform: uppercase;
      font-size: 10px;
      letter-spacing: 0.3px;
    }

    .pill-val {
      color: var(--tl-text-primary);
      font-weight: 600;

      &.text-emerald {
        color: var(--tl-emerald, #10B981);
      }
      &.text-cyan {
        color: var(--tl-cyan, #06B6D4);
      }
      &.uppercase {
        text-transform: uppercase;
      }
    }

    .matrix-wrapper {
      display: flex;
      gap: 8px;
      position: relative;
    }

    .axis-y-label {
      writing-mode: vertical-lr;
      transform: rotate(180deg);
      text-align: center;
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 1px;
      color: var(--tl-text-muted);
      padding: 8px 0;
    }

    .table-scroll-container {
      flex: 1;
      overflow-x: auto;
      display: flex;
      flex-direction: column;
      gap: 4px;
    }

    .axis-x-label {
      text-align: center;
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 1px;
      color: var(--tl-text-muted);
      padding-left: 140px;
    }

    .cm-table {
      border-collapse: collapse;
      font-size: 11px;
      min-width: 900px;
    }

    .corner-header {
      width: 140px;
      font-size: 10px;
      color: var(--tl-text-muted);
      text-align: left;
      padding: 4px 8px;
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid rgba(255, 255, 255, 0.05);
    }

    .col-header {
      width: 55px;
      max-width: 65px;
      padding: 8px 2px;
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid rgba(255, 255, 255, 0.05);
      text-align: center;

      .header-text {
        display: inline-block;
        font-size: 10px;
        color: var(--tl-text-secondary);
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        max-width: 55px;
      }
    }

    .row-header {
      width: 140px;
      padding: 4px 8px;
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid rgba(255, 255, 255, 0.05);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;

      .row-text {
        font-size: 11px;
        font-weight: 600;
        color: var(--tl-text-primary);
      }
    }

    .matrix-cell {
      width: 55px;
      height: 28px;
      text-align: center;
      border: 1px solid rgba(255, 255, 255, 0.03);
      cursor: crosshair;
      transition: outline 0.1s ease;

      &:hover {
        outline: 1px solid var(--tl-cyan, #06B6D4);
        z-index: 10;
        position: relative;
      }
    }

    .cell-val {
      font-size: 10px;
      display: inline-block;

      &.val-diag {
        font-weight: 700;
        color: #FFFFFF;
      }

      &.val-off {
        color: rgba(255, 255, 255, 0.4);
      }
    }

    .cm-footer {
      padding-top: 10px;
      border-top: 1px solid rgba(255, 255, 255, 0.04);
    }

    .footer-note {
      display: flex;
      align-items: flex-start;
      gap: 6px;
      font-size: 11px;
      color: var(--tl-text-muted);
      line-height: 1.5;

      .note-icon {
        font-size: 15px;
        color: var(--tl-amber, #F59E0B);
        margin-top: 2px;
      }

      strong {
        color: var(--tl-text-primary);
      }
    }
  `],
})
export class ConfusionMatrixGridComponent {
  @Input() title: string = '14×14 Multi-Class Confusion Matrix';
  @Input() subtitle: string = 'Raw prediction distributions and class-normalized recall matrices';
  @Input() loading: boolean = false;
  @Input() errorMessage: string | null = null;

  @Input() validationMetrics: SplitMetricsSummary | null | undefined = null;
  @Input() testMetrics: SplitMetricsSummary | null | undefined = null;

  activeSplit: 'val' | 'test' = 'val';
  formatMode: 'normalized' | 'raw' = 'normalized';

  get currentMetrics(): SplitMetricsSummary | null {
    const metrics = this.activeSplit === 'val' ? this.validationMetrics : this.testMetrics;
    return metrics ?? null;
  }

  get labels(): string[] {
    return this.currentMetrics?.confusion_matrix?.class_labels || [];
  }

  getCellValue(r: number, c: number): string {
    const cm = this.currentMetrics?.confusion_matrix;
    if (!cm) return '-';

    if (this.formatMode === 'normalized') {
      const val = cm.normalized_matrix?.[r]?.[c] ?? 0;
      return (val * 100).toFixed(val === 1 || val === 0 ? 0 : 1) + '%';
    } else {
      const raw = cm.raw_matrix?.[r]?.[c] ?? 0;
      if (raw >= 100000) {
        return (raw / 1000).toFixed(0) + 'K';
      }
      return raw.toLocaleString();
    }
  }

  getCellTooltip(r: number, c: number): string {
    const cm = this.currentMetrics?.confusion_matrix;
    if (!cm) return '';
    const norm = (cm.normalized_matrix?.[r]?.[c] ?? 0) * 100;
    const raw = (cm.raw_matrix?.[r]?.[c] ?? 0).toLocaleString();
    return `${raw} flows (${norm.toFixed(2)}%)`;
  }

  getCellBg(r: number, c: number): string {
    const cm = this.currentMetrics?.confusion_matrix;
    if (!cm) return 'transparent';
    const norm = cm.normalized_matrix?.[r]?.[c] ?? 0;

    if (r === c) {
      // Diagonal: true positive recall (emerald gradient)
      if (norm >= 0.95) return 'rgba(16, 185, 129, 0.65)';
      if (norm >= 0.70) return 'rgba(16, 185, 129, 0.45)';
      if (norm >= 0.30) return 'rgba(16, 185, 129, 0.25)';
      return 'rgba(16, 185, 129, 0.10)';
    } else {
      // Off-diagonal: confusion error (amber/rose gradient)
      if (norm >= 0.20) return 'rgba(239, 68, 68, 0.60)';
      if (norm >= 0.05) return 'rgba(239, 68, 68, 0.35)';
      if (norm > 0) return 'rgba(245, 158, 11, 0.18)';
      return 'transparent';
    }
  }
}

