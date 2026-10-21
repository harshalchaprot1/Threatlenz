import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ModelReliability } from '../../../core/models';

@Component({
  selector: 'app-reliability-badge',
  standalone: true,
  imports: [CommonModule],
  template: `
    <span
      class="rel-badge"
      [ngClass]="getBadgeClass()"
      [attr.title]="getTooltip()"
      [attr.aria-label]="'Model Reliability: ' + getDisplayLabel()"
    >
      <span class="material-symbols-outlined rel-icon">{{ getIcon() }}</span>
      <span class="rel-text">{{ getDisplayLabel() }}</span>
    </span>
  `,
  styles: [`
    .rel-badge {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 3px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.3px;
      white-space: nowrap;
    }

    .rel-icon {
      font-size: 14px;
    }

    .rel-high {
      background: rgba(16, 185, 129, 0.15);
      color: #34D399;
      border: 1px solid rgba(16, 185, 129, 0.3);
    }

    .rel-evaluable {
      background: rgba(59, 130, 246, 0.15);
      color: #60A5FA;
      border: 1px solid rgba(59, 130, 246, 0.3);
    }

    .rel-unreliable {
      background: rgba(245, 158, 11, 0.15);
      color: #FBBF24;
      border: 1px solid rgba(245, 158, 11, 0.35);
    }

    .rel-non-evaluable {
      background: rgba(107, 114, 128, 0.2);
      color: #9CA3AF;
      border: 1px solid rgba(107, 114, 128, 0.35);
    }

    .rel-none {
      background: rgba(107, 114, 128, 0.1);
      color: #6B7280;
      border: 1px dashed rgba(107, 114, 128, 0.3);
    }
  `],
})
export class ReliabilityBadgeComponent {
  @Input() reliability?: ModelReliability | string | null;

  getDisplayLabel(): string {
    switch (this.reliability) {
      case 'HIGH_RELIABILITY':
        return 'High Reliability';
      case 'EVALUABLE':
        return 'Evaluable';
      case 'UNRELIABLE':
        return 'Unreliable (Excluded)';
      case 'NON_EVALUABLE':
        return 'Non-Evaluable';
      default:
        return 'Not Evaluated';
    }
  }

  getIcon(): string {
    switch (this.reliability) {
      case 'HIGH_RELIABILITY':
        return 'verified';
      case 'EVALUABLE':
        return 'check_circle_outline';
      case 'UNRELIABLE':
        return 'report_problem';
      case 'NON_EVALUABLE':
        return 'block';
      default:
        return 'radio_button_unchecked';
    }
  }

  getBadgeClass(): string {
    switch (this.reliability) {
      case 'HIGH_RELIABILITY':
        return 'rel-high';
      case 'EVALUABLE':
        return 'rel-evaluable';
      case 'UNRELIABLE':
        return 'rel-unreliable';
      case 'NON_EVALUABLE':
        return 'rel-non-evaluable';
      default:
        return 'rel-none';
    }
  }

  getTooltip(): string {
    switch (this.reliability) {
      case 'HIGH_RELIABILITY':
        return 'Validation support >= 100 and min(Precision, Recall, F1) >= 0.75';
      case 'EVALUABLE':
        return 'Validation support >= 30 and min(Precision, Recall, F1) >= 0.60';
      case 'UNRELIABLE':
        return 'Validation support < 30 or min metric < 0.60. Model excluded from operational evidence.';
      case 'NON_EVALUABLE':
        return 'Zero validation support. Model cannot be evaluated on this category.';
      default:
        return 'No model reliability assessment available.';
    }
  }
}
