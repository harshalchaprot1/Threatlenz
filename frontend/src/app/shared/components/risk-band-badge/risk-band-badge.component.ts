import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-risk-band-badge',
  standalone: true,
  imports: [CommonModule],
  template: `
    <span
      class="risk-band-badge"
      [ngClass]="getBadgeClass()"
      [attr.title]="getTooltip()"
      [attr.aria-label]="'Risk Band: ' + getDisplayBand()"
    >
      <span class="material-symbols-outlined band-icon">{{ getIcon() }}</span>
      <span class="band-text">{{ getDisplayBand() }}</span>
    </span>
  `,
  styles: [`
    .risk-band-badge {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 3px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.5px;
      text-transform: uppercase;
      white-space: nowrap;
    }

    .band-icon {
      font-size: 14px;
    }

    .band-critical {
      background: rgba(239, 68, 68, 0.2);
      color: #EF4444;
      border: 1px solid rgba(239, 68, 68, 0.4);
    }

    .band-high {
      background: rgba(249, 115, 22, 0.2);
      color: #F97316;
      border: 1px solid rgba(249, 115, 22, 0.4);
    }

    .band-medium {
      background: rgba(245, 158, 11, 0.2);
      color: #F59E0B;
      border: 1px solid rgba(245, 158, 11, 0.4);
    }

    .band-low {
      background: rgba(16, 185, 129, 0.2);
      color: #10B981;
      border: 1px solid rgba(16, 185, 129, 0.4);
    }

    .band-informational {
      background: rgba(59, 130, 246, 0.2);
      color: #3B82F6;
      border: 1px solid rgba(59, 130, 246, 0.4);
    }

    .band-withheld {
      background: rgba(139, 92, 246, 0.15);
      color: #FBBF24;
      border: 1px dashed rgba(245, 158, 11, 0.5);
    }
  `],
})
export class RiskBandBadgeComponent {
  @Input() riskBand?: string | null;
  @Input() isConfirmed: boolean = true;
  @Input() provisionalBand?: string | null;

  getDisplayBand(): string {
    if (!this.isConfirmed || this.riskBand === 'Insufficient Evidence') {
      return 'Insufficient Evidence';
    }
    return this.riskBand || 'Unknown';
  }

  getIcon(): string {
    if (!this.isConfirmed || this.riskBand === 'Insufficient Evidence') {
      return 'shield_with_heart';
    }
    switch (this.riskBand?.toLowerCase()) {
      case 'critical':
        return 'dangerous';
      case 'high':
        return 'warning';
      case 'medium':
        return 'error_outline';
      case 'low':
        return 'security';
      case 'informational':
        return 'info';
      default:
        return 'help_outline';
    }
  }

  getBadgeClass(): string {
    if (!this.isConfirmed || this.riskBand === 'Insufficient Evidence') {
      return 'band-withheld';
    }
    switch (this.riskBand?.toLowerCase()) {
      case 'critical':
        return 'band-critical';
      case 'high':
        return 'band-high';
      case 'medium':
        return 'band-medium';
      case 'low':
        return 'band-low';
      case 'informational':
        return 'band-informational';
      default:
        return 'band-informational';
    }
  }

  getTooltip(): string {
    if (!this.isConfirmed || this.riskBand === 'Insufficient Evidence') {
      return this.provisionalBand
        ? `Operational rating withheld. ${this.provisionalBand}`
        : 'Operational rating withheld due to missing asset telemetry.';
    }
    return `Confirmed TLRS Risk Band: ${this.riskBand}`;
  }
}
