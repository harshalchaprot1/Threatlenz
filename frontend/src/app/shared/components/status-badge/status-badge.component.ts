import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { AttackStatus } from '../../../core/models';

@Component({
  selector: 'app-status-badge',
  standalone: true,
  imports: [CommonModule],
  template: `
    <span
      class="status-chip"
      [ngClass]="getChipClass()"
      [attr.aria-label]="'Traffic Status: ' + (status || 'UNKNOWN')"
    >
      <span class="material-symbols-outlined chip-icon">{{ getIcon() }}</span>
      <span class="chip-text">{{ getLabel() }}</span>
    </span>
  `,
  styles: [`
    .status-chip {
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

    .chip-icon {
      font-size: 14px;
    }

    .chip-attack {
      background: rgba(239, 68, 68, 0.15);
      color: #F87171;
      border: 1px solid rgba(239, 68, 68, 0.35);
    }

    .chip-benign {
      background: rgba(16, 185, 129, 0.15);
      color: #34D399;
      border: 1px solid rgba(16, 185, 129, 0.35);
    }

    .chip-unknown {
      background: rgba(139, 92, 246, 0.15);
      color: #C4B5FD;
      border: 1px solid rgba(139, 92, 246, 0.35);
    }
  `],
})
export class StatusBadgeComponent {
  @Input() status?: AttackStatus | string | null;

  getLabel(): string {
    if (!this.status) return 'UNKNOWN';
    return this.status.toUpperCase();
  }

  getIcon(): string {
    switch (this.status?.toUpperCase()) {
      case 'ATTACK':
        return 'warning';
      case 'BENIGN':
        return 'check_circle';
      default:
        return 'help';
    }
  }

  getChipClass(): string {
    switch (this.status?.toUpperCase()) {
      case 'ATTACK':
        return 'chip-attack';
      case 'BENIGN':
        return 'chip-benign';
      default:
        return 'chip-unknown';
    }
  }
}
