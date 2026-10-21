import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-stat-card',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="stat-card">
      <div class="stat-header">
        <span class="stat-title">{{ title }}</span>
        @if (icon) {
          <div class="stat-icon-wrapper">
            <span class="material-symbols-outlined stat-icon">{{ icon }}</span>
          </div>
        }
      </div>

      <div class="stat-body">
        <span class="stat-value">{{ value }}</span>
        @if (badgeText) {
          <span class="stat-badge" [ngClass]="'badge-' + (badgeType || 'default')">
            {{ badgeText }}
          </span>
        }
      </div>

      @if (subtitle) {
        <div class="stat-footer">
          <span class="stat-subtitle">{{ subtitle }}</span>
        </div>
      }
    </div>
  `,
  styles: [`
    .stat-card {
      background: var(--tl-bg-surface);
      border: 1px solid var(--tl-border);
      border-radius: 8px;
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 8px;
      transition: transform 0.2s ease, border-color 0.2s ease;

      &:hover {
        border-color: rgba(255, 255, 255, 0.15);
      }
    }

    .stat-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .stat-title {
      font-size: 12px;
      font-weight: 600;
      color: var(--tl-text-muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .stat-icon-wrapper {
      display: flex;
      align-items: center;
      justify-content: center;
      width: 32px;
      height: 32px;
      border-radius: 6px;
      background: rgba(6, 182, 212, 0.1);
      border: 1px solid rgba(6, 182, 212, 0.2);

      .stat-icon {
        font-size: 18px;
        color: var(--tl-cyan);
      }
    }

    .stat-body {
      display: flex;
      align-items: baseline;
      gap: 10px;
      flex-wrap: wrap;
    }

    .stat-value {
      font-size: 26px;
      font-weight: 700;
      color: var(--tl-text-primary);
      letter-spacing: -0.5px;
      font-variant-numeric: tabular-nums;
    }

    .stat-badge {
      font-size: 11px;
      font-weight: 600;
      padding: 2px 6px;
      border-radius: 4px;
    }

    .badge-default {
      background: var(--tl-bg-card);
      color: var(--tl-text-secondary);
    }

    .badge-success {
      background: rgba(16, 185, 129, 0.15);
      color: #34D399;
      border: 1px solid rgba(16, 185, 129, 0.3);
    }

    .badge-warning {
      background: rgba(245, 158, 11, 0.15);
      color: #FBBF24;
      border: 1px solid rgba(245, 158, 11, 0.3);
    }

    .badge-danger {
      background: rgba(239, 68, 68, 0.15);
      color: #F87171;
      border: 1px solid rgba(239, 68, 68, 0.3);
    }

    .badge-info {
      background: rgba(59, 130, 246, 0.15);
      color: #60A5FA;
      border: 1px solid rgba(59, 130, 246, 0.3);
    }

    .stat-footer {
      margin-top: 4px;
    }

    .stat-subtitle {
      font-size: 12px;
      color: var(--tl-text-secondary);
      line-height: 1.4;
    }
  `],
})
export class StatCardComponent {
  @Input() title: string = '';
  @Input() value: string | number | null | undefined = '';
  @Input() subtitle?: string;
  @Input() icon?: string;
  @Input() badgeText?: string;
  @Input() badgeType?: 'default' | 'success' | 'warning' | 'danger' | 'info' = 'default';
}
