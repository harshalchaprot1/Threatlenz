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
      border-radius: 6px;
      padding: 14px 18px;
      display: flex;
      flex-direction: column;
      gap: 6px;
      transition: border-color 0.15s ease;

      &:hover {
        border-color: rgba(255, 255, 255, 0.12);
      }
    }

    .stat-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .stat-title {
      font-size: 11px;
      font-weight: 600;
      color: var(--tl-text-muted);
      text-transform: uppercase;
      letter-spacing: 0.6px;
    }

    .stat-icon-wrapper {
      display: flex;
      align-items: center;
      justify-content: center;
      width: 28px;
      height: 28px;
      border-radius: 4px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid rgba(255, 255, 255, 0.06);

      .stat-icon {
        font-size: 16px;
        color: var(--tl-text-muted);
      }
    }

    .stat-body {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 8px;
      flex-wrap: wrap;
    }

    .stat-value {
      font-size: 24px;
      font-weight: 700;
      color: var(--tl-text-primary);
      letter-spacing: -0.5px;
      font-variant-numeric: tabular-nums;
      line-height: 1.1;
    }

    .stat-badge {
      font-size: 10px;
      font-weight: 600;
      padding: 2px 6px;
      border-radius: 3px;
      letter-spacing: 0.3px;
    }

    .badge-default {
      background: rgba(255, 255, 255, 0.05);
      color: var(--tl-text-secondary);
    }

    .badge-success {
      background: rgba(16, 185, 129, 0.1);
      color: #10B981;
      border: 1px solid rgba(16, 185, 129, 0.25);
    }

    .badge-warning {
      background: rgba(245, 158, 11, 0.1);
      color: #F59E0B;
      border: 1px solid rgba(245, 158, 11, 0.25);
    }

    .badge-danger {
      background: rgba(239, 68, 68, 0.1);
      color: #EF4444;
      border: 1px solid rgba(239, 68, 68, 0.25);
    }

    .badge-info {
      background: rgba(6, 182, 212, 0.1);
      color: #06B6D4;
      border: 1px solid rgba(6, 182, 212, 0.25);
    }

    .stat-footer {
      margin-top: 2px;
    }

    .stat-subtitle {
      font-size: 11px;
      color: var(--tl-text-muted);
      line-height: 1.3;
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
