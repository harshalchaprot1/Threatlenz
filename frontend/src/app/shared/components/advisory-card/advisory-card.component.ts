import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { AdvisoryResponse } from '../../../core/models';

@Component({
  selector: 'app-advisory-card',
  standalone: true,
  imports: [CommonModule],
  template: `
    @if (advisory) {
      <div class="advisory-card" [ngClass]="getCardPriorityClass()">
        <div class="advisory-header">
          <div class="badge-row">
            <span class="priority-chip" [ngClass]="getPriorityChipClass()">
              {{ advisory.priority }} PRIORITY
            </span>
            <span class="action-chip">{{ advisory.action_type }}</span>
            <span class="rec-id">{{ advisory.recommendation_id }}</span>
          </div>
          <div class="governance-indicator" title="ThreatLenz Governance Enforced">
            <span class="material-symbols-outlined gov-icon">gavel</span>
            <span class="gov-text">Analyst Sign-off Required</span>
          </div>
        </div>

        <h3 class="advisory-summary">{{ advisory.summary }}</h3>
        <p class="advisory-guidance">{{ advisory.detailed_guidance }}</p>

        @if (advisory.missing_evidence_required && advisory.missing_evidence_required.length > 0) {
          <div class="telemetry-block">
            <span class="telemetry-title">Required Telemetry for Verification:</span>
            <ul class="telemetry-list">
              @for (item of advisory.missing_evidence_required; track item) {
                <li>
                  <span class="material-symbols-outlined list-icon">arrow_right</span>
                  <span>{{ item }}</span>
                </li>
              }
            </ul>
          </div>
        }

        <div class="advisory-footer">
          <div class="safety-clause">
            <span class="material-symbols-outlined lock-icon">shield_lock</span>
            <span>Non-Destructive: Automated firewall blocks prohibited without human authorization.</span>
          </div>
          <span class="category-tag">{{ advisory.threat_category }}</span>
        </div>
      </div>
    }
  `,
  styles: [`
    .advisory-card {
      background: var(--tl-bg-surface);
      border: 1px solid var(--tl-border);
      border-radius: 8px;
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 12px;
      transition: border-color 0.2s ease;

      &:hover {
        border-color: rgba(255, 255, 255, 0.15);
      }
    }

    .advisory-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 10px;
    }

    .badge-row {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }

    .priority-chip {
      font-size: 11px;
      font-weight: 700;
      padding: 3px 8px;
      border-radius: 4px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .priority-critical {
      background: rgba(239, 68, 68, 0.2);
      color: #EF4444;
      border: 1px solid rgba(239, 68, 68, 0.4);
    }

    .priority-high {
      background: rgba(249, 115, 22, 0.2);
      color: #F97316;
      border: 1px solid rgba(249, 115, 22, 0.4);
    }

    .priority-medium {
      background: rgba(245, 158, 11, 0.2);
      color: #F59E0B;
      border: 1px solid rgba(245, 158, 11, 0.4);
    }

    .priority-low {
      background: rgba(59, 130, 246, 0.2);
      color: #60A5FA;
      border: 1px solid rgba(59, 130, 246, 0.4);
    }

    .action-chip {
      background: var(--tl-bg-card);
      color: var(--tl-cyan);
      border: 1px solid var(--tl-border);
      font-size: 11px;
      font-weight: 600;
      padding: 3px 8px;
      border-radius: 4px;
    }

    .rec-id {
      font-size: 11px;
      color: var(--tl-text-muted);
      font-family: monospace;
    }

    .governance-indicator {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      color: #FBBF24;
      font-size: 11px;
      font-weight: 600;
      background: rgba(245, 158, 11, 0.1);
      padding: 2px 8px;
      border-radius: 4px;
      border: 1px solid rgba(245, 158, 11, 0.25);

      .gov-icon {
        font-size: 14px;
      }
    }

    .advisory-summary {
      margin: 0;
      font-size: 15px;
      font-weight: 600;
      color: var(--tl-text-primary);
      line-height: 1.4;
    }

    .advisory-guidance {
      margin: 0;
      font-size: 13px;
      color: var(--tl-text-secondary);
      line-height: 1.6;
    }

    .telemetry-block {
      background: var(--tl-bg-base);
      border: 1px solid var(--tl-border);
      border-radius: 6px;
      padding: 10px 14px;
    }

    .telemetry-title {
      font-size: 11px;
      font-weight: 700;
      color: var(--tl-text-muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
      display: block;
      margin-bottom: 6px;
    }

    .telemetry-list {
      margin: 0;
      padding: 0;
      list-style: none;
      display: flex;
      flex-direction: column;
      gap: 4px;

      li {
        display: flex;
        align-items: center;
        gap: 6px;
        font-size: 12px;
        color: #D1D5DB;

        .list-icon {
          font-size: 16px;
          color: var(--tl-cyan);
        }
      }
    }

    .advisory-footer {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 10px;
      padding-top: 10px;
      border-top: 1px solid var(--tl-border);
    }

    .safety-clause {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 11px;
      color: var(--tl-text-muted);

      .lock-icon {
        font-size: 15px;
        color: var(--tl-emerald);
      }
    }

    .category-tag {
      font-size: 11px;
      font-weight: 600;
      color: var(--tl-text-secondary);
    }
  `],
})
export class AdvisoryCardComponent {
  @Input() advisory?: AdvisoryResponse;

  getPriorityChipClass(): string {
    switch (this.advisory?.priority?.toUpperCase()) {
      case 'CRITICAL':
        return 'priority-critical';
      case 'HIGH':
        return 'priority-high';
      case 'MEDIUM':
        return 'priority-medium';
      default:
        return 'priority-low';
    }
  }

  getCardPriorityClass(): string {
    return 'priority-border-' + (this.advisory?.priority?.toLowerCase() || 'low');
  }
}
