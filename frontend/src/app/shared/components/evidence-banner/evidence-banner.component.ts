import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-evidence-banner',
  standalone: true,
  imports: [CommonModule],
  template: `
    @if (!isConfirmed) {
      <div class="evidence-panel" role="region" aria-label="Operational Risk Governance Policy">
        <div class="panel-icon-col">
          <span class="material-symbols-outlined panel-icon">verified_user</span>
        </div>
        <div class="panel-content-col">
          <div class="panel-title-row">
            <span class="panel-title">Operational Risk Assessment: Not Rated</span>
            <span class="coverage-tag">
              Evidence Coverage: {{ (evidenceCoverage * 100).toFixed(0) }}%
            </span>
          </div>

          <p class="panel-message">
            Host destination asset criticality telemetry (Target Impact) is absent in this Netflow observation window.
            In compliance with ThreatLenz Governance Policy, <strong>the overall operational risk rating is not assigned</strong> pending full telemetry.
          </p>
        </div>
      </div>
    } @else {
      <div class="confirmed-panel" role="region" aria-label="Operational Risk Assessment Confirmed">
        <div class="panel-icon-col">
          <span class="material-symbols-outlined confirmed-icon">verified_user</span>
        </div>
        <div class="panel-content-col">
          <div class="panel-title-row">
            <span class="confirmed-title">Confirmed Operational Evidence</span>
            <span class="confirmed-tag">100% Coverage</span>
          </div>
          <p class="confirmed-message">
            All 4 TLRS telemetry factors (Severity, Frequency, Recurrence, and Target Impact) are fully observed and rated.
          </p>
        </div>
      </div>
    }
  `,
  styles: [`
    .evidence-panel {
      display: flex;
      align-items: flex-start;
      gap: 14px;
      padding: 12px 16px;
      background: var(--tl-bg-surface, #1E293B);
      border: 1px solid var(--tl-border, rgba(255, 255, 255, 0.08));
      border-left: 3px solid var(--tl-cyan, #06B6D4);
      border-radius: 6px;
    }

    .panel-icon-col {
      display: flex;
      align-items: center;
      padding-top: 1px;

      .panel-icon {
        font-size: 20px;
        color: var(--tl-cyan, #06B6D4);
      }
    }

    .panel-content-col {
      flex: 1 1 auto;
      display: flex;
      flex-direction: column;
      gap: 4px;
    }

    .panel-title-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }

    .panel-title {
      font-size: 13px;
      font-weight: 700;
      color: var(--tl-text-primary, #F8FAFC);
      letter-spacing: -0.1px;
    }

    .coverage-tag {
      font-size: 11px;
      font-weight: 600;
      background: rgba(255, 255, 255, 0.04);
      color: var(--tl-text-secondary, #94A3B8);
      border: 1px solid var(--tl-border, rgba(255, 255, 255, 0.08));
      padding: 2px 8px;
      border-radius: 4px;
      letter-spacing: 0.2px;
    }

    .panel-message {
      font-size: 12px;
      color: var(--tl-text-secondary, #94A3B8);
      margin: 0;
      line-height: 1.5;

      strong {
        color: var(--tl-text-primary, #F8FAFC);
        font-weight: 600;
      }
    }

    .confirmed-panel {
      display: flex;
      align-items: flex-start;
      gap: 14px;
      padding: 12px 16px;
      background: var(--tl-bg-surface, #1E293B);
      border: 1px solid var(--tl-border, rgba(255, 255, 255, 0.08));
      border-left: 3px solid #10B981;
      border-radius: 6px;
    }

    .confirmed-icon {
      font-size: 20px;
      color: #10B981;
    }

    .confirmed-title {
      font-size: 13px;
      font-weight: 700;
      color: var(--tl-text-primary, #F8FAFC);
    }

    .confirmed-tag {
      font-size: 11px;
      font-weight: 600;
      background: rgba(16, 185, 129, 0.1);
      color: #34D399;
      border: 1px solid rgba(16, 185, 129, 0.25);
      padding: 2px 8px;
      border-radius: 4px;
    }

    .confirmed-message {
      font-size: 12px;
      color: var(--tl-text-secondary, #94A3B8);
      margin: 0;
      line-height: 1.5;
    }
  `],
})
export class EvidenceBannerComponent {
  @Input() isConfirmed: boolean = false;
  @Input() evidenceCoverage: number = 0.85;
  @Input() provisionalRiskBand?: string | null = null;
}
