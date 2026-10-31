import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-evidence-banner',
  standalone: true,
  imports: [CommonModule],
  template: `
    @if (!isConfirmed) {
      <div class="evidence-alert-container" role="alert" aria-live="polite">
        <div class="alert-icon-col">
          <span class="material-symbols-outlined alert-icon">policy</span>
        </div>
        <div class="alert-content-col">
          <div class="alert-title-row">
            <span class="alert-title">Operational Risk Score Withheld (Evidence Safeguard)</span>
            <span class="coverage-pill">
              {{ (evidenceCoverage * 100).toFixed(1) }}% Evidence Coverage
            </span>
          </div>

          <p class="alert-message">
            Host-level destination asset criticality (Target Impact telemetry) is absent in this Netflow capture.
            Under ThreatLenz Governance Policy, <strong>the operational TLRS rating is strictly withheld as "Insufficient Evidence"</strong>.
            Any computed heuristic is strictly diagnostic.
          </p>

          @if (provisionalRiskBand) {
            <div class="diagnostic-indicator">
              <span class="diagnostic-tag">DIAGNOSTIC ONLY — NON-OPERATIONAL:</span>
              <span class="diagnostic-val">{{ provisionalRiskBand }}</span>
            </div>
          }
        </div>
      </div>
    } @else {
      <div class="confirmed-alert-container">
        <span class="material-symbols-outlined confirmed-icon">verified_user</span>
        <div class="confirmed-text">
          <span class="confirmed-title">Confirmed Operational Evidence</span>
          <span class="confirmed-sub">All 4 TLRS telemetry factors (Severity, Frequency, Recurrence, Target Impact) fully observed.</span>
        </div>
      </div>
    }
  `,
  styles: [`
    .evidence-alert-container {
      display: flex;
      gap: 14px;
      padding: 12px 16px;
      background: rgba(245, 158, 11, 0.05);
      border: 1px solid rgba(245, 158, 11, 0.25);
      border-radius: 6px;
      margin-bottom: 0;
    }

    .alert-icon-col {
      display: flex;
      align-items: flex-start;
      padding-top: 1px;
      .alert-icon {
        font-size: 22px;
        color: #F59E0B;
      }
    }

    .alert-content-col {
      flex: 1 1 auto;
      display: flex;
      flex-direction: column;
      gap: 4px;
    }

    .alert-title-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }

    .alert-title {
      font-size: 13px;
      font-weight: 700;
      color: #F59E0B;
      letter-spacing: -0.1px;
    }

    .coverage-pill {
      font-size: 10px;
      font-weight: 700;
      background: rgba(245, 158, 11, 0.15);
      color: #FDE68A;
      border: 1px solid rgba(245, 158, 11, 0.3);
      padding: 1px 7px;
      border-radius: 4px;
      letter-spacing: 0.3px;
    }

    .alert-message {
      font-size: 12px;
      color: #94A3B8;
      margin: 0;
      line-height: 1.45;

      strong {
        color: #E2E8F0;
      }
    }

    .diagnostic-indicator {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      margin-top: 2px;
      padding: 3px 8px;
      background: rgba(0, 0, 0, 0.3);
      border: 1px solid rgba(245, 158, 11, 0.25);
      border-radius: 4px;
      width: fit-content;
    }

    .diagnostic-tag {
      font-size: 10px;
      font-weight: 700;
      color: #F59E0B;
      letter-spacing: 0.5px;
    }

    .diagnostic-val {
      font-size: 11px;
      font-weight: 600;
      color: #CBD5E1;
      font-family: monospace;
    }

    .confirmed-alert-container {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 10px 16px;
      background: rgba(16, 185, 129, 0.05);
      border: 1px solid rgba(16, 185, 129, 0.25);
      border-radius: 6px;
      margin-bottom: 0;
    }

    .confirmed-icon {
      font-size: 24px;
      color: #34D399;
    }

    .confirmed-text {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }

    .confirmed-title {
      font-size: 13px;
      font-weight: 700;
      color: #34D399;
    }

    .confirmed-sub {
      font-size: 12px;
      color: #9CA3AF;
    }
  `],
})
export class EvidenceBannerComponent {
  @Input() isConfirmed: boolean = false;
  @Input() evidenceCoverage: number = 0.85;
  @Input() provisionalRiskBand?: string | null = null;
}
