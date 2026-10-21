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
      gap: 16px;
      padding: 16px 20px;
      background: rgba(245, 158, 11, 0.08);
      border: 1px solid rgba(245, 158, 11, 0.35);
      border-radius: 8px;
      margin-bottom: 20px;
    }

    .alert-icon-col {
      display: flex;
      align-items: flex-start;
      padding-top: 2px;
      .alert-icon {
        font-size: 28px;
        color: #FBBF24;
      }
    }

    .alert-content-col {
      flex: 1 1 auto;
      display: flex;
      flex-direction: column;
      gap: 6px;
    }

    .alert-title-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }

    .alert-title {
      font-size: 14px;
      font-weight: 700;
      color: #FBBF24;
      letter-spacing: -0.2px;
    }

    .coverage-pill {
      font-size: 11px;
      font-weight: 700;
      background: rgba(245, 158, 11, 0.2);
      color: #FDE68A;
      border: 1px solid rgba(245, 158, 11, 0.4);
      padding: 2px 8px;
      border-radius: 12px;
    }

    .alert-message {
      font-size: 13px;
      color: #D1D5DB;
      margin: 0;
      line-height: 1.5;
    }

    .diagnostic-indicator {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      margin-top: 6px;
      padding: 6px 12px;
      background: rgba(17, 24, 39, 0.6);
      border: 1px dashed rgba(245, 158, 11, 0.4);
      border-radius: 6px;
    }

    .diagnostic-tag {
      font-size: 11px;
      font-weight: 700;
      color: #F59E0B;
      letter-spacing: 0.5px;
    }

    .diagnostic-val {
      font-size: 13px;
      font-weight: 600;
      color: #F3F4F6;
    }

    .confirmed-alert-container {
      display: flex;
      align-items: center;
      gap: 14px;
      padding: 12px 18px;
      background: rgba(16, 185, 129, 0.08);
      border: 1px solid rgba(16, 185, 129, 0.3);
      border-radius: 8px;
      margin-bottom: 20px;
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
