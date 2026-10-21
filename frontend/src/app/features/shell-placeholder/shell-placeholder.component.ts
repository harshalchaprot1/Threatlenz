import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
import { environment } from '../../../environments/environment';

@Component({
  selector: 'app-shell-placeholder',
  standalone: true,
  imports: [CommonModule, MatCardModule, MatIconModule],
  template: `
    <div class="placeholder-container">
      <div class="welcome-card">
        <div class="card-header-icon">
          <span class="material-symbols-outlined icon-glow">shield_locked</span>
        </div>
        <h2>ThreatLenz Intelligence Console</h2>
        <p class="subtitle">
          Trustworthy Big Data-Based Threat Analytics &amp; Risk Intelligence
        </p>

        <div class="status-grid">
          <div class="status-box">
            <span class="status-label">Angular Platform</span>
            <span class="status-val">v18.2 (Standalone)</span>
          </div>
          <div class="status-box">
            <span class="status-label">Design System</span>
            <span class="status-val">Angular Material Dark Cyber</span>
          </div>
          <div class="status-box">
            <span class="status-label">FastAPI Backend</span>
            <span class="status-val">{{ apiUrl }}</span>
          </div>
          <div class="status-box">
            <span class="status-label">Evidence Safeguard</span>
            <span class="status-val">Withholding Active</span>
          </div>
        </div>

        <div class="next-step-box">
          <span class="material-symbols-outlined" style="color: var(--tl-cyan);">info</span>
          <span>Phase 2, Step 1 Scaffolding Verified. Ready for Step 2 (Core Data Layer &amp; Reusable Widgets).</span>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .placeholder-container {
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 60vh;
    }

    .welcome-card {
      background: var(--tl-bg-surface);
      border: 1px solid var(--tl-border);
      border-radius: 12px;
      padding: 40px;
      max-width: 650px;
      width: 100%;
      text-align: center;
      box-shadow: 0 10px 25px rgba(0, 0, 0, 0.4);
    }

    .card-header-icon {
      margin-bottom: 16px;
      .icon-glow {
        font-size: 48px;
        color: var(--tl-cyan);
        filter: drop-shadow(0 0 12px rgba(6, 182, 212, 0.5));
      }
    }

    h2 {
      margin: 0 0 8px 0;
      color: var(--tl-text-primary);
      font-size: 22px;
      font-weight: 700;
    }

    .subtitle {
      color: var(--tl-text-secondary);
      font-size: 14px;
      margin: 0 0 28px 0;
    }

    .status-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 12px;
      margin-bottom: 24px;
      text-align: left;
    }

    .status-box {
      background: var(--tl-bg-card);
      border: 1px solid var(--tl-border);
      border-radius: 8px;
      padding: 12px 16px;
      display: flex;
      flex-direction: column;
      gap: 4px;
    }

    .status-label {
      font-size: 11px;
      color: var(--tl-text-muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .status-val {
      font-size: 13px;
      color: var(--tl-text-primary);
      font-weight: 600;
    }

    .next-step-box {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 12px 16px;
      background: rgba(6, 182, 212, 0.08);
      border: 1px solid rgba(6, 182, 212, 0.25);
      border-radius: 8px;
      font-size: 12px;
      color: var(--tl-text-secondary);
      text-align: left;
    }
  `],
})
export class ShellPlaceholderComponent {
  readonly apiUrl = environment.apiUrl;
}
