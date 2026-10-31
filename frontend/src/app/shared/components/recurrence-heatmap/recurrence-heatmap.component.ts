import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ThreatProfileSummary } from '../../../core/models';

interface RecurrenceItem {
  label: string;
  activeUnits: number;
  totalUnits: number;
  ratio: number;
  ratioPct: number;
  isAttack: boolean;
  statusBadge: string;
}

@Component({
  selector: 'app-recurrence-heatmap',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="recurrence-card">
      <div class="recurrence-header">
        <div class="recurrence-title-group">
          <span class="recurrence-title">{{ title }}</span>
          <span class="recurrence-subtitle">{{ subtitle }}</span>
        </div>
        <div class="horizon-badge">
          <span class="material-symbols-outlined horizon-icon">date_range</span>
          <span>Observation Horizon: H={{ observationHorizon }} Days</span>
        </div>
      </div>

      <div class="recurrence-grid">
        @for (item of items; track item.label) {
          <div class="recurrence-item">
            <div class="item-header">
              <span class="item-name" [title]="item.label">{{ item.label }}</span>
              <span class="unit-count">{{ item.activeUnits }} / {{ item.totalUnits }} d</span>
            </div>

            <!-- Heat blocks for H observation days -->
            <div class="blocks-row">
              @for (dayIndex of dayIndices; track dayIndex) {
                <div
                  class="day-block"
                  [ngClass]="{
                    'block-active-attack': dayIndex < item.activeUnits && item.isAttack,
                    'block-active-benign': dayIndex < item.activeUnits && !item.isAttack,
                    'block-inactive': dayIndex >= item.activeUnits
                  }"
                  [title]="'Observed in ' + item.activeUnits + ' of ' + item.totalUnits + ' campaign days'"
                ></div>
              }
            </div>

            <div class="item-footer">
              <span class="recurrence-pct">{{ item.ratioPct.toFixed(1) }}% Persistence</span>
              <span class="persistence-label" [ngClass]="getPersistenceClass(item.ratio)">
                {{ getPersistenceLabel(item.ratio) }}
              </span>
            </div>
          </div>
        }
      </div>

      <div class="recurrence-footer">
        <span class="footer-note">
          <span class="material-symbols-outlined note-icon">schedule</span>
          Recurrence ratio feeds directly into TLRS risk assessment formula: R = d / H (where H=8 observed campaign days).
        </span>
      </div>
    </div>
  `,
  styles: [`
    .recurrence-card {
      background: var(--tl-bg-surface);
      border: 1px solid var(--tl-border);
      border-radius: 8px;
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .recurrence-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
      padding-bottom: 12px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.06);
    }

    .recurrence-title-group {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }

    .recurrence-title {
      font-size: 14px;
      font-weight: 600;
      color: var(--tl-text-primary);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .recurrence-subtitle {
      font-size: 12px;
      color: var(--tl-text-secondary);
    }

    .horizon-badge {
      display: flex;
      align-items: center;
      gap: 6px;
      background: rgba(6, 182, 212, 0.08);
      border: 1px solid rgba(6, 182, 212, 0.25);
      color: var(--tl-accent-cyan, #06B6D4);
      padding: 4px 10px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;

      .horizon-icon {
        font-size: 14px;
      }
    }

    .recurrence-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
      gap: 12px;
    }

    .recurrence-item {
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid rgba(255, 255, 255, 0.04);
      border-radius: 6px;
      padding: 12px;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .item-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
    }

    .item-name {
      font-size: 12px;
      font-weight: 600;
      color: var(--tl-text-primary);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .unit-count {
      font-size: 11px;
      font-family: monospace;
      color: var(--tl-text-secondary);
    }

    .blocks-row {
      display: grid;
      grid-template-columns: repeat(8, 1fr);
      gap: 4px;
      height: 10px;
    }

    .day-block {
      border-radius: 2px;
      height: 100%;

      &.block-active-attack {
        background: var(--tl-crimson, #EF4444);
        box-shadow: 0 0 4px rgba(239, 68, 68, 0.4);
      }

      &.block-active-benign {
        background: var(--tl-emerald, #10B981);
        box-shadow: 0 0 4px rgba(16, 185, 129, 0.4);
      }

      &.block-inactive {
        background: rgba(255, 255, 255, 0.06);
      }
    }

    .item-footer {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 6px;
      font-size: 11px;
    }

    .recurrence-pct {
      color: var(--tl-text-muted);
    }

    .persistence-label {
      font-weight: 600;
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.3px;

      &.p-continuous {
        color: var(--tl-emerald, #10B981);
      }

      &.p-frequent {
        color: var(--tl-amber, #F59E0B);
      }

      &.p-intermittent {
        color: var(--tl-accent-cyan, #06B6D4);
      }

      &.p-single {
        color: var(--tl-text-muted);
      }
    }

    .recurrence-footer {
      padding-top: 10px;
      border-top: 1px solid rgba(255, 255, 255, 0.04);
    }

    .footer-note {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 11px;
      color: var(--tl-text-muted);

      .note-icon {
        font-size: 14px;
        color: var(--tl-accent-cyan, #06B6D4);
      }
    }
  `],
})
export class RecurrenceHeatmapComponent {
  @Input() title: string = 'Campaign Temporal Recurrence & Persistence';
  @Input() subtitle: string = 'Active observation units across the 8-day CSE-CIC-IDS2018 campaign calendar';
  @Input() set profiles(data: ThreatProfileSummary[]) {
    this._profiles = data || [];
    this.recompute();
  }

  private _profiles: ThreatProfileSummary[] = [];
  items: RecurrenceItem[] = [];
  observationHorizon: number = 8;
  dayIndices: number[] = [0, 1, 2, 3, 4, 5, 6, 7];

  getPersistenceLabel(ratio: number): string {
    if (ratio >= 0.8) return 'Continuous';
    if (ratio >= 0.5) return 'Frequent';
    if (ratio >= 0.25) return 'Intermittent';
    return 'Sparse';
  }

  getPersistenceClass(ratio: number): string {
    if (ratio >= 0.8) return 'p-continuous';
    if (ratio >= 0.5) return 'p-frequent';
    if (ratio >= 0.25) return 'p-intermittent';
    return 'p-single';
  }

  private recompute(): void {
    if (!this._profiles || this._profiles.length === 0) {
      this.items = [];
      return;
    }

    this.observationHorizon = this._profiles[0]?.recurrence_denominator || 8;
    this.dayIndices = Array.from({ length: this.observationHorizon }, (_, i) => i);

    // Sort: attacks first, descending active observation units
    const sorted = [...this._profiles].sort((a, b) => {
      if (a.attack_status !== b.attack_status) {
        return a.attack_status === 'ATTACK' ? -1 : 1;
      }
      return (b.active_observation_units || 0) - (a.active_observation_units || 0);
    });

    this.items = sorted.map((p) => {
      const units = p.active_observation_units || 0;
      const denom = p.recurrence_denominator || this.observationHorizon;
      const ratio = p.recurrence_ratio !== undefined ? p.recurrence_ratio : denom > 0 ? units / denom : 0;

      return {
        label: p.canonical_label,
        activeUnits: units,
        totalUnits: denom,
        ratio: ratio,
        ratioPct: ratio * 100,
        isAttack: p.attack_status === 'ATTACK',
        statusBadge: p.attack_status,
      };
    });
  }
}
