import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSelectModule } from '@angular/material/select';
import { DestinationPortAnalyticsResponse, CategoryPortAnalysis, PortConcentrationItem } from '../../../core/models';

@Component({
  selector: 'app-port-concentration-card',
  standalone: true,
  imports: [CommonModule, FormsModule, MatFormFieldModule, MatSelectModule],
  template: `
    <div class="port-card">
      <div class="card-header">
        <div class="header-left">
          <span class="card-title">{{ title }}</span>
          <span class="card-subtitle">{{ subtitle }}</span>
        </div>

        <!-- Category Selector Dropdown -->
        @if (categoriesList.length > 0) {
          <div class="selector-wrapper">
            <mat-form-field appearance="outline" class="category-select">
              <mat-label>Threat Category</mat-label>
              <mat-select [(ngModel)]="selectedCategoryKey" (selectionChange)="onCategoryChange()">
                @for (cat of categoriesList; track cat) {
                  <mat-option [value]="cat">{{ cat }}</mat-option>
                }
              </mat-select>
            </mat-form-field>
          </div>
        }
      </div>

      @if (loading) {
        <div class="state-box">
          <span class="state-label">Loading port concentration analytics...</span>
        </div>
      } @else if (errorMessage) {
        <div class="state-box error">
          <span class="material-symbols-outlined error-icon">warning</span>
          <span class="state-label">{{ errorMessage }}</span>
        </div>
      } @else if (!activeCategory) {
        <div class="state-box">
          <span class="state-label">No port concentration data available.</span>
        </div>
      } @else {
        <div class="card-content">
          <!-- Summary Metrics Strip -->
          <div class="summary-strip">
            <div class="strip-item">
              <span class="strip-label">Selected Category</span>
              <span class="strip-val">{{ activeCategory.class_name }}</span>
            </div>
            <div class="strip-item">
              <span class="strip-label">Total Category Flows</span>
              <span class="strip-val font-mono">{{ activeCategory.total_flows | number }}</span>
            </div>
            <div class="strip-item">
              <span class="strip-label">Top 1 Port Concentration</span>
              <span class="strip-val font-mono" [ngClass]="activeCategory.has_extreme_port_concentration ? 'text-amber' : 'text-cyan'">
                {{ activeCategory.concentration_top_1_port_pct.toFixed(1) }}%
              </span>
            </div>
            <div class="strip-item">
              <span class="strip-label">Top 3 Ports Concentration</span>
              <span class="strip-val font-mono">
                {{ activeCategory.concentration_top_3_ports_pct.toFixed(1) }}%
              </span>
            </div>
          </div>

          <!-- Port Concentration Horizontal Breakdown -->
          <div class="ports-list">
            @for (portItem of activeCategory.top_ports; track portItem.port) {
              <div class="port-row">
                <div class="port-identity">
                  <div class="port-badge">
                    <span class="port-num font-mono">Port {{ portItem.port }}</span>
                  </div>
                  <div class="port-service-group">
                    <span class="port-service">{{ portItem.service_name }}</span>
                    <span class="port-criticality">Asset Criticality Weight: {{ portItem.criticality_weight }}</span>
                  </div>
                </div>

                <div class="port-bar-track">
                  <div
                    class="port-bar-fill"
                    [style.width.%]="Math.min(portItem.percentage_within_class, 100)"
                  ></div>
                </div>

                <div class="port-metrics">
                  <span class="port-count font-mono">{{ portItem.flow_count | number }}</span>
                  <span class="port-pct font-mono">{{ portItem.percentage_within_class.toFixed(1) }}%</span>
                </div>
              </div>
            }
          </div>

          <div class="card-footer">
            <span class="footer-note">
              <span class="material-symbols-outlined note-icon">share</span>
              Shows destination port concentration within the selected threat category. Distinguishes protocol service targeting from overall attack frequency.
            </span>
          </div>
        </div>
      }
    </div>
  `,
  styles: [`
    .port-card {
      background: var(--tl-bg-surface);
      border: 1px solid var(--tl-border);
      border-radius: 6px;
      padding: 18px 20px;
      display: flex;
      flex-direction: column;
      gap: 14px;
      height: 100%;
      box-sizing: border-box;
    }

    .card-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
      padding-bottom: 10px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    }

    .header-left {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }

    .card-title {
      font-size: 13px;
      font-weight: 700;
      color: var(--tl-text-primary);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .card-subtitle {
      font-size: 11px;
      color: var(--tl-text-muted);
    }

    .selector-wrapper {
      min-width: 190px;
      display: flex;
      align-items: center;

      .category-select {
        width: 100%;
        margin-bottom: -1.25em; /* Compensate for Angular Material form-field baseline spacing */
      }

      ::ng-deep .mat-mdc-form-field-subscript-wrapper {
        display: none;
      }

      ::ng-deep .mat-mdc-text-field-wrapper {
        padding: 0 12px;
        background: rgba(255, 255, 255, 0.04);
        border-radius: 4px;
        height: 36px;
        display: flex;
        align-items: center;
      }

      ::ng-deep .mat-mdc-form-field-flex {
        align-items: center;
        height: 36px;
      }

      ::ng-deep .mat-mdc-form-field-infix {
        padding-top: 6px !important;
        padding-bottom: 6px !important;
        min-height: unset;
      }

      ::ng-deep .mat-mdc-select {
        display: flex;
        align-items: center;
      }

      ::ng-deep .mat-mdc-select-trigger {
        display: flex;
        align-items: center;
        height: 100%;
      }

      ::ng-deep .mat-mdc-select-value {
        font-size: 12px;
        font-weight: 500;
        color: var(--tl-text-primary);
        line-height: normal;
      }

      ::ng-deep .mat-mdc-select-arrow-wrapper {
        transform: translateY(0);
        display: flex;
        align-items: center;
      }

      ::ng-deep .mat-mdc-floating-label {
        top: 18px !important;
        font-size: 11px;
      }
    }

    .state-box {
      min-height: 220px;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      color: var(--tl-text-muted);
      font-size: 12px;

      &.error {
        color: #EF4444;
      }
    }

    .card-content {
      display: flex;
      flex-direction: column;
      gap: 14px;
      flex: 1;
    }

    .summary-strip {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
      gap: 8px;
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid rgba(255, 255, 255, 0.04);
      border-radius: 4px;
      padding: 8px 12px;
    }

    .strip-item {
      display: flex;
      flex-direction: column;
      gap: 1px;
    }

    .strip-label {
      font-size: 9px;
      text-transform: uppercase;
      color: var(--tl-text-muted);
      letter-spacing: 0.4px;
      font-weight: 600;
    }

    .strip-val {
      font-size: 12px;
      font-weight: 600;
      color: var(--tl-text-primary);

      &.text-cyan {
        color: var(--tl-cyan, #06B6D4);
      }

      &.text-amber {
        color: #F59E0B;
      }
    }

    .ports-list {
      display: flex;
      flex-direction: column;
      gap: 8px;
      flex: 1;
    }

    .port-row {
      display: grid;
      grid-template-columns: 220px 1fr 100px;
      align-items: center;
      gap: 14px;
      padding: 6px 10px;
      background: rgba(255, 255, 255, 0.015);
      border-radius: 4px;
      border: 1px solid rgba(255, 255, 255, 0.03);

      @media (max-width: 768px) {
        grid-template-columns: 150px 1fr 80px;
        gap: 8px;
      }
    }

    .port-identity {
      display: flex;
      align-items: center;
      gap: 8px;
      overflow: hidden;
    }

    .port-badge {
      font-size: 10px;
      font-weight: 700;
      background: rgba(6, 182, 212, 0.12);
      color: var(--tl-cyan, #06B6D4);
      border: 1px solid rgba(6, 182, 212, 0.25);
      padding: 2px 6px;
      border-radius: 3px;
      flex-shrink: 0;
    }

    .port-service {
      font-size: 11px;
      color: var(--tl-text-secondary);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .port-track-col {
      width: 100%;
    }

    .port-track {
      width: 100%;
      height: 8px;
      background: rgba(255, 255, 255, 0.04);
      border-radius: 4px;
      overflow: hidden;
    }

    .port-fill {
      height: 100%;
      border-radius: 4px;
      background: #0284C7;
      transition: width 0.3s ease;
    }

    .port-metrics-col {
      display: flex;
      align-items: baseline;
      justify-content: flex-end;
      gap: 8px;
    }

    .port-count {
      font-size: 11px;
      font-family: monospace;
      font-weight: 600;
      color: var(--tl-text-primary);
    }

    .port-pct {
      font-size: 10px;
      font-weight: 600;
      color: var(--tl-cyan, #06B6D4);
      min-width: 38px;
      text-align: right;
    }

    .card-footer {
      padding-top: 8px;
      border-top: 1px solid rgba(255, 255, 255, 0.04);
    }

    .footer-note {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 11px;
      color: var(--tl-text-muted);

      .note-icon {
        font-size: 13px;
        color: var(--tl-cyan, #06B6D4);
      }
    }

    .ports-list {
      display: flex;
      flex-direction: column;
      gap: 6px;
      flex: 1;
    }

    .port-row {
      display: grid;
      grid-template-columns: 200px 1fr 100px;
      align-items: center;
      gap: 14px;
      padding: 6px 10px;
      background: rgba(255, 255, 255, 0.015);
      border-radius: 4px;
      border: 1px solid rgba(255, 255, 255, 0.03);

      @media (max-width: 768px) {
        grid-template-columns: 140px 1fr 80px;
        gap: 8px;
      }
    }

    .port-identity {
      display: flex;
      align-items: center;
      gap: 8px;
      overflow: hidden;
    }

    .port-badge {
      font-size: 10px;
      font-weight: 700;
      background: rgba(6, 182, 212, 0.12);
      color: var(--tl-cyan, #06B6D4);
      border: 1px solid rgba(6, 182, 212, 0.25);
      padding: 2px 6px;
      border-radius: 3px;
      flex-shrink: 0;

      .port-num {
        font-size: 10px;
      }
    }

    .port-service-group {
      display: flex;
      flex-direction: column;
      gap: 1px;
      overflow: hidden;
    }

    .port-service {
      font-size: 11px;
      font-weight: 500;
      color: var(--tl-text-primary);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .port-criticality {
      font-size: 9px;
      color: var(--tl-text-muted);
    }

    .port-bar-track {
      width: 100%;
      height: 8px;
      background: rgba(255, 255, 255, 0.04);
      border-radius: 4px;
      overflow: hidden;
    }

    .port-bar-fill {
      height: 100%;
      border-radius: 4px;
      background: #0284C7;
      transition: width 0.3s ease;
    }

    .port-metrics {
      display: flex;
      align-items: baseline;
      justify-content: flex-end;
      gap: 8px;
    }

    .port-count {
      font-size: 11px;
      font-family: monospace;
      font-weight: 600;
      color: var(--tl-text-primary);
    }

    .port-pct {
      font-size: 10px;
      font-weight: 600;
      color: var(--tl-cyan, #06B6D4);
      min-width: 38px;
      text-align: right;
    }

    .card-footer {
      padding-top: 8px;
      border-top: 1px solid rgba(255, 255, 255, 0.04);
    }

    .footer-note {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 11px;
      color: var(--tl-text-muted);

      .note-icon {
        font-size: 13px;
        color: var(--tl-cyan, #06B6D4);
      }
    }
  `],
})
export class PortConcentrationCardComponent {
  @Input() title: string = 'Destination Port Concentration';
  @Input() subtitle: string = 'Service targeting and destination port distribution for evaluated threat classes';
  @Input() loading: boolean = false;
  @Input() errorMessage: string | null = null;

  @Input() set portData(data: DestinationPortAnalyticsResponse | null | undefined) {
    this._portData = data || null;
    this.recompute();
  }

  private _portData: DestinationPortAnalyticsResponse | null = null;
  categoriesList: string[] = [];
  selectedCategoryKey: string = 'Benign';
  activeCategory: CategoryPortAnalysis | null = null;
  readonly Math = Math;

  onCategoryChange(): void {
    if (this._portData && this._portData.categories) {
      this.activeCategory = this._portData.categories[this.selectedCategoryKey] || null;
    }
  }

  private recompute(): void {
    if (!this._portData || !this._portData.categories) {
      this.categoriesList = [];
      this.activeCategory = null;
      return;
    }

    this.categoriesList = Object.keys(this._portData.categories).sort();
    if (!this.categoriesList.includes(this.selectedCategoryKey)) {
      this.selectedCategoryKey = this.categoriesList[0] || 'Benign';
    }
    this.activeCategory = this._portData.categories[this.selectedCategoryKey] || null;
  }
}

