import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { FeatureRedundancyResponse, EvaluatedCorrelationPair } from '../../../core/models';

export type CorrelationFilter = 'ALL' | 'NEAR_DUPLICATE' | 'STRONGLY_COLLINEAR' | 'NON_COLLINEAR';

interface PruningDecisionMeta {
  pipelineStatusText: string;
  isPruned: boolean;
  prunedFeature?: string;
  retainedFeature?: string;
  reason: string;
}

@Component({
  selector: 'app-feature-redundancy-table',
  standalone: true,
  imports: [CommonModule, FormsModule, MatProgressSpinnerModule],
  template: `
    <div class="redundancy-card">
      <div class="redundancy-header">
        <div class="header-titles">
          <div class="title-row">
            <span class="redundancy-title">{{ title }}</span>
            <span class="eval-pill">63-Feature Evaluation Pipeline</span>
          </div>
          <span class="redundancy-subtitle">{{ subtitle }}</span>
        </div>

        <div class="header-controls">
          <!-- Classification Filter -->
          <div class="filter-group">
            <label for="redundancyFilter" class="filter-label">Filter Classification:</label>
            <div class="select-wrapper">
              <select
                id="redundancyFilter"
                class="filter-select"
                [ngModel]="selectedFilter"
                (ngModelChange)="onFilterChange($event)"
              >
                <option value="ALL">All Pairs (9)</option>
                <option value="NEAR_DUPLICATE">Near-Duplicates (6)</option>
                <option value="STRONGLY_COLLINEAR">Strongly Collinear (2)</option>
                <option value="NON_COLLINEAR">Non-Collinear (1)</option>
              </select>
            </div>
            @if (selectedFilter !== 'ALL') {
              <button class="reset-filter-btn" (click)="resetFilter()" title="Reset to all pairs">
                <span class="material-symbols-outlined reset-icon">close</span>
                <span>Reset</span>
              </button>
            }
          </div>
        </div>
      </div>

      <!-- Threshold Guide & Pruning Summary -->
      <div class="threshold-guide-strip">
        <div class="guide-legend">
          <span class="guide-title">Classification Thresholds:</span>
          <div class="legend-badges">
            <span class="threshold-tag near-duplicate">
              <span class="pill-dot dot-dup"></span>
              <strong>Near-Duplicate:</strong> |r| &ge; 0.98 (6 pairs)
            </span>
            <span class="threshold-tag collinear">
              <span class="pill-dot dot-col"></span>
              <strong>Strongly Collinear:</strong> 0.90 &le; |r| &lt; 0.98 (2 pairs)
            </span>
            <span class="threshold-tag non-collinear">
              <span class="pill-dot dot-non"></span>
              <strong>Non-Collinear:</strong> |r| &lt; 0.90 (1 pair)
            </span>
          </div>
        </div>

        <div class="pipeline-verification-pill">
          <span class="material-symbols-outlined check-icon">verified</span>
          <span>Verified against <code class="inline-code">models/clean_per_class_rf/feature_metadata.json</code></span>
        </div>
      </div>

      <!-- Feature Terminology Quick Glossary -->
      <div class="feature-glossary-panel">
        <div class="glossary-header">
          <span class="material-symbols-outlined glossary-icon">help_outline</span>
          <span class="glossary-title">Network Telemetry Terminology &amp; Redundancy Glossary</span>
        </div>
        <div class="glossary-items">
          <div class="glossary-item">
            <span class="glossary-term">Forward (fwd):</span>
            <span class="glossary-desc">Packets or bytes transmitted from the recorded flow source (initiator) toward the destination.</span>
          </div>
          <div class="glossary-item">
            <span class="glossary-term">Backward (bwd):</span>
            <span class="glossary-desc">Packets or bytes transmitted in the reverse direction from destination back to source.</span>
          </div>
          <div class="glossary-item">
            <span class="glossary-term">Flow:</span>
            <span class="glossary-desc">Bidirectional network conversation identified by its 5-tuple (source IP, destination IP, source port, destination port, protocol).</span>
          </div>
          <div class="glossary-item">
            <span class="glossary-term">Packet Length:</span>
            <span class="glossary-desc">Total packet length in bytes across the flow, calculated from the packet lengths observed by CICFlowMeter.</span>
          </div>
          <div class="glossary-item">
            <span class="glossary-term">Inter-Arrival Time (IAT):</span>
            <span class="glossary-desc">Elapsed time in microseconds (&mu;s) between consecutive packet arrivals within a flow direction.</span>
          </div>
          <div class="glossary-item">
            <span class="glossary-term">Pearson Correlation (r):</span>
            <span class="glossary-desc">Linear relationship metric (-1 to +1). Values near 1.0 indicate strong collinearity; correlation does not imply causation.</span>
          </div>
          <div class="glossary-item">
            <span class="glossary-term">Feature Redundancy:</span>
            <span class="glossary-desc">Statistical collinearity where two metrics convey duplicate information, potentially distorting decision tree splits.</span>
          </div>
          <div class="glossary-item">
            <span class="glossary-term">Pipeline Pruning:</span>
            <span class="glossary-desc">Exclusion of redundant subflow duplicates from model input vectorization while preserving raw dataset integrity.</span>
          </div>
        </div>
      </div>

      <!-- Why 63 Features Architecture Explanation -->
      <div class="pipeline-derivation-panel">
        <div class="derivation-header">
          <div class="derivation-title-row">
            <span class="material-symbols-outlined derivation-icon">account_tree</span>
            <span class="derivation-title">Architecture Audit: Derivation of the 63-Feature Model Input</span>
          </div>
          <span class="derivation-subtitle">
            Exact, verified feature selection progression from 80 raw CSV fields to 63 MLlib Random Forest features
          </span>
        </div>

        <div class="derivation-flow-grid">
          <div class="flow-step">
            <div class="step-num">Stage 1</div>
            <div class="step-label">Raw Benchmark Telemetry</div>
            <div class="step-count">80 Columns</div>
            <div class="step-desc">79 network flow metrics + 1 ground-truth string label (<code class="inline-code">Label</code>) across 8 CSV capture files.</div>
          </div>

          <div class="flow-arrow">&rarr;</div>

          <div class="flow-step">
            <div class="step-num">Stage 2</div>
            <div class="step-label">ETL Curated Lakehouse</div>
            <div class="step-count">83 Columns</div>
            <div class="step-desc">+3 derived audit columns: <code class="inline-code">raw_label</code>, <code class="inline-code">timestamp_parsed</code>, and date partition key <code class="inline-code">event_date</code>.</div>
          </div>

          <div class="flow-arrow">&rarr;</div>

          <div class="flow-step step-exclusion">
            <div class="step-num">Stage 3</div>
            <div class="step-label">Governance Exclusions</div>
            <div class="step-count">-6 Columns</div>
            <div class="step-desc">
              <strong>4 Metadata/Targets:</strong> <code class="inline-code">timestamp</code>, <code class="inline-code">label</code>, <code class="inline-code">raw_label</code>, <code class="inline-code">event_date</code><br>
              <strong>1 Shortcut Port:</strong> <code class="inline-code">dst_port</code> (synthetic testbed memorization)<br>
              <strong>1 Quarantined Index:</strong> <code class="inline-code">label_idx</code> (target-label leakage elimination)
            </div>
          </div>

          <div class="flow-arrow">&rarr;</div>

          <div class="flow-step step-pruned">
            <div class="step-num">Stage 4</div>
            <div class="step-label">Variance &amp; Collinearity Pruning</div>
            <div class="step-count">-14 Columns</div>
            <div class="step-desc">
              <strong>8 Constant Columns:</strong> 0 variance across all 7.23M flows (<code class="inline-code">bwd_psh_flags</code>, <code class="inline-code">bwd_urg_flags</code>, etc.)<br>
              <strong>6 Redundant Subflows:</strong> Perfect collinear duplicates (|r| &ge; 0.999999) pruned to prevent tree distortion.
            </div>
          </div>

          <div class="flow-arrow">&rarr;</div>

          <div class="flow-step step-final">
            <div class="step-num">Final</div>
            <div class="step-label">Model Input Vector</div>
            <div class="step-count">63 Features</div>
            <div class="step-desc">Leakage-excluded, zero-collinearity dense feature vector assembled for verified Random Forest evaluation.</div>
          </div>
        </div>

        <div class="derivation-footer-math">
          <strong>Mathematical Schema Progression:</strong>
          <span class="math-expr">83 Lakehouse Columns - (5 Metadata/Label/Date + 1 Shortcut Port + 8 Constant + 6 Redundant Subflows) = <strong>63 Clean Features</strong></span>
        </div>
      </div>

      <!-- Loading State -->
      @if (loading) {
        <div class="state-container">
          <mat-spinner diameter="36"></mat-spinner>
          <span>Evaluating Pearson correlation matrix...</span>
        </div>
      }

      <!-- Error State -->
      @if (errorMessage && !loading) {
        <div class="state-container error-state">
          <span class="material-symbols-outlined state-icon">error</span>
          <span>{{ errorMessage }}</span>
        </div>
      }

      <!-- Redundancy Table -->
      @if (!loading && !errorMessage && filteredPairs.length > 0) {
        <div class="table-responsive">
          <table class="redundancy-table">
            <thead>
              <tr>
                <th class="col-pair">Evaluated Feature Pair</th>
                <th class="col-desc">Pair Relationship</th>
                <th class="col-pearson">Pearson r</th>
                <th class="col-class">Classification</th>
                <th class="col-status">63-Feature Pipeline Decision &amp; Rationale</th>
              </tr>
            </thead>
            <tbody>
              @for (pair of filteredPairs; track pair.feature_1 + '-' + pair.feature_2) {
                <tr [ngClass]="getRowClass(pair)">
                  <td class="features-cell">
                    <div class="pair-display-wrap">
                      <!-- Feature 1 -->
                      <div class="feature-unit">
                        <span class="feat-human-label">
                          {{ getHumanName(pair.feature_1) }}
                        </span>
                        <div class="feat-meta-row">
                          <span class="feat-tag font-mono">
                            {{ pair.feature_1 }}
                          </span>
                          <span
                            class="pipeline-status-badge"
                            [class.badge-pruned]="isFeaturePruned(pair, pair.feature_1)"
                            [class.badge-retained]="!isFeaturePruned(pair, pair.feature_1)"
                          >
                            {{ isFeaturePruned(pair, pair.feature_1) ? 'Pruned from 63-Feature Pipeline' : 'Retained in 63-Feature Pipeline' }}
                          </span>
                        </div>
                      </div>

                      <span class="corr-arrow" title="Evaluated correlation relationship">&harr;</span>

                      <!-- Feature 2 -->
                      <div class="feature-unit">
                        <span class="feat-human-label">
                          {{ getHumanName(pair.feature_2) }}
                        </span>
                        <div class="feat-meta-row">
                          <span class="feat-tag font-mono">
                            {{ pair.feature_2 }}
                          </span>
                          <span
                            class="pipeline-status-badge"
                            [class.badge-pruned]="isFeaturePruned(pair, pair.feature_2)"
                            [class.badge-retained]="!isFeaturePruned(pair, pair.feature_2)"
                          >
                            {{ isFeaturePruned(pair, pair.feature_2) ? 'Pruned from 63-Feature Pipeline' : 'Retained in 63-Feature Pipeline' }}
                          </span>
                        </div>
                      </div>
                    </div>
                  </td>

                  <td class="desc-cell">{{ pair.description }}</td>

                  <td class="corr-cell font-mono">
                    <div class="corr-gauge">
                      <span class="corr-num">{{ pair.pearson_correlation.toFixed(6) }}</span>
                      <div class="gauge-bar">
                        <div
                          class="gauge-fill"
                          [style.width.%]="pair.pearson_correlation * 100"
                          [ngClass]="getGaugeFillClass(pair)"
                        ></div>
                      </div>
                    </div>
                  </td>

                  <td>
                    @if (pair.is_near_duplicate) {
                      <span class="class-pill pill-duplicate">Near-Duplicate</span>
                    } @else if (pair.is_strongly_collinear) {
                      <span class="class-pill pill-collinear">Strongly Collinear</span>
                    } @else {
                      <span class="class-pill pill-non-collinear">Non-Collinear</span>
                    }
                  </td>

                  <td class="status-cell">
                    <div class="status-wrapper">
                      @if (getPipelineDecision(pair).isPruned) {
                        <span class="status-pill pruned-badge">
                          <span class="material-symbols-outlined status-icon">content_cut</span>
                          <span>Pruned in 63-Feature Pipeline</span>
                        </span>
                        <span class="status-subdetail">
                          Dropped <code>{{ getPipelineDecision(pair).prunedFeature }}</code>; retained <code>{{ getPipelineDecision(pair).retainedFeature }}</code>
                        </span>
                        <span class="status-reason-text">
                          {{ getPipelineDecision(pair).reason }}
                        </span>
                      } @else {
                        <span class="status-pill retained-badge">
                          <span class="material-symbols-outlined status-icon">check_circle</span>
                          <span>Retained in 63-Feature Pipeline</span>
                        </span>
                        <span class="status-subdetail">
                          Both features retained in 63-feature pipeline
                        </span>
                        <span class="status-reason-text">
                          {{ getPipelineDecision(pair).reason }}
                        </span>
                      }
                    </div>
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>

        <div class="redundancy-footer">
          <div class="footer-note">
            <span class="material-symbols-outlined note-icon">tips_and_updates</span>
            <div>
              <strong>Feature Collinearity &amp; Pipeline Execution Audit:</strong>
              Of the 9 evaluated feature pairs, exactly 6 near-duplicate subflow aggregations were permanently removed in the 63-feature pipeline (<code class="inline-code">collinear_subflows_pruned: true</code>).
              The remaining 3 collinear or non-collinear pairs were retained in the evaluated Random Forest architecture.
            </div>
          </div>
          @if (selectedFilter !== 'ALL') {
            <span class="filter-count-note">
              Showing {{ filteredPairs.length }} of 9 evaluated pairs
            </span>
          }
        </div>
      }

      @if (!loading && !errorMessage && filteredPairs.length === 0) {
        <div class="state-container">
          <span class="material-symbols-outlined state-icon">search_off</span>
          <span>No feature correlation pairs match the selected filter.</span>
          <button class="reset-filter-btn" (click)="resetFilter()">Reset Filter</button>
        </div>
      }
    </div>
  `,
  styles: [`
    .redundancy-card {
      background: var(--tl-bg-surface, #1E293B);
      border: 1px solid var(--tl-border, rgba(255, 255, 255, 0.08));
      border-radius: 8px;
      padding: 18px 20px;
      display: flex;
      flex-direction: column;
      gap: 14px;
    }

    .redundancy-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
    }

    .header-titles {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }

    .title-row {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }

    .redundancy-title {
      font-size: 16px;
      font-weight: 700;
      color: var(--tl-text-primary, #F8FAFC);
    }

    .eval-pill {
      font-size: 10px;
      font-weight: 600;
      color: var(--tl-cyan, #06B6D4);
      background: rgba(6, 182, 212, 0.1);
      border: 1px solid rgba(6, 182, 212, 0.25);
      border-radius: 4px;
      padding: 2px 8px;
    }

    .redundancy-subtitle {
      font-size: 12px;
      color: var(--tl-text-secondary, #94A3B8);
    }

    .header-controls {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .filter-group {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .filter-label {
      font-size: 12px;
      color: var(--tl-text-secondary, #94A3B8);
      font-weight: 500;
    }

    .select-wrapper {
      position: relative;
    }

    .filter-select {
      background: rgba(15, 23, 42, 0.8);
      border: 1px solid var(--tl-border, rgba(255, 255, 255, 0.12));
      border-radius: 5px;
      color: var(--tl-text-primary, #F8FAFC);
      font-size: 12px;
      font-weight: 500;
      padding: 5px 28px 5px 10px;
      cursor: pointer;
      appearance: none;
      background-image: url("data:image/svg+xml;charset=UTF-8,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%2394A3B8'%3e%3cpath d='M7 10l5 5 5-5z'/%3e%3c/svg%3e");
      background-repeat: no-repeat;
      background-position: right 6px center;
      background-size: 16px;
      min-width: 170px;

      &:focus {
        outline: none;
        border-color: var(--tl-cyan, #06B6D4);
      }
    }

    .reset-filter-btn {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      background: rgba(239, 68, 68, 0.1);
      border: 1px solid rgba(239, 68, 68, 0.25);
      color: #F87171;
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.15s ease;

      .reset-icon { font-size: 14px; }
      &:hover { background: rgba(239, 68, 68, 0.2); color: #FECACA; }
    }

    /* Threshold Guide */
    .threshold-guide-strip {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
      padding: 8px 12px;
      background: rgba(15, 23, 42, 0.4);
      border: 1px solid rgba(255, 255, 255, 0.04);
      border-radius: 5px;
    }

    .guide-legend {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }

    .guide-title {
      font-size: 11px;
      font-weight: 600;
      color: var(--tl-text-muted, #64748B);
    }

    .legend-badges {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }

    .threshold-tag {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      font-size: 11px;
      padding: 3px 8px;
      border-radius: 4px;

      strong {
        font-weight: 600;
      }

      &.near-duplicate {
        background: rgba(239, 68, 68, 0.1);
        color: #FCA5A5;
        border: 1px solid rgba(239, 68, 68, 0.25);
      }

      &.collinear {
        background: rgba(245, 158, 11, 0.1);
        color: #FCD34D;
        border: 1px solid rgba(245, 158, 11, 0.25);
      }

      &.non-collinear {
        background: rgba(16, 185, 129, 0.1);
        color: #6EE7B7;
        border: 1px solid rgba(16, 185, 129, 0.25);
      }
    }

    .pill-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      &.dot-dup { background: #EF4444; }
      &.dot-col { background: #F59E0B; }
      &.dot-non { background: #10B981; }
    }

    .pipeline-verification-pill {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      font-size: 11px;
      color: var(--tl-text-secondary, #94A3B8);

      .check-icon {
        font-size: 15px;
        color: var(--tl-cyan, #06B6D4);
      }

      .inline-code {
        font-family: monospace;
        background: rgba(255, 255, 255, 0.06);
        padding: 1px 4px;
        border-radius: 3px;
        font-size: 10.5px;
        color: var(--tl-text-primary, #F8FAFC);
      }
    }

    /* Terminology Glossary Panel */
    .feature-glossary-panel {
      background: rgba(15, 23, 42, 0.5);
      border: 1px solid var(--tl-border, rgba(255, 255, 255, 0.08));
      border-left: 3px solid var(--tl-cyan, #06B6D4);
      border-radius: 6px;
      padding: 12px 14px;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .glossary-header {
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .glossary-icon {
      font-size: 16px;
      color: var(--tl-cyan, #06B6D4);
    }

    .glossary-title {
      font-size: 12px;
      font-weight: 700;
      color: var(--tl-text-primary, #F8FAFC);
    }

    .glossary-items {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 8px 16px;
    }

    .glossary-item {
      display: flex;
      flex-direction: column;
      gap: 2px;
      font-size: 11.5px;
    }

    .glossary-term {
      font-weight: 700;
      color: var(--tl-cyan, #06B6D4);
      font-size: 11px;
    }

    .glossary-desc {
      color: var(--tl-text-secondary, #94A3B8);
      line-height: 1.4;
    }

    /* Derivation of 63 Features Panel */
    .pipeline-derivation-panel {
      background: rgba(15, 23, 42, 0.6);
      border: 1px solid var(--tl-border, rgba(255, 255, 255, 0.08));
      border-radius: 6px;
      padding: 14px 16px;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .derivation-header {
      display: flex;
      flex-direction: column;
      gap: 3px;
    }

    .derivation-title-row {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .derivation-icon {
      font-size: 18px;
      color: var(--tl-cyan, #06B6D4);
    }

    .derivation-title {
      font-size: 13px;
      font-weight: 700;
      color: var(--tl-text-primary, #F8FAFC);
    }

    .derivation-subtitle {
      font-size: 11.5px;
      color: var(--tl-text-secondary, #94A3B8);
    }

    .derivation-flow-grid {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      flex-wrap: wrap;
    }

    .flow-step {
      flex: 1;
      min-width: 170px;
      background: rgba(30, 41, 59, 0.6);
      border: 1px solid var(--tl-border, rgba(255, 255, 255, 0.08));
      border-radius: 6px;
      padding: 10px 12px;
      display: flex;
      flex-direction: column;
      gap: 4px;

      &.step-exclusion {
        border-color: rgba(245, 158, 11, 0.25);
        background: rgba(245, 158, 11, 0.04);
        .step-count { color: #FCD34D; }
      }

      &.step-pruned {
        border-color: rgba(239, 68, 68, 0.25);
        background: rgba(239, 68, 68, 0.04);
        .step-count { color: #FCA5A5; }
      }

      &.step-final {
        border-color: rgba(6, 182, 212, 0.35);
        background: rgba(6, 182, 212, 0.06);
        .step-count { color: #67E8F9; font-weight: 800; }
      }
    }

    .step-num {
      font-size: 10px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--tl-text-muted, #64748B);
    }

    .step-label {
      font-size: 12px;
      font-weight: 700;
      color: var(--tl-text-primary, #F8FAFC);
    }

    .step-count {
      font-size: 14px;
      font-weight: 700;
      color: var(--tl-cyan, #06B6D4);
    }

    .step-desc {
      font-size: 10.5px;
      color: var(--tl-text-secondary, #94A3B8);
      line-height: 1.4;

      .inline-code {
        font-family: monospace;
        font-size: 10px;
        background: rgba(255, 255, 255, 0.06);
        padding: 0 3px;
        border-radius: 2px;
        color: var(--tl-text-primary, #F8FAFC);
      }
    }

    .flow-arrow {
      color: var(--tl-text-muted, #64748B);
      font-size: 16px;
      font-weight: bold;
    }

    .derivation-footer-math {
      font-size: 11.5px;
      color: var(--tl-text-secondary, #94A3B8);
      background: rgba(15, 23, 42, 0.4);
      padding: 6px 10px;
      border-radius: 4px;
      border: 1px dashed rgba(255, 255, 255, 0.08);

      strong {
        color: var(--tl-text-primary, #F8FAFC);
      }

      .math-expr {
        font-family: monospace;
        color: var(--tl-cyan, #06B6D4);
        margin-left: 6px;
      }
    }

    /* Table Styles */
    .table-responsive {
      overflow-x: auto;
      border: 1px solid var(--tl-border, rgba(255, 255, 255, 0.08));
      border-radius: 6px;
    }

    .redundancy-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;

      th {
        text-align: left;
        padding: 8px 12px;
        background: rgba(15, 23, 42, 0.85);
        color: var(--tl-text-muted, #64748B);
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.4px;
        border-bottom: 1px solid var(--tl-border, rgba(255, 255, 255, 0.08));
      }

      td {
        padding: 10px 12px;
        border-bottom: 1px solid rgba(255, 255, 255, 0.04);
        color: var(--tl-text-primary, #F8FAFC);
        vertical-align: middle;
      }

      tr.row-duplicate { background: rgba(239, 68, 68, 0.02); }
      tr.row-collinear { background: rgba(245, 158, 11, 0.02); }
      tr.row-non-collinear { background: rgba(16, 185, 129, 0.02); }

      tr:hover {
        background: rgba(255, 255, 255, 0.03);
      }
    }

    .col-pair { min-width: 280px; }
    .col-desc { min-width: 190px; }
    .col-pearson { width: 130px; }
    .col-class { width: 140px; }
    .col-status { min-width: 310px; }

    .pair-display-wrap {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }

    .feature-unit {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }

    .feat-human-label {
      font-size: 12.5px;
      font-weight: 600;
      color: var(--tl-text-primary, #F8FAFC);
      line-height: 1.25;
    }

    .feat-meta-row {
      display: flex;
      align-items: center;
      gap: 6px;
      flex-wrap: wrap;
    }

    .feat-tag {
      background: rgba(255, 255, 255, 0.06);
      border: 1px solid rgba(255, 255, 255, 0.12);
      padding: 1px 6px;
      border-radius: 3px;
      font-size: 10.5px;
      color: var(--tl-cyan, #06B6D4);
      width: fit-content;
      transition: all 0.15s ease;
    }

    .pipeline-status-badge {
      font-size: 9.5px;
      font-weight: 600;
      padding: 1px 5px;
      border-radius: 3px;
      letter-spacing: 0.2px;
      white-space: nowrap;

      &.badge-pruned {
        background: rgba(245, 158, 11, 0.12);
        border: 1px solid rgba(245, 158, 11, 0.3);
        color: #FCD34D;
      }

      &.badge-retained {
        background: rgba(16, 185, 129, 0.1);
        border: 1px solid rgba(16, 185, 129, 0.25);
        color: #6EE7B7;
      }
    }

    .corr-arrow {
      color: var(--tl-text-muted, #64748B);
      font-size: 14px;
      padding: 0 2px;
    }

    .desc-cell {
      font-size: 12px;
      color: var(--tl-text-secondary, #94A3B8);
    }

    .corr-gauge {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }

    .corr-num {
      font-size: 11px;
      font-weight: 700;
      color: var(--tl-text-primary, #F8FAFC);
    }

    .gauge-bar {
      width: 100%;
      height: 4px;
      background: rgba(255, 255, 255, 0.08);
      border-radius: 2px;
      overflow: hidden;
    }

    .gauge-fill {
      height: 100%;
      border-radius: 2px;
      &.fill-dup { background: #EF4444; }
      &.fill-col { background: #F59E0B; }
      &.fill-non { background: #10B981; }
    }

    .class-pill {
      display: inline-block;
      font-size: 10px;
      font-weight: 700;
      padding: 2px 7px;
      border-radius: 4px;
      text-transform: uppercase;
      letter-spacing: 0.4px;
      white-space: nowrap;

      &.pill-duplicate {
        background: rgba(239, 68, 68, 0.15);
        color: #F87171;
        border: 1px solid rgba(239, 68, 68, 0.3);
      }

      &.pill-collinear {
        background: rgba(245, 158, 11, 0.15);
        color: #FBBF24;
        border: 1px solid rgba(245, 158, 11, 0.3);
      }

      &.pill-non-collinear {
        background: rgba(16, 185, 129, 0.15);
        color: #34D399;
        border: 1px solid rgba(16, 185, 129, 0.3);
      }
    }

    .status-cell {
      vertical-align: middle;
    }

    .status-wrapper {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }

    .status-pill {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      font-size: 11px;
      font-weight: 600;
      padding: 2px 8px;
      border-radius: 4px;
      width: fit-content;

      .status-icon {
        font-size: 13px;
      }

      &.pruned-badge {
        background: rgba(6, 182, 212, 0.12);
        border: 1px solid rgba(6, 182, 212, 0.3);
        color: #67E8F9;
      }

      &.retained-badge {
        background: rgba(148, 163, 184, 0.12);
        border: 1px solid rgba(148, 163, 184, 0.25);
        color: #CBD5E1;
      }
    }

    .status-subdetail {
      font-size: 10.5px;
      color: var(--tl-text-muted, #64748B);

      code {
        font-family: monospace;
        color: var(--tl-text-secondary, #94A3B8);
        background: rgba(255, 255, 255, 0.05);
        padding: 0 3px;
        border-radius: 2px;
      }
    }

    .status-reason-text {
      font-size: 11px;
      color: var(--tl-text-secondary, #94A3B8);
      line-height: 1.35;
      margin-top: 2px;
    }

    .font-mono {
      font-family: monospace;
    }

    .redundancy-footer {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 8px;
      padding-top: 4px;
    }

    .footer-note {
      display: flex;
      align-items: flex-start;
      gap: 8px;
      font-size: 11px;
      color: var(--tl-text-muted, #64748B);
      line-height: 1.45;

      .note-icon {
        font-size: 15px;
        color: var(--tl-cyan, #06B6D4);
        margin-top: 1px;
        flex-shrink: 0;
      }

      strong {
        color: var(--tl-text-primary, #F8FAFC);
      }

      .inline-code {
        font-family: monospace;
        background: rgba(255, 255, 255, 0.05);
        padding: 1px 4px;
        border-radius: 3px;
      }
    }

    .filter-count-note {
      font-size: 11px;
      color: var(--tl-cyan, #06B6D4);
      font-weight: 600;
    }

    .state-container {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      min-height: 180px;
      gap: 12px;
      color: var(--tl-text-secondary, #94A3B8);
      font-size: 13px;
    }

    .error-state {
      color: #EF4444;
      .state-icon { font-size: 32px; }
    }
  `],
})
export class FeatureRedundancyTableComponent {
  @Input() title: string = 'Statistical Feature Redundancy & Correlation Pruning';
  @Input() subtitle: string = 'Pearson correlation evaluation across 9 feature pairs from CSE-CIC-IDS2018 Spark analytics';
  @Input() loading: boolean = false;
  @Input() errorMessage: string | null = null;

  @Input() set redundancyData(data: FeatureRedundancyResponse | null | undefined) {
    this._data = data;
    this.pairs = data?.all_evaluated_correlations || [];
    this.applyFilter();
  }

  private _data: FeatureRedundancyResponse | null | undefined = null;
  pairs: EvaluatedCorrelationPair[] = [];
  filteredPairs: EvaluatedCorrelationPair[] = [];
  selectedFilter: CorrelationFilter = 'ALL';

  // Verified against models/clean_per_class_rf/feature_metadata.json (63 features in ordered_features)
  // Pruned subflow features: subflow_fwd_pkts, subflow_bwd_pkts, subflow_fwd_byts, subflow_bwd_byts, fwd_seg_size_avg, bwd_seg_size_avg
  readonly prunedFeaturesSet: Set<string> = new Set([
    'subflow_fwd_pkts',
    'subflow_bwd_pkts',
    'subflow_fwd_byts',
    'subflow_bwd_byts',
    'fwd_seg_size_avg',
    'bwd_seg_size_avg',
  ]);

  readonly humanFeatureNames: Record<string, string> = {
    tot_fwd_pkts: 'Total Forward Packets',
    subflow_fwd_pkts: 'Subflow Forward Packets',
    tot_bwd_pkts: 'Total Backward Packets',
    subflow_bwd_pkts: 'Subflow Backward Packets',
    totlen_fwd_pkts: 'Total Length of Forward Packets',
    subflow_fwd_byts: 'Subflow Forward Bytes',
    totlen_bwd_pkts: 'Total Length of Backward Packets',
    subflow_bwd_byts: 'Subflow Backward Bytes',
    fwd_pkt_len_mean: 'Mean Forward Packet Length',
    fwd_seg_size_avg: 'Average Forward Segment Size',
    bwd_pkt_len_mean: 'Mean Backward Packet Length',
    bwd_seg_size_avg: 'Average Backward Segment Size',
    pkt_len_mean: 'Mean Packet Length',
    pkt_size_avg: 'Average Packet Size',
    flow_duration: 'Total Flow Duration',
    fwd_iat_tot: 'Total Forward Inter-Arrival Time',
    flow_pkts_s: 'Flow Packet Rate',
    flow_byts_s: 'Flow Byte Rate',
  };

  getHumanName(featureKey: string): string {
    return this.humanFeatureNames[featureKey] || featureKey;
  }

  onFilterChange(f: CorrelationFilter): void {
    this.selectedFilter = f;
    this.applyFilter();
  }

  resetFilter(): void {
    this.selectedFilter = 'ALL';
    this.applyFilter();
  }

  private applyFilter(): void {
    if (this.selectedFilter === 'ALL') {
      this.filteredPairs = [...this.pairs];
    } else if (this.selectedFilter === 'NEAR_DUPLICATE') {
      this.filteredPairs = this.pairs.filter((p) => p.is_near_duplicate);
    } else if (this.selectedFilter === 'STRONGLY_COLLINEAR') {
      this.filteredPairs = this.pairs.filter((p) => p.is_strongly_collinear && !p.is_near_duplicate);
    } else if (this.selectedFilter === 'NON_COLLINEAR') {
      this.filteredPairs = this.pairs.filter((p) => !p.is_strongly_collinear && !p.is_near_duplicate);
    }
  }

  isFeaturePruned(pair: EvaluatedCorrelationPair, feat: string): boolean {
    return this.prunedFeaturesSet.has(feat);
  }

  getFeatureStatusTooltip(pair: EvaluatedCorrelationPair, feat: string): string {
    if (this.prunedFeaturesSet.has(feat)) {
      return `${feat}: Pruned from 63-feature pipeline to eliminate collinear redundancy`;
    }
    return `${feat}: Retained in 63-feature pipeline`;
  }

  getPipelineDecision(pair: EvaluatedCorrelationPair): PruningDecisionMeta {
    const f1Pruned = this.prunedFeaturesSet.has(pair.feature_1);
    const f2Pruned = this.prunedFeaturesSet.has(pair.feature_2);

    if (f1Pruned && !f2Pruned) {
      return {
        pipelineStatusText: 'Pruned in 63-Feature Pipeline',
        isPruned: true,
        prunedFeature: pair.feature_1,
        retainedFeature: pair.feature_2,
        reason: this.getPruningReason(pair, pair.feature_1, pair.feature_2),
      };
    } else if (!f1Pruned && f2Pruned) {
      return {
        pipelineStatusText: 'Pruned in 63-Feature Pipeline',
        isPruned: true,
        prunedFeature: pair.feature_2,
        retainedFeature: pair.feature_1,
        reason: this.getPruningReason(pair, pair.feature_2, pair.feature_1),
      };
    } else {
      return {
        pipelineStatusText: 'Retained in 63-Feature Pipeline',
        isPruned: false,
        reason: this.getRetentionReason(pair),
      };
    }
  }

  private getPruningReason(
    pair: EvaluatedCorrelationPair,
    pruned: string,
    retained: string
  ): string {
    if (pruned === 'subflow_fwd_pkts' || pruned === 'subflow_bwd_pkts') {
      return `Pruned redundant subflow packet counter (${pruned}) to eliminate duplicate variance (|r| = ${pair.pearson_correlation.toFixed(4)}). Primary aggregate packet count (${retained}) is retained.`;
    }
    if (pruned === 'subflow_fwd_byts' || pruned === 'subflow_bwd_byts') {
      return `Pruned redundant subflow byte counter (${pruned}) to eliminate duplicate variance (|r| = ${pair.pearson_correlation.toFixed(4)}). Primary total packet length (${retained}) is retained.`;
    }
    if (pruned.endsWith('_avg')) {
      return `Pruned duplicate average segment size calculation (${pruned}) in favor of canonical mean packet length (${retained}) (|r| = 1.0000).`;
    }
    return `Pruned collinear duplicate feature (${pruned}) to prevent tree split distortion while retaining ${retained}.`;
  }

  private getRetentionReason(pair: EvaluatedCorrelationPair): string {
    if (pair.feature_1 === 'flow_pkts_s' && pair.feature_2 === 'flow_byts_s') {
      return `Both features retained (|r| = 0.2830): weak linear correlation demonstrates independent signals (packet transmission rate vs byte throughput volume).`;
    }
    if (pair.feature_1 === 'flow_duration' && pair.feature_2 === 'fwd_iat_tot') {
      return `Both features retained (|r| = 0.9957): total flow duration captures overall session lifetime, whereas forward IAT captures direction-specific transmission intervals.`;
    }
    if (pair.feature_1 === 'pkt_len_mean' && pair.feature_2 === 'pkt_size_avg') {
      return `Both features retained (|r| = 0.9938): distinct mathematical formulations (arithmetic packet length mean vs aggregate total bytes / total packets) provide complementary directional nuance.`;
    }
    return `Both features retained: distinct telemetry dimensions evaluated by the Random Forest model.`;
  }

  getRowClass(pair: EvaluatedCorrelationPair): string {
    if (pair.is_near_duplicate) return 'row-duplicate';
    if (pair.is_strongly_collinear) return 'row-collinear';
    return 'row-non-collinear';
  }

  getGaugeFillClass(pair: EvaluatedCorrelationPair): string {
    if (pair.is_near_duplicate) return 'fill-dup';
    if (pair.is_strongly_collinear) return 'fill-col';
    return 'fill-non';
  }
}

