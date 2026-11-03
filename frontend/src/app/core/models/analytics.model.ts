/**
 * Analytical Reports & Diagnostics models corresponding to FastAPI backend schemas.
 */

// 1. Temporal Analytics Models
export interface DailyAttackCount {
  class_name: string;
  active_days_count: number;
  primary_event_date: string;
  primary_day_count: number;
  primary_day_percentage: float;
  is_single_day_attack: boolean;
  daily_counts: Record<string, number>;
}

export interface TemporalDateSummary {
  event_date: string;
  total_flows: number;
}

export interface TemporalAnalyticsResponse {
  report_name: string;
  timestamp: string;
  dataset_path: string;
  horizon_days: number;
  dates: string[];
  event_date_totals: TemporalDateSummary[];
  attack_temporal_profiles: DailyAttackCount[];
}

// 2. Destination Port Concentration Models
export interface PortConcentrationItem {
  port: number;
  service_name: string;
  criticality_weight: number;
  flow_count: number;
  percentage_within_class: number;
}

export interface CategoryPortAnalysis {
  class_name: string;
  total_flows: number;
  top_ports: PortConcentrationItem[];
  concentration_top_1_port_pct: number;
  concentration_top_3_ports_pct: number;
  has_extreme_port_concentration: boolean;
}

export interface DestinationPortAnalyticsResponse {
  report_name: string;
  timestamp: string;
  total_categories: number;
  categories: Record<string, CategoryPortAnalysis>;
}

// 3. Model Diagnostics & Confusion Matrix Models
export interface ConfusionMatrixPayload {
  class_labels: string[];
  raw_matrix: number[][];
  normalized_matrix: number[][];
}

export interface SplitMetricsSummary {
  evaluated_split: string;
  total_evaluated_samples: number;
  overall_accuracy: number;
  majority_class_baseline_accuracy: number;
  macro_f1: number;
  weighted_f1: number;
  weighted_precision: number;
  weighted_recall: number;
  balanced_accuracy: number;
  confusion_matrix: ConfusionMatrixPayload;
  calibration_notice?: string | null;
}

export interface FeatureImportanceItem {
  feature_name: string;
  clean_feature_name: string;
  importance: number;
}

export interface SplitClassMetrics {
  support: number;
  predicted_support: number;
  precision: number;
  recall: number;
  f1_score: number;
  specificity: number;
  fpr: number;
  fnr: number;
  tp: number;
  fp: number;
  fn: number;
  tn: number;
}

export interface CategoryGovernanceItem {
  class_name: string;
  official_reliability_tier: string;
  gating_reason: string;
  generalization_assessment: string;
  validation: SplitClassMetrics;
  test: SplitClassMetrics;
}

export interface ModelDiagnosticsResponse {
  pipeline_name: string;
  model_artifact: string;
  model_governance_status: string;
  quarantine_disclosure: string;
  training_duration_seconds: number;
  top_feature_importances: FeatureImportanceItem[];
  validation_metrics: SplitMetricsSummary;
  test_metrics: SplitMetricsSummary;
  category_evaluations: CategoryGovernanceItem[];
}

// 4. Feature Redundancy Models
export interface EvaluatedCorrelationPair {
  feature_1: string;
  feature_2: string;
  description: string;
  pearson_correlation: number;
  is_near_duplicate: boolean;
  is_strongly_collinear: boolean;
  recommendation: string;
}

export interface FeatureRedundancyResponse {
  report_name: string;
  timestamp: string;
  evaluated_pairs_count: number;
  redundant_pairs_count: number;
  all_evaluated_correlations: EvaluatedCorrelationPair[];
}

// 5. Full 63-Feature Importance Models
export interface RankedFeatureImportanceItem {
  feature_name: string;
  clean_feature_name: string;
  training_index: number;
  importance: number;
  rank: number;
}

export interface AllFeatureImportancesResponse {
  artifact_name: string;
  model_artifact: string;
  feature_count: number;
  feature_ordering: string;
  importance_method: string;
  governance_notice: string;
  all_feature_importances: RankedFeatureImportanceItem[];
}

type float = number;


