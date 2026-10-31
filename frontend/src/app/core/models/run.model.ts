/**
 * Pipeline run models corresponding to FastAPI backend schemas.
 */

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface PipelineRunSummary {
  run_id: string;
  report_name: string;
  pipeline_version: string;
  run_timestamp: string;
  execution_duration_seconds: number;
  source_manifest_hash: string;
  total_profiles: number;
  attack_categories_count: number;
  benign_categories_count: number;
  unknown_categories_count: number;
  target_impact_status: string;
  model_status: string;
  created_at: string;
}

export interface PipelineRunDetail extends PipelineRunSummary {
  dataset_path: string;
  manifest_files_count: number;
  manifest_total_bytes: number;
  provenance_type: string;
  traffic_source: string;
  is_model_prediction: boolean;
  is_live_detection: boolean;
  is_independently_verified: boolean;
  window_type: string;
  window_start: string;
  window_end: string;
  interval_semantics: string;
  model_artifact: string;
  model_quarantine_reason: string;
  model_inference_executed: boolean;
  model_evaluation_metrics_status: string;
}
