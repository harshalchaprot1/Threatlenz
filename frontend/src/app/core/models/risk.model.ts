/**
 * Threat Level Risk Score (TLRS) models corresponding to FastAPI backend schemas.
 */

export type RiskBand =
  | 'Informational'
  | 'Low'
  | 'Medium'
  | 'High'
  | 'Critical'
  | 'Insufficient Evidence'
  | string;

export interface RiskAssessmentResponse {
  snapshot_id: string;
  severity_score: number;
  frequency_score: number;
  recurrence_score: number;
  target_impact_score: number | null;
  weight_severity: number;
  weight_frequency: number;
  weight_recurrence: number;
  weight_target_impact: number;
  tlrs_complete: number | null;
  tlrs_complete_rounded: number | null;
  tlrs_partial_diagnostic: number;
  tlrs_normalized_heuristic: number;
  tlrs_normalized_rounded: number;
  evidence_coverage: number;
  scoring_status: string;
  risk_band: RiskBand;
  provisional_risk_band: string | null;
  is_confirmed: boolean;
  created_at: string;
}
