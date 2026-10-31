/**
 * Defensive advisory recommendation models corresponding to FastAPI backend schemas.
 */

export type AdvisoryPriority = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | string;

export interface AdvisoryResponse {
  id: number;
  snapshot_id: string;
  recommendation_id: string;
  threat_category: string;
  priority: AdvisoryPriority;
  action_type: string;
  summary: string;
  detailed_guidance: string;
  missing_evidence_required: string[];
  analyst_validation_required: boolean;
  is_automated_action: boolean;
  created_at: string;
}

export interface AdvisoriesListResponse {
  snapshot_id: string;
  total: number;
  items: AdvisoryResponse[];
}
