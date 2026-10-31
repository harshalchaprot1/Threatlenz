/**
 * Threat profile models corresponding to FastAPI backend schemas.
 */

export type AttackStatus = 'ATTACK' | 'BENIGN' | 'UNKNOWN';

export type ModelReliability = 'HIGH_RELIABILITY' | 'EVALUABLE' | 'UNRELIABLE' | 'NON_EVALUABLE';

export interface ThreatProfileSummary {
  snapshot_id: string;
  profile_id: string;
  run_id: string;
  source_manifest_hash: string;
  schema_version: string;
  window_type: string;
  window_start: string;
  window_end: string;
  canonical_label: string;
  raw_label: string;
  attack_status: AttackStatus;
  is_attack: boolean | null;
  is_mapped: boolean;
  flow_count: number;
  total_bytes: number;
  total_packets: number;
  active_observation_units: number;
  recurrence_denominator: number;
  recurrence_ratio: number;
  model_reliability?: ModelReliability | null;
  created_at: string;
}

export interface ProfileFilterParams {
  run_id?: string;
  canonical_label?: string;
  attack_status?: AttackStatus;
  is_attack?: boolean;
  limit?: number;
  offset?: number;
}
