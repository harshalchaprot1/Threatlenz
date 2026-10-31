/**
 * MITRE ATT&CK technique mapping models corresponding to FastAPI backend schemas.
 */

export type MitreMappingStatus = 'candidate' | 'unverified' | 'not_applicable' | 'verified' | string;

export interface MitreMappingResponse {
  snapshot_id: string;
  canonical_label: string;
  technique_id: string | null;
  technique_name: string | null;
  tactic: string | null;
  mapping_status: MitreMappingStatus;
  is_confirmed: boolean;
  rationale: string | null;
  missing_telemetry: string[];
  created_at: string;
}
