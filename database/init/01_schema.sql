-- ==============================================================================
-- ThreatLenz Phase 6: PostgreSQL Relational Schema
-- Normalized persistence for pipeline runs, threat profiles, MITRE mappings,
-- TLRS risk assessments, and advisory recommendations.
--
-- Safeguards Enforced:
-- 1. Idempotent DDL (IF NOT EXISTS, deterministic unique constraints).
-- 2. Foreign key cascade deletes to ensure zero orphaned child records.
-- 3. Strict flags for unconfirmed intelligence:
--    - mitre_mappings.is_confirmed: FALSE for candidate/unverified mappings.
--    - risk_assessments.is_confirmed: FALSE when target_impact is missing.
-- 4. Mandatory analyst validation:
--    - advisories.analyst_validation_required: DEFAULT TRUE.
--    - advisories.is_automated_action: DEFAULT FALSE (advisory only).
-- ==============================================================================

-- 1. Pipeline Execution Runs
CREATE TABLE IF NOT EXISTS pipeline_runs (
    run_id VARCHAR(64) PRIMARY KEY,
    report_name VARCHAR(128) NOT NULL,
    pipeline_version VARCHAR(32) NOT NULL,
    run_timestamp TIMESTAMPTZ NOT NULL,
    execution_duration_seconds NUMERIC(10, 2) NOT NULL,
    dataset_path TEXT NOT NULL,
    source_manifest_hash VARCHAR(32) NOT NULL,
    manifest_files_count INTEGER NOT NULL,
    manifest_total_bytes BIGINT NOT NULL,
    provenance_type VARCHAR(64) NOT NULL,
    traffic_source VARCHAR(255) NOT NULL,
    is_model_prediction BOOLEAN NOT NULL DEFAULT FALSE,
    is_live_detection BOOLEAN NOT NULL DEFAULT FALSE,
    is_independently_verified BOOLEAN NOT NULL DEFAULT FALSE,
    window_type VARCHAR(32) NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    window_end TIMESTAMPTZ NOT NULL,
    interval_semantics VARCHAR(64) NOT NULL,
    model_artifact VARCHAR(255) NOT NULL,
    model_status VARCHAR(64) NOT NULL,
    model_quarantine_reason TEXT NOT NULL,
    model_inference_executed BOOLEAN NOT NULL DEFAULT FALSE,
    model_evaluation_metrics_status VARCHAR(64) NOT NULL,
    total_profiles INTEGER NOT NULL,
    attack_categories_count INTEGER NOT NULL,
    benign_categories_count INTEGER NOT NULL,
    unknown_categories_count INTEGER NOT NULL,
    target_impact_status VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_pipeline_runs_run_timestamp ON pipeline_runs(run_timestamp);
CREATE INDEX IF NOT EXISTS ix_pipeline_runs_source_manifest_hash ON pipeline_runs(source_manifest_hash);

-- 2. Structured Threat Profiles (Snapshots)
CREATE TABLE IF NOT EXISTS threat_profiles (
    snapshot_id VARCHAR(32) PRIMARY KEY,
    profile_id VARCHAR(32) NOT NULL,
    run_id VARCHAR(64) NOT NULL REFERENCES pipeline_runs(run_id) ON DELETE CASCADE,
    source_manifest_hash VARCHAR(32) NOT NULL,
    schema_version VARCHAR(16) NOT NULL,
    window_type VARCHAR(32) NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    window_end TIMESTAMPTZ NOT NULL,
    canonical_label VARCHAR(64) NOT NULL,
    raw_label VARCHAR(64) NOT NULL,
    attack_status VARCHAR(32) NOT NULL,
    is_attack BOOLEAN,
    is_mapped BOOLEAN NOT NULL DEFAULT TRUE,
    flow_count BIGINT NOT NULL,
    total_bytes BIGINT NOT NULL,
    total_packets BIGINT NOT NULL,
    active_observation_units INTEGER NOT NULL,
    recurrence_denominator INTEGER NOT NULL,
    recurrence_ratio NUMERIC(6, 4) NOT NULL,
    model_reliability VARCHAR(32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_run_profile UNIQUE (run_id, profile_id)
);

CREATE INDEX IF NOT EXISTS ix_threat_profiles_profile_id ON threat_profiles(profile_id);
CREATE INDEX IF NOT EXISTS ix_threat_profiles_run_id ON threat_profiles(run_id);
CREATE INDEX IF NOT EXISTS ix_threat_profiles_canonical_label ON threat_profiles(canonical_label);
CREATE INDEX IF NOT EXISTS ix_threat_profiles_attack_status ON threat_profiles(attack_status);

-- 3. MITRE ATT&CK Technique Mappings
CREATE TABLE IF NOT EXISTS mitre_mappings (
    snapshot_id VARCHAR(32) PRIMARY KEY REFERENCES threat_profiles(snapshot_id) ON DELETE CASCADE,
    canonical_label VARCHAR(64) NOT NULL,
    technique_id VARCHAR(32),
    technique_name VARCHAR(255),
    tactic VARCHAR(128),
    mapping_status VARCHAR(32) NOT NULL,
    is_confirmed BOOLEAN NOT NULL DEFAULT FALSE,
    rationale TEXT,
    missing_telemetry JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_mitre_mappings_technique_id ON mitre_mappings(technique_id);
CREATE INDEX IF NOT EXISTS ix_mitre_mappings_mapping_status ON mitre_mappings(mapping_status);
CREATE INDEX IF NOT EXISTS ix_mitre_mappings_is_confirmed ON mitre_mappings(is_confirmed);

-- 4. Threat Level Risk Scoring (TLRS) Assessments
CREATE TABLE IF NOT EXISTS risk_assessments (
    snapshot_id VARCHAR(32) PRIMARY KEY REFERENCES threat_profiles(snapshot_id) ON DELETE CASCADE,
    severity_score NUMERIC(6, 2) NOT NULL,
    frequency_score NUMERIC(6, 2) NOT NULL,
    recurrence_score NUMERIC(6, 2) NOT NULL,
    target_impact_score NUMERIC(6, 2),
    weight_severity NUMERIC(4, 2) NOT NULL DEFAULT 0.40,
    weight_frequency NUMERIC(4, 2) NOT NULL DEFAULT 0.25,
    weight_recurrence NUMERIC(4, 2) NOT NULL DEFAULT 0.20,
    weight_target_impact NUMERIC(4, 2) NOT NULL DEFAULT 0.15,
    tlrs_complete NUMERIC(6, 2),
    tlrs_complete_rounded INTEGER,
    tlrs_partial_diagnostic NUMERIC(6, 2) NOT NULL,
    tlrs_normalized_heuristic NUMERIC(6, 2) NOT NULL,
    tlrs_normalized_rounded INTEGER NOT NULL,
    evidence_coverage NUMERIC(4, 2) NOT NULL,
    scoring_status VARCHAR(32) NOT NULL,
    risk_band VARCHAR(32) NOT NULL,
    provisional_risk_band VARCHAR(64),
    is_confirmed BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_risk_assessments_scoring_status ON risk_assessments(scoring_status);
CREATE INDEX IF NOT EXISTS ix_risk_assessments_risk_band ON risk_assessments(risk_band);
CREATE INDEX IF NOT EXISTS ix_risk_assessments_is_confirmed ON risk_assessments(is_confirmed);

-- 5. Defensive Advisory Recommendations
CREATE TABLE IF NOT EXISTS advisories (
    id BIGSERIAL PRIMARY KEY,
    snapshot_id VARCHAR(32) NOT NULL REFERENCES threat_profiles(snapshot_id) ON DELETE CASCADE,
    recommendation_id VARCHAR(64) NOT NULL,
    threat_category VARCHAR(64) NOT NULL,
    priority VARCHAR(16) NOT NULL,
    action_type VARCHAR(64) NOT NULL,
    summary TEXT NOT NULL,
    detailed_guidance TEXT NOT NULL,
    missing_evidence_required JSONB NOT NULL DEFAULT '[]'::jsonb,
    analyst_validation_required BOOLEAN NOT NULL DEFAULT TRUE,
    is_automated_action BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_snapshot_recommendation UNIQUE (snapshot_id, recommendation_id)
);

CREATE INDEX IF NOT EXISTS ix_advisories_snapshot_id ON advisories(snapshot_id);
CREATE INDEX IF NOT EXISTS ix_advisories_recommendation_id ON advisories(recommendation_id);
CREATE INDEX IF NOT EXISTS ix_advisories_priority ON advisories(priority);
CREATE INDEX IF NOT EXISTS ix_advisories_action_type ON advisories(action_type);
