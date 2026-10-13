"""Pydantic v2 Request & Response Schemas.

Defines serialized representations for Health checks, Pipeline Runs,
Threat Profiles, MITRE ATT&CK Mappings, TLRS Risk Assessments, and Advisories.
"""

from datetime import datetime
from typing import Generic, List, Optional, TypeVar
from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


# 1. Generic Paginated Envelope
class PaginatedResponse(BaseModel, Generic[T]):
    """Standard pagination wrapper envelope."""
    items: List[T] = Field(..., description="List of items for current page")
    total: int = Field(..., description="Total number of items matching criteria")
    limit: int = Field(..., description="Requested page limit")
    offset: int = Field(..., description="Requested page offset")


# 2. Health Check Schemas
class DatabaseHealth(BaseModel):
    """Database connectivity status detail."""
    status: str = Field(..., description="Connectivity status: 'connected' or 'disconnected'")
    dialect: str = Field(..., description="Active database engine dialect (e.g., 'postgresql', 'sqlite')")


class HealthResponse(BaseModel):
    """System health check payload."""
    status: str = Field(..., description="Overall service status: 'healthy' or 'degraded'")
    database: DatabaseHealth = Field(..., description="Database backend health details")
    app_name: str = Field(..., description="Application name")
    version: str = Field(..., description="Application version")
    timestamp: datetime = Field(..., description="Current system timestamp")


# 3. Pipeline Run Schemas
class PipelineRunSummary(BaseModel):
    """Summarized pipeline execution run metadata for listing."""
    model_config = ConfigDict(from_attributes=True)

    run_id: str
    report_name: str
    pipeline_version: str
    run_timestamp: datetime
    execution_duration_seconds: float
    source_manifest_hash: str
    total_profiles: int
    attack_categories_count: int
    benign_categories_count: int
    unknown_categories_count: int
    target_impact_status: str
    model_status: str
    created_at: datetime


class PipelineRunDetail(BaseModel):
    """Comprehensive pipeline execution run metadata."""
    model_config = ConfigDict(from_attributes=True)

    run_id: str
    report_name: str
    pipeline_version: str
    run_timestamp: datetime
    execution_duration_seconds: float
    dataset_path: str
    source_manifest_hash: str
    manifest_files_count: int
    manifest_total_bytes: int
    provenance_type: str
    traffic_source: str
    is_model_prediction: bool
    is_live_detection: bool
    is_independently_verified: bool
    window_type: str
    window_start: datetime
    window_end: datetime
    interval_semantics: str
    model_artifact: str
    model_status: str
    model_quarantine_reason: str
    model_inference_executed: bool
    model_evaluation_metrics_status: str
    total_profiles: int
    attack_categories_count: int
    benign_categories_count: int
    unknown_categories_count: int
    target_impact_status: str
    created_at: datetime


# 4. Threat Profile Schemas
class ThreatProfileSummary(BaseModel):
    """Aggregated threat profile snapshot representation."""
    model_config = ConfigDict(from_attributes=True)

    snapshot_id: str
    profile_id: str
    run_id: str
    source_manifest_hash: str
    schema_version: str
    window_type: str
    window_start: datetime
    window_end: datetime
    canonical_label: str
    raw_label: str
    attack_status: str
    is_attack: Optional[bool] = None
    is_mapped: bool
    flow_count: int
    total_bytes: int
    total_packets: int
    active_observation_units: int
    recurrence_denominator: int
    recurrence_ratio: float
    model_reliability: Optional[str] = None
    created_at: datetime


# 5. MITRE ATT&CK Mapping Schemas
class MitreMappingResponse(BaseModel):
    """Adversary technique mapping details."""
    model_config = ConfigDict(from_attributes=True)

    snapshot_id: str
    canonical_label: str
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None
    tactic: Optional[str] = None
    mapping_status: str = Field(..., description="'candidate', 'unverified', 'not_applicable', or 'verified'")
    is_confirmed: bool = Field(..., description="False for candidate/unverified mappings")
    rationale: Optional[str] = None
    missing_telemetry: List[str] = Field(default_factory=list)
    created_at: datetime


# 6. Risk Assessment Schemas
class RiskAssessmentResponse(BaseModel):
    """TLRS risk assessment details."""
    model_config = ConfigDict(from_attributes=True)

    snapshot_id: str
    severity_score: float
    frequency_score: float
    recurrence_score: float
    target_impact_score: Optional[float] = None
    weight_severity: float
    weight_frequency: float
    weight_recurrence: float
    weight_target_impact: float
    tlrs_complete: Optional[float] = None
    tlrs_complete_rounded: Optional[int] = None
    tlrs_partial_diagnostic: float
    tlrs_normalized_heuristic: float
    tlrs_normalized_rounded: int
    evidence_coverage: float
    scoring_status: str
    risk_band: str
    provisional_risk_band: Optional[str] = None
    is_confirmed: bool = Field(..., description="Strictly False when target impact telemetry is missing")
    created_at: datetime


# 7. Advisory Recommendation Schemas
class AdvisoryResponse(BaseModel):
    """Actionable defensive advisory recommendation."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    snapshot_id: str
    recommendation_id: str
    threat_category: str
    priority: str
    action_type: str
    summary: str
    detailed_guidance: str
    missing_evidence_required: List[str] = Field(default_factory=list)
    analyst_validation_required: bool = Field(..., description="Always True for advisory governance")
    is_automated_action: bool = Field(..., description="Always False (advisory only)")
    created_at: datetime


class AdvisoriesListResponse(BaseModel):
    """List of advisories linked to a profile snapshot."""
    snapshot_id: str
    total: int
    items: List[AdvisoryResponse]
