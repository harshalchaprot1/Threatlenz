"""ThreatLenz Phase 6: PostgreSQL Relational Persistence Layer.

Provides normalized SQLAlchemy 2.0 ORM models, transaction management, and
idempotent ingestion for Phase 5 Threat Intelligence reports.

Architectural Safeguards:
1. Strict Relational Normalization: Normalized tables for pipeline runs, threat
   profiles, MITRE ATT&CK mappings, TLRS risk scores, and advisories.
2. Safe Transactionality & Idempotency: Atomic transactions ensure zero partial
   or orphaned records on failure; deterministic keys support replacement or skip.
3. Unconfirmed Intelligence Safeguard: Candidate/unverified MITRE mappings and
   provisional TLRS scores are explicitly flagged with is_confirmed=False.
4. Mandatory Analyst Validation: Advisories strictly require analyst validation
   (analyst_validation_required=True) and prohibit automated remediation.
5. Dialect Compatibility: Uses JSONB with JSON fallback to seamlessly support both
   production PostgreSQL and in-memory SQLite testing.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    event,
    select,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Engine
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    relationship,
    sessionmaker,
)
from sqlalchemy.types import JSON

from src.config import settings
from src.utils import get_logger

logger = get_logger("ThreatLenz.Database")

# Dialect-agnostic JSON type: JSONB on PostgreSQL, JSON on SQLite/others
JSON_VARIANT = JSON().with_variant(JSONB, "postgresql")


class Base(DeclarativeBase):
    """Base class for ThreatLenz declarative SQLAlchemy models."""
    pass


class PipelineRun(Base):
    """Records metadata, provenance, and governance for a pipeline execution."""

    __tablename__ = "pipeline_runs"

    run_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    report_name: Mapped[str] = mapped_column(String(128), nullable=False)
    pipeline_version: Mapped[str] = mapped_column(String(32), nullable=False)
    run_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    execution_duration_seconds: Mapped[float] = mapped_column(Numeric(10, 2), nullable=False)
    dataset_path: Mapped[str] = mapped_column(Text, nullable=False)

    # Source manifest
    source_manifest_hash: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    manifest_files_count: Mapped[int] = mapped_column(Integer, nullable=False)
    manifest_total_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)

    # Evidence provenance
    provenance_type: Mapped[str] = mapped_column(String(64), nullable=False)
    traffic_source: Mapped[str] = mapped_column(String(255), nullable=False)
    is_model_prediction: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_live_detection: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_independently_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Campaign interval
    window_type: Mapped[str] = mapped_column(String(32), nullable=False)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    interval_semantics: Mapped[str] = mapped_column(String(64), nullable=False)

    # Model governance & quarantine
    model_artifact: Mapped[str] = mapped_column(String(255), nullable=False)
    model_status: Mapped[str] = mapped_column(String(64), nullable=False)
    model_quarantine_reason: Mapped[str] = mapped_column(Text, nullable=False)
    model_inference_executed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    model_evaluation_metrics_status: Mapped[str] = mapped_column(String(64), nullable=False)

    # Report summary counts
    total_profiles: Mapped[int] = mapped_column(Integer, nullable=False)
    attack_categories_count: Mapped[int] = mapped_column(Integer, nullable=False)
    benign_categories_count: Mapped[int] = mapped_column(Integer, nullable=False)
    unknown_categories_count: Mapped[int] = mapped_column(Integer, nullable=False)
    target_impact_status: Mapped[str] = mapped_column(String(64), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    profiles: Mapped[List["ThreatProfileRecord"]] = relationship(
        "ThreatProfileRecord",
        back_populates="pipeline_run",
        cascade="all, delete-orphan",
    )


class ThreatProfileRecord(Base):
    """Snapshot record of an aggregated traffic profile for a pipeline run."""

    __tablename__ = "threat_profiles"
    __table_args__ = (
        UniqueConstraint("run_id", "profile_id", name="uq_run_profile"),
        Index("ix_threat_profiles_canonical_label", "canonical_label"),
    )

    snapshot_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    profile_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    run_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("pipeline_runs.run_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source_manifest_hash: Mapped[str] = mapped_column(String(32), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")

    # Time boundaries
    window_type: Mapped[str] = mapped_column(String(32), nullable=False)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Category classification
    canonical_label: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_label: Mapped[str] = mapped_column(String(64), nullable=False)
    attack_status: Mapped[str] = mapped_column(String(32), nullable=False)
    is_attack: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    is_mapped: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Aggregated metrics
    flow_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    total_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    total_packets: Mapped[int] = mapped_column(BigInteger, nullable=False)
    active_observation_units: Mapped[int] = mapped_column(Integer, nullable=False)
    recurrence_denominator: Mapped[int] = mapped_column(Integer, nullable=False)
    recurrence_ratio: Mapped[float] = mapped_column(Numeric(6, 4), nullable=False)

    # Operational gating / reliability
    model_reliability: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    pipeline_run: Mapped["PipelineRun"] = relationship("PipelineRun", back_populates="profiles")
    mitre_mapping: Mapped[Optional["MitreMappingRecord"]] = relationship(
        "MitreMappingRecord",
        back_populates="profile",
        uselist=False,
        cascade="all, delete-orphan",
    )
    risk_assessment: Mapped[Optional["RiskAssessmentRecord"]] = relationship(
        "RiskAssessmentRecord",
        back_populates="profile",
        uselist=False,
        cascade="all, delete-orphan",
    )
    advisories: Mapped[List["AdvisoryRecord"]] = relationship(
        "AdvisoryRecord",
        back_populates="profile",
        cascade="all, delete-orphan",
    )


class MitreMappingRecord(Base):
    """Maps a profile snapshot to an adversary technique from MITRE ATT&CK Enterprise."""

    __tablename__ = "mitre_mappings"

    snapshot_id: Mapped[str] = mapped_column(
        String(32),
        ForeignKey("threat_profiles.snapshot_id", ondelete="CASCADE"),
        primary_key=True,
    )
    canonical_label: Mapped[str] = mapped_column(String(64), nullable=False)
    technique_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    technique_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    tactic: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    mapping_status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)

    # Unconfirmed intelligence safeguard: candidate / unverified mappings are FALSE
    is_confirmed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    rationale: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    missing_telemetry: Mapped[List[str]] = mapped_column(JSON_VARIANT, nullable=False, default=list)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    profile: Mapped["ThreatProfileRecord"] = relationship("ThreatProfileRecord", back_populates="mitre_mapping")


class RiskAssessmentRecord(Base):
    """Threat Level Risk Score (TLRS) assessment for a profile snapshot."""

    __tablename__ = "risk_assessments"

    snapshot_id: Mapped[str] = mapped_column(
        String(32),
        ForeignKey("threat_profiles.snapshot_id", ondelete="CASCADE"),
        primary_key=True,
    )

    # Component dimensions (0 - 100)
    severity_score: Mapped[float] = mapped_column(Numeric(6, 2), nullable=False)
    frequency_score: Mapped[float] = mapped_column(Numeric(6, 2), nullable=False)
    recurrence_score: Mapped[float] = mapped_column(Numeric(6, 2), nullable=False)
    target_impact_score: Mapped[Optional[float]] = mapped_column(Numeric(6, 2), nullable=True)

    # Component weights
    weight_severity: Mapped[float] = mapped_column(Numeric(4, 2), nullable=False, default=0.40)
    weight_frequency: Mapped[float] = mapped_column(Numeric(4, 2), nullable=False, default=0.25)
    weight_recurrence: Mapped[float] = mapped_column(Numeric(4, 2), nullable=False, default=0.20)
    weight_target_impact: Mapped[float] = mapped_column(Numeric(4, 2), nullable=False, default=0.15)

    # Complete vs provisional diagnostic scores
    tlrs_complete: Mapped[Optional[float]] = mapped_column(Numeric(6, 2), nullable=True)
    tlrs_complete_rounded: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    tlrs_partial_diagnostic: Mapped[float] = mapped_column(Numeric(6, 2), nullable=False)
    tlrs_normalized_heuristic: Mapped[float] = mapped_column(Numeric(6, 2), nullable=False)
    tlrs_normalized_rounded: Mapped[int] = mapped_column(Integer, nullable=False)
    evidence_coverage: Mapped[float] = mapped_column(Numeric(4, 2), nullable=False)

    # Qualitative risk classification
    scoring_status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    risk_band: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    provisional_risk_band: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # Unconfirmed intelligence safeguard: provisional scores are NOT confirmed
    is_confirmed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    profile: Mapped["ThreatProfileRecord"] = relationship("ThreatProfileRecord", back_populates="risk_assessment")


class AdvisoryRecord(Base):
    """Defensive advisory recommendation linked to a profile snapshot."""

    __tablename__ = "advisories"
    __table_args__ = (
        UniqueConstraint("snapshot_id", "recommendation_id", name="uq_snapshot_recommendation"),
        Index("ix_advisories_recommendation_id", "recommendation_id"),
        Index("ix_advisories_priority", "priority"),
        Index("ix_advisories_action_type", "action_type"),
    )

    id: Mapped[int] = mapped_column(Integer().with_variant(BigInteger, "postgresql"), primary_key=True, autoincrement=True)
    snapshot_id: Mapped[str] = mapped_column(
        String(32),
        ForeignKey("threat_profiles.snapshot_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    recommendation_id: Mapped[str] = mapped_column(String(64), nullable=False)
    threat_category: Mapped[str] = mapped_column(String(64), nullable=False)
    priority: Mapped[str] = mapped_column(String(16), nullable=False)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    detailed_guidance: Mapped[str] = mapped_column(Text, nullable=False)
    missing_evidence_required: Mapped[List[str]] = mapped_column(JSON_VARIANT, nullable=False, default=list)

    # Mandatory analyst safeguards
    analyst_validation_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_automated_action: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    profile: Mapped["ThreatProfileRecord"] = relationship("ThreatProfileRecord", back_populates="advisories")


# Custom Exceptions
class DuplicateRunError(Exception):
    """Raised when attempting to insert an existing pipeline run and if_exists='error'."""
    pass


class ReportPersistenceError(Exception):
    """Raised when persistence of a threat intelligence report encounters a failure."""
    pass


@event.listens_for(Engine, "connect")
def _set_sqlite_pragma(dbapi_connection: Any, connection_record: Any) -> None:
    """Enforces foreign key constraint checks and cascades when using SQLite."""
    if type(dbapi_connection).__module__.startswith("sqlite3"):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


# Database Connection & Session Management
def get_db_engine(db_url: Optional[str] = None, echo: bool = False) -> Engine:
    """Creates a SQLAlchemy Engine from configured settings or given URL."""
    target_url = db_url or settings.effective_database_url
    return create_engine(target_url, echo=echo, future=True)


def get_db_session(engine: Optional[Engine] = None) -> Session:
    """Returns a new SQLAlchemy Session bound to the target engine."""
    target_engine = engine or get_db_engine()
    session_factory = sessionmaker(bind=target_engine, expire_on_commit=False, future=True)
    return session_factory()


def init_db(engine: Optional[Engine] = None) -> None:
    """Initializes schema tables in the database."""
    target_engine = engine or get_db_engine()
    Base.metadata.create_all(bind=target_engine)
    logger.info("Database schema initialized successfully.")


def parse_iso_datetime(dt_str: str) -> datetime:
    """Parses ISO-8601 string ensuring UTC-aware timestamp."""
    dt = datetime.fromisoformat(dt_str)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# Report Loader & Persistence Service
def load_threat_intelligence_report(
    report_source: Union[str, Path, Dict[str, Any]],
    session: Optional[Session] = None,
    engine: Optional[Engine] = None,
    if_exists: str = "replace",  # 'replace', 'skip', 'error'
) -> PipelineRun:
    """Safely and transactionally persists a Threat Intelligence report.

    Args:
        report_source: File path to report JSON or pre-parsed dictionary.
        session: Optional external SQLAlchemy Session. If None, session is created.
        engine: Optional SQLAlchemy Engine. Used if session is None.
        if_exists: Handling strategy if run_id already exists:
                   - 'replace': Atomically remove existing run and cascade delete children.
                   - 'skip': Gracefully return the existing PipelineRun without modifying data.
                   - 'error': Raise DuplicateRunError.

    Returns:
        PipelineRun: The persisted or existing pipeline run record.

    Raises:
        FileNotFoundError: If the report file does not exist.
        DuplicateRunError: If if_exists='error' and run_id exists.
        ReportPersistenceError: If validation or persistence fails.
    """
    if if_exists not in ("replace", "skip", "error"):
        raise ValueError(f"Invalid if_exists strategy '{if_exists}'. Must be 'replace', 'skip', or 'error'.")

    # 1. Parse report source
    if isinstance(report_source, (str, Path)):
        report_path = Path(report_source)
        if not report_path.exists():
            raise FileNotFoundError(f"Report file not found at {report_path}")
        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    elif isinstance(report_source, dict):
        data = report_source
    else:
        raise TypeError(f"Unsupported report_source type: {type(report_source)}")

    # 2. Extract and validate required metadata
    run_id = data.get("run_id")
    if not run_id:
        raise ReportPersistenceError("Report is missing required 'run_id' field.")

    logger.info("Persisting Threat Intelligence Report for Run ID: %s", run_id)

    # 3. Determine session management
    managed_session = session is None
    active_session = session or get_db_session(engine=engine)

    try:
        # Wrap execution in transaction context
        # If managed_session, session.begin() manages transaction; if external, nested savepoint
        context = active_session.begin() if managed_session else active_session.begin_nested()
        with context:
            # 4. Check for existing run
            existing_run = active_session.get(PipelineRun, run_id)
            if existing_run:
                if if_exists == "skip":
                    logger.info("Pipeline run %s already exists; skipping load.", run_id)
                    return existing_run
                elif if_exists == "error":
                    raise DuplicateRunError(f"Pipeline run '{run_id}' already exists in database.")
                elif if_exists == "replace":
                    logger.info("Pipeline run %s already exists; replacing atomically.", run_id)
                    active_session.delete(existing_run)
                    active_session.flush()

            # 5. Build PipelineRun record
            manifest = data.get("source_manifest", {})
            prov = data.get("evidence_provenance", {})
            interval = prov.get("campaign_interval", {})
            gov = data.get("model_governance", {})
            summary = data.get("summary", {})

            pipeline_run = PipelineRun(
                run_id=run_id,
                report_name=str(data.get("report_name", "ThreatLenz-Phase5-Threat-Intelligence")),
                pipeline_version=str(data.get("pipeline_version", "1.0.0")),
                run_timestamp=parse_iso_datetime(data["timestamp"]),
                execution_duration_seconds=float(data.get("execution_duration_seconds", 0.0)),
                dataset_path=str(data.get("dataset_path", "")),
                source_manifest_hash=str(manifest.get("source_manifest_hash", "")),
                manifest_files_count=int(manifest.get("files_count", 0)),
                manifest_total_bytes=int(manifest.get("total_bytes", 0)),
                provenance_type=str(prov.get("provenance_type", "curated_dataset_flows")),
                traffic_source=str(prov.get("traffic_source", "CSE-CIC-IDS2018 enterprise emulation lab traffic")),
                is_model_prediction=bool(prov.get("is_model_prediction", False)),
                is_live_detection=bool(prov.get("is_live_detection", False)),
                is_independently_verified=bool(prov.get("is_independently_verified", False)),
                window_type=str(interval.get("window_type", "full_campaign")),
                window_start=parse_iso_datetime(interval.get("window_start", "2018-02-14T00:00:00")),
                window_end=parse_iso_datetime(interval.get("window_end", "2018-03-03T00:00:00")),
                interval_semantics=str(interval.get("interval_semantics", "[window_start, window_end) half-open")),
                model_artifact=str(gov.get("model_artifact", "models/pilot_rf_model")),
                model_status=str(gov.get("model_status", "QUARANTINED_TARGET_LEAKAGE")),
                model_quarantine_reason=str(gov.get("quarantine_reason", "")),
                model_inference_executed=bool(gov.get("inference_executed", False)),
                model_evaluation_metrics_status=str(gov.get("evaluation_metrics_status", "QUARANTINED_EXCLUDED_FROM_EVIDENCE")),
                total_profiles=int(summary.get("total_profiles_generated", len(data.get("profiles", [])))),
                attack_categories_count=int(summary.get("attack_categories_count", 0)),
                benign_categories_count=int(summary.get("benign_categories_count", 0)),
                unknown_categories_count=int(summary.get("unknown_categories_count", 0)),
                target_impact_status=str(summary.get("target_impact_status", "MISSING_EVIDENCE_WITHHELD")),
            )
            active_session.add(pipeline_run)
            active_session.flush()

            # 6. Build child profiles, MITRE mappings, risk assessments, and advisories
            raw_profiles = data.get("profiles", [])
            for p_data in raw_profiles:
                cat = p_data.get("category", {})
                canonical_label = str(cat.get("canonical_label", "Unknown"))
                snapshot_id_raw = p_data.get("snapshot_id")
                profile_id_raw = p_data.get("profile_id")
                if not snapshot_id_raw or not profile_id_raw:
                    raise ReportPersistenceError(
                        "Profile record is missing required non-empty 'snapshot_id' or 'profile_id'."
                    )
                snapshot_id = str(snapshot_id_raw)
                profile_id = str(profile_id_raw)

                units = int(p_data.get("active_observation_units", 0))
                denom = int(p_data.get("recurrence_denominator", 8))
                ratio = round(units / denom, 4) if denom > 0 else 0.0

                # Operational reliability status string
                rel_raw = p_data.get("model_reliability")
                if isinstance(rel_raw, dict):
                    rel_val = str(rel_raw.get("status")) if rel_raw.get("status") else None
                elif hasattr(rel_raw, "status"):
                    rel_val = str(rel_raw.status)
                elif isinstance(rel_raw, str):
                    rel_val = rel_raw
                else:
                    rel_val = None

                profile_record = ThreatProfileRecord(
                    snapshot_id=snapshot_id,
                    profile_id=profile_id,
                    run_id=run_id,
                    source_manifest_hash=str(p_data.get("source_manifest_hash", pipeline_run.source_manifest_hash)),
                    schema_version=str(p_data.get("schema_version", "1.0")),
                    window_type=str(p_data.get("window_type", pipeline_run.window_type)),
                    window_start=parse_iso_datetime(p_data.get("window_start", interval.get("window_start", "2018-02-14T00:00:00"))),
                    window_end=parse_iso_datetime(p_data.get("window_end", interval.get("window_end", "2018-03-03T00:00:00"))),
                    canonical_label=canonical_label,
                    raw_label=str(cat.get("raw_label", canonical_label)),
                    attack_status=str(cat.get("attack_status", "UNKNOWN")),
                    is_attack=cat.get("is_attack"),
                    is_mapped=bool(cat.get("is_mapped", True)),
                    flow_count=int(p_data.get("flow_count", 0)),
                    total_bytes=int(p_data.get("total_bytes", 0)),
                    total_packets=int(p_data.get("total_packets", 0)),
                    active_observation_units=units,
                    recurrence_denominator=denom,
                    recurrence_ratio=ratio,
                    model_reliability=rel_val,
                )
                active_session.add(profile_record)
                active_session.flush()

                # MITRE Mapping Record
                mitre = p_data.get("mitre_mapping", {})
                mapping_status = str(mitre.get("mapping_status", "unverified"))
                # Unconfirmed intelligence safeguard: candidate / unverified mappings are NEVER confirmed
                mitre_confirmed = (mapping_status == "verified")

                mitre_record = MitreMappingRecord(
                    snapshot_id=snapshot_id,
                    canonical_label=str(mitre.get("canonical_label", canonical_label)),
                    technique_id=mitre.get("technique_id"),
                    technique_name=mitre.get("technique_name"),
                    tactic=mitre.get("tactic"),
                    mapping_status=mapping_status,
                    is_confirmed=mitre_confirmed,
                    rationale=mitre.get("rationale"),
                    missing_telemetry=mitre.get("missing_telemetry", []),
                )
                active_session.add(mitre_record)

                # Risk Assessment Record
                tlrs = p_data.get("tlrs_result", {})
                comps = tlrs.get("components", {})
                weights = tlrs.get("weights", {})
                scoring_status = str(tlrs.get("scoring_status", "insufficient_evidence"))
                tlrs_complete = tlrs.get("tlrs_complete")

                # Provisional scores are strictly unconfirmed
                tlrs_confirmed = (scoring_status == "complete" and tlrs_complete is not None)

                risk_record = RiskAssessmentRecord(
                    snapshot_id=snapshot_id,
                    severity_score=float(comps.get("severity", 0.0)),
                    frequency_score=float(comps.get("frequency", 0.0)),
                    recurrence_score=float(comps.get("recurrence", 0.0)),
                    target_impact_score=comps.get("target_impact"),  # Preserved as None/NULL
                    weight_severity=float(weights.get("severity", 0.40)),
                    weight_frequency=float(weights.get("frequency", 0.25)),
                    weight_recurrence=float(weights.get("recurrence", 0.20)),
                    weight_target_impact=float(weights.get("target_impact", 0.15)),
                    tlrs_complete=tlrs_complete,
                    tlrs_complete_rounded=tlrs.get("tlrs_complete_rounded"),
                    tlrs_partial_diagnostic=float(tlrs.get("tlrs_partial_diagnostic", 0.0)),
                    tlrs_normalized_heuristic=float(tlrs.get("tlrs_normalized_heuristic", 0.0)),
                    tlrs_normalized_rounded=int(tlrs.get("tlrs_normalized_rounded", 0)),
                    evidence_coverage=float(tlrs.get("evidence_coverage", 0.85)),
                    scoring_status=scoring_status,
                    risk_band=str(tlrs.get("risk_band", "Insufficient Evidence")),
                    provisional_risk_band=tlrs.get("provisional_risk_band"),
                    is_confirmed=tlrs_confirmed,
                )
                active_session.add(risk_record)

                # Defensive Advisories
                raw_advisories = p_data.get("advisories", [])
                for adv in raw_advisories:
                    advisory_record = AdvisoryRecord(
                        snapshot_id=snapshot_id,
                        recommendation_id=str(adv["recommendation_id"]),
                        threat_category=str(adv.get("threat_category", canonical_label)),
                        priority=str(adv.get("priority", "Medium")),
                        action_type=str(adv.get("action_type", "Investigation")),
                        summary=str(adv.get("summary", "")),
                        detailed_guidance=str(adv.get("detailed_guidance", "")),
                        missing_evidence_required=adv.get("missing_evidence_required", []),
                        analyst_validation_required=bool(adv.get("analyst_validation_required", True)),
                        is_automated_action=False,
                    )
                    active_session.add(advisory_record)

            active_session.flush()

        logger.info(
            "Successfully persisted run %s with %d profiles and child records.",
            run_id,
            len(raw_profiles),
        )
        return pipeline_run

    except DuplicateRunError:
        raise
    except Exception as exc:
        logger.error("Failed to persist Threat Intelligence report: %s", exc)
        raise ReportPersistenceError(f"Persistence transaction failed: {exc}") from exc
    finally:
        if managed_session:
            active_session.close()


# Repository Query Helpers
def get_pipeline_run(run_id: str, session: Session) -> Optional[PipelineRun]:
    """Fetches a PipelineRun by run_id."""
    return session.get(PipelineRun, run_id)


def get_latest_pipeline_run(session: Session) -> Optional[PipelineRun]:
    """Fetches the most recently recorded PipelineRun."""
    stmt = select(PipelineRun).order_by(PipelineRun.run_timestamp.desc()).limit(1)
    return session.scalar(stmt)


def list_pipeline_runs(session: Session, limit: int = 20) -> List[PipelineRun]:
    """Lists recent pipeline runs up to limit."""
    stmt = select(PipelineRun).order_by(PipelineRun.run_timestamp.desc()).limit(limit)
    return list(session.scalars(stmt).all())


def get_profiles_for_run(run_id: str, session: Session) -> List[ThreatProfileRecord]:
    """Fetches all threat profiles associated with a run_id."""
    stmt = select(ThreatProfileRecord).where(ThreatProfileRecord.run_id == run_id)
    return list(session.scalars(stmt).all())
