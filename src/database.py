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
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    delete,
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


class AnalyticalConfusionMatrixRecord(Base):
    """Historical evaluated confusion matrix per class for holdout splits."""

    __tablename__ = "analytical_confusion_matrix"
    __table_args__ = (
        CheckConstraint("evaluated_split IN ('validation', 'test')", name="ck_cm_evaluated_split"),
        UniqueConstraint(
            "source_report_hash",
            "evaluated_split",
            "true_label",
            "predicted_label",
            name="uq_confusion_cell",
        ),
        Index("ix_cm_hash_split", "source_report_hash", "evaluated_split"),
        Index("ix_cm_run_id", "run_id"),
        Index("ix_cm_labels", "true_label", "predicted_label"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    source_report_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    report_timestamp: Mapped[str] = mapped_column(String(32), nullable=False)
    pipeline_name: Mapped[str] = mapped_column(String(128), nullable=False)
    model_artifact: Mapped[str] = mapped_column(String(255), nullable=False)
    run_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        ForeignKey("pipeline_runs.run_id", ondelete="SET NULL"),
        nullable=True,
    )
    evaluated_split: Mapped[str] = mapped_column(String(32), nullable=False)
    true_label: Mapped[str] = mapped_column(String(64), nullable=False)
    predicted_label: Mapped[str] = mapped_column(String(64), nullable=False)
    true_label_idx: Mapped[int] = mapped_column(Integer, nullable=False)
    predicted_label_idx: Mapped[int] = mapped_column(Integer, nullable=False)
    raw_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    true_class_support: Mapped[int] = mapped_column(BigInteger, nullable=False)
    normalized_ratio: Mapped[float] = mapped_column(Numeric(8, 4), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


class AnalyticalPortConcentrationRecord(Base):
    """Destination port distribution and concentration per evaluated threat class."""

    __tablename__ = "analytical_port_concentration"
    __table_args__ = (
        UniqueConstraint(
            "source_report_hash",
            "threat_category",
            "destination_port",
            name="uq_port_concentration",
        ),
        Index("ix_port_hash_cat", "source_report_hash", "threat_category"),
        Index("ix_port_run_id", "run_id"),
        Index("ix_port_num", "destination_port"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    source_report_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    report_timestamp: Mapped[str] = mapped_column(String(32), nullable=False)
    report_name: Mapped[str] = mapped_column(String(128), nullable=False)
    dataset_path: Mapped[str] = mapped_column(String(255), nullable=False)
    run_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        ForeignKey("pipeline_runs.run_id", ondelete="SET NULL"),
        nullable=True,
    )
    threat_category: Mapped[str] = mapped_column(String(64), nullable=False)
    destination_port: Mapped[int] = mapped_column(Integer, nullable=False)
    service_name: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    criticality_weight: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    flow_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    total_class_flows: Mapped[int] = mapped_column(BigInteger, nullable=False)
    percentage_within_class: Mapped[float] = mapped_column(Numeric(6, 2), nullable=False)
    has_extreme_concentration: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


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


def compute_file_sha256(filepath: Union[str, Path]) -> str:
    """Computes hexadecimal SHA-256 hash for a given file."""
    import hashlib

    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def ingest_analytical_tables(
    reports_dir: Optional[Union[str, Path]] = None,
    link_run_id: Optional[str] = None,
    session: Optional[Session] = None,
) -> Dict[str, Any]:
    """Ingests analytical confusion matrix and port concentration data.

    Safeguards:
    1. Cryptographic Provenance: Records SHA-256 source_report_hash and exact raw timestamp.
    2. Strict Trust Boundary: run_id defaults to NULL unless link_run_id is explicitly provided
       and passes trustworthiness validation against pipeline_runs.
    3. Safe Normalization: Decimal ratio [0.0, 1.0] for confusion matrix, percentage [0.0, 100.0] for ports.
    4. Idempotent Upsert: Atomic transaction replaces existing rows matching source_report_hash.
    """
    target_dir = Path(reports_dir) if reports_dir else settings.reports_dir
    rf_report_path = target_dir / "clean_per_class_rf_evaluation_report.json"
    spark_report_path = target_dir / "spark_analytics_report.json"

    if not rf_report_path.exists():
        raise FileNotFoundError(f"Missing RF evaluation report at: {rf_report_path}")
    if not spark_report_path.exists():
        raise FileNotFoundError(f"Missing Spark analytics report at: {spark_report_path}")

    rf_hash = compute_file_sha256(rf_report_path)
    spark_hash = compute_file_sha256(spark_report_path)

    with open(rf_report_path, "r", encoding="utf-8") as f:
        rf_data = json.load(f)
    with open(spark_report_path, "r", encoding="utf-8") as f:
        spark_data = json.load(f)

    managed_session = False
    active_session = session
    if active_session is None:
        active_session = get_db_session()
        managed_session = True

    try:
        validated_run_id: Optional[str] = None
        if link_run_id:
            pipeline_run = active_session.get(PipelineRun, link_run_id)
            if not pipeline_run:
                raise ValueError(f"Pipeline run '{link_run_id}' not found in pipeline_runs.")

            import os as _os

            # ── Check 1: RF model artifact must match pipeline_run.model_artifact exactly. ──
            # Normalize both paths: resolve OS separators, strip trailing slash, lowercase.
            rf_model_raw = rf_data.get("model_location", "")
            if not rf_model_raw:
                raise ValueError(
                    "Provenance validation rejected linkage: RF report has no 'model_location' field."
                )
            db_artifact_norm = _os.path.normpath(pipeline_run.model_artifact).replace(_os.sep, "/").lower()
            rf_model_norm = _os.path.normpath(rf_model_raw).replace(_os.sep, "/").lower()
            if db_artifact_norm != rf_model_norm:
                raise ValueError(
                    f"Provenance check 1 failed: pipeline_run.model_artifact "
                    f"'{pipeline_run.model_artifact}' does not match RF report "
                    f"model_location '{rf_model_raw}' after normalization. "
                    f"Linkage rejected."
                )

            # ── Check 2: Spark dataset path must match pipeline_run.dataset_path exactly. ──
            # Both checks must pass; failure of either rejects the entire linkage.
            spark_dataset_raw = spark_data.get("dataset_path", "")
            if not spark_dataset_raw:
                raise ValueError(
                    "Provenance validation rejected linkage: Spark report has no 'dataset_path' field."
                )
            db_dataset_norm = _os.path.normpath(pipeline_run.dataset_path).replace(_os.sep, "/").lower()
            spark_dataset_norm = _os.path.normpath(spark_dataset_raw).replace(_os.sep, "/").lower()
            if db_dataset_norm != spark_dataset_norm:
                raise ValueError(
                    f"Provenance check 2 failed: pipeline_run.dataset_path "
                    f"'{pipeline_run.dataset_path}' does not match Spark report "
                    f"dataset_path '{spark_dataset_raw}' after normalization. "
                    f"Linkage rejected."
                )

            # Both checks passed — safe to associate run_id.
            validated_run_id = link_run_id

        pipeline_name = str(rf_data.get("pipeline_name", ""))
        if not pipeline_name:
            raise ValueError("RF report missing required 'pipeline_name' field.")
        model_artifact = str(rf_data.get("model_location", ""))
        if not model_artifact:
            raise ValueError("RF report missing required 'model_location' field.")
        rf_timestamp_val = str(rf_data.get("timestamp", ""))
        if not rf_timestamp_val:
            raise ValueError("RF report missing required 'timestamp' field.")

        spark_report_name = str(spark_data.get("report_name", ""))
        if not spark_report_name:
            raise ValueError("Spark report missing required 'report_name' field.")
        dataset_path = str(spark_data.get("dataset_path", ""))
        if not dataset_path:
            raise ValueError("Spark report missing required 'dataset_path' field.")
        spark_timestamp_val = str(spark_data.get("timestamp", ""))
        if not spark_timestamp_val:
            raise ValueError("Spark report missing required 'timestamp' field.")

        # Validate RF confusion matrix structure before any insert
        _EXPECTED_CLASSES = 14
        for split in ["validation", "test"]:
            split_key = f"{split}_metrics"
            cm_obj = rf_data.get(split_key, {}).get("confusion_matrix", {})
            class_labels = cm_obj.get("class_labels")
            raw_matrix = cm_obj.get("raw_matrix")
            norm_matrix = cm_obj.get("normalized_matrix")
            if not class_labels or not raw_matrix or not norm_matrix:
                raise ValueError(
                    f"RF report '{split}_metrics.confusion_matrix' is missing "
                    f"'class_labels', 'raw_matrix', or 'normalized_matrix'."
                )
            if len(class_labels) != _EXPECTED_CLASSES:
                raise ValueError(
                    f"RF report '{split}' has {len(class_labels)} classes; expected {_EXPECTED_CLASSES}."
                )
            if len(raw_matrix) != _EXPECTED_CLASSES:
                raise ValueError(
                    f"RF report '{split}' raw_matrix has {len(raw_matrix)} rows; expected {_EXPECTED_CLASSES}."
                )
            if len(norm_matrix) != _EXPECTED_CLASSES:
                raise ValueError(
                    f"RF report '{split}' normalized_matrix has {len(norm_matrix)} rows; expected {_EXPECTED_CLASSES}."
                )
            for row_idx, row in enumerate(raw_matrix):
                if len(row) != _EXPECTED_CLASSES:
                    raise ValueError(
                        f"RF report '{split}' raw_matrix row {row_idx} has {len(row)} columns; expected {_EXPECTED_CLASSES}."
                    )
                for val in row:
                    if int(val) < 0:
                        raise ValueError(
                            f"RF report '{split}' raw_matrix[{row_idx}] contains negative count {val}."
                        )
            for row_idx, row in enumerate(norm_matrix):
                if len(row) != _EXPECTED_CLASSES:
                    raise ValueError(
                        f"RF report '{split}' normalized_matrix row {row_idx} has {len(row)} columns; expected {_EXPECTED_CLASSES}."
                    )

        # Validate Spark port data structure before any insert
        dest_port_analysis = spark_data.get("destination_port_analysis", {})
        if not dest_port_analysis:
            raise ValueError("Spark report missing or empty 'destination_port_analysis'.")
        for cat_name, cat_obj in dest_port_analysis.items():
            if not isinstance(cat_obj, dict):
                raise ValueError(
                    f"Spark report destination_port_analysis['{cat_name}'] is not a dict."
                )
            total_flows = cat_obj.get("total_flows")
            if total_flows is None or int(total_flows) <= 0:
                raise ValueError(
                    f"Spark report category '{cat_name}' has missing or zero total_flows: {total_flows}."
                )
            top_ports = cat_obj.get("top_ports")
            if top_ports is None:
                raise ValueError(
                    f"Spark report category '{cat_name}' missing 'top_ports' key."
                )
            for p in top_ports:
                port_num = p.get("port")
                if port_num is None:
                    raise ValueError(
                        f"Spark report category '{cat_name}' top_ports entry missing 'port' key."
                    )
                if not (0 <= int(port_num) <= 65535):
                    raise ValueError(
                        f"Spark report category '{cat_name}' port {port_num} outside valid range [0, 65535]."
                    )
                pct = p.get("percentage_within_class")
                if pct is None:
                    raise ValueError(
                        f"Spark report category '{cat_name}' port {port_num} missing 'percentage_within_class'."
                    )
                if not (0.0 <= float(pct) <= 100.0):
                    raise ValueError(
                        f"Spark report category '{cat_name}' port {port_num} percentage {pct} outside [0.0, 100.0]."
                    )
                f_count = p.get("flow_count")
                if f_count is None or int(f_count) < 0:
                    raise ValueError(
                        f"Spark report category '{cat_name}' port {port_num} has invalid flow_count: {f_count}."
                    )

        # Atomic transaction: delete existing rows for these report hashes, then insert new
        with active_session.begin_nested():
            active_session.execute(
                delete(AnalyticalConfusionMatrixRecord).where(
                    AnalyticalConfusionMatrixRecord.source_report_hash == rf_hash
                )
            )
            active_session.execute(
                delete(AnalyticalPortConcentrationRecord).where(
                    AnalyticalPortConcentrationRecord.source_report_hash == spark_hash
                )
            )

            # Ingest confusion matrix for validation and test splits
            cm_count = 0
            for split in ["validation", "test"]:
                split_key = f"{split}_metrics"
                cm_obj = rf_data[split_key]["confusion_matrix"]
                class_labels = cm_obj["class_labels"]
                raw_matrix = cm_obj["raw_matrix"]
                norm_matrix = cm_obj["normalized_matrix"]

                for i, true_lbl in enumerate(class_labels):
                    row_raw = raw_matrix[i]
                    row_norm = norm_matrix[i]
                    class_support = sum(row_raw)
                    if class_support < 0:
                        raise ValueError(
                            f"RF report '{split}' class '{true_lbl}' has negative support {class_support}."
                        )

                    for j, pred_lbl in enumerate(class_labels):
                        # No silent zero defaults — both dimensions validated above
                        raw_c = int(row_raw[j])
                        norm_ratio = float(row_norm[j])

                        cm_rec = AnalyticalConfusionMatrixRecord(
                            source_report_hash=rf_hash,
                            report_timestamp=rf_timestamp_val,
                            pipeline_name=pipeline_name,
                            model_artifact=model_artifact,
                            run_id=validated_run_id,
                            evaluated_split=split,
                            true_label=true_lbl,
                            predicted_label=pred_lbl,
                            true_label_idx=i,
                            predicted_label_idx=j,
                            raw_count=raw_c,
                            true_class_support=class_support,
                            normalized_ratio=round(norm_ratio, 4),
                        )
                        active_session.add(cm_rec)
                        cm_count += 1

            # Ingest port concentration
            port_count = 0
            for cat_name, cat_obj in dest_port_analysis.items():
                if not isinstance(cat_obj, dict):
                    continue
                total_flows = int(cat_obj["total_flows"])
                has_extreme = bool(cat_obj.get("has_extreme_port_concentration", False))
                top_ports = cat_obj["top_ports"]

                for p in top_ports:
                    port_num = int(p["port"])
                    svc_name = p.get("service_name")
                    crit_weight = int(p.get("criticality_weight", 50))
                    f_count = int(p["flow_count"])
                    pct_within = float(p["percentage_within_class"])

                    port_rec = AnalyticalPortConcentrationRecord(
                        source_report_hash=spark_hash,
                        report_timestamp=spark_timestamp_val,
                        report_name=spark_report_name,
                        dataset_path=dataset_path,
                        run_id=validated_run_id,
                        threat_category=cat_name,
                        destination_port=port_num,
                        service_name=svc_name,
                        criticality_weight=crit_weight,
                        flow_count=f_count,
                        total_class_flows=total_flows,
                        percentage_within_class=round(pct_within, 2),
                        has_extreme_concentration=has_extreme,
                    )
                    active_session.add(port_rec)
                    port_count += 1

            active_session.flush()

        if managed_session:
            active_session.commit()

        logger.info(
            "Successfully ingested analytical records: %d confusion cells (hash: %s), %d port records (hash: %s). run_id=%s",
            cm_count,
            rf_hash[:12],
            port_count,
            spark_hash[:12],
            validated_run_id,
        )
        return {
            "confusion_matrix_rows": cm_count,
            "port_concentration_rows": port_count,
            "rf_report_hash": rf_hash,
            "spark_report_hash": spark_hash,
            "run_id": validated_run_id,
        }

    except Exception as exc:
        if managed_session:
            active_session.rollback()
        logger.error("Failed to ingest analytical tables: %s", exc)
        raise
    finally:
        if managed_session:
            active_session.close()


