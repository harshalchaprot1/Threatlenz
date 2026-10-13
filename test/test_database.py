"""ThreatLenz Phase 6: PostgreSQL Relational Persistence Tests.

Verifies:
1. Schema normalization, table creation, and foreign key cascade deletion.
2. Safe, transactional, and idempotent ingestion of threat intelligence reports.
3. Preservation of source provenance, run IDs, and quarantined model governance metadata.
4. Preservation of missing target telemetry (target_impact=None, tlrs_complete=None, Insufficient Evidence).
5. Safeguards against treating candidate MITRE mappings or provisional scores as confirmed intelligence.
6. Mandatory analyst validation (analyst_validation_required=True) on all advisories.
7. Transaction rollback on ingestion failure ensuring zero orphan records.
8. Optional live PostgreSQL integration test when PostgreSQL service is available.
"""

from copy import deepcopy
import json
from pathlib import Path
from typing import Any, Dict
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from src.database import (
    AdvisoryRecord,
    Base,
    DuplicateRunError,
    MitreMappingRecord,
    PipelineRun,
    ReportPersistenceError,
    RiskAssessmentRecord,
    ThreatProfileRecord,
    get_latest_pipeline_run,
    get_pipeline_run,
    get_profiles_for_run,
    init_db,
    list_pipeline_runs,
    load_threat_intelligence_report,
)


@pytest.fixture
def sqlite_engine():
    """In-memory SQLite engine for fast, isolated unit tests."""
    engine = create_engine("sqlite:///:memory:", future=True)
    init_db(engine)
    return engine


@pytest.fixture
def sqlite_session(sqlite_engine):
    """Session fixture bound to in-memory SQLite engine."""
    session_factory = sessionmaker(bind=sqlite_engine, expire_on_commit=False, future=True)
    session = session_factory()
    yield session
    session.close()


@pytest.fixture
def sample_report_path() -> Path:
    """Path to the real Phase 5 threat intelligence report."""
    path = Path("reports/threat_intelligence_report.json")
    if not path.exists():
        pytest.skip(f"Report file {path} not found; run pipeline first.")
    return path


@pytest.fixture
def sample_report_data(sample_report_path) -> Dict[str, Any]:
    """Loaded dictionary of the real Phase 5 threat intelligence report."""
    with open(sample_report_path, "r", encoding="utf-8") as f:
        return json.load(f)


# 1. Schema Creation & Table Constraints
def test_schema_tables_and_columns_created(sqlite_engine):
    """Verifies that all 5 normalized tables exist in metadata."""
    table_names = Base.metadata.tables.keys()
    assert "pipeline_runs" in table_names
    assert "threat_profiles" in table_names
    assert "mitre_mappings" in table_names
    assert "risk_assessments" in table_names
    assert "advisories" in table_names


# 2. Real Report Ingestion & Provenance Preservation
def test_load_real_threat_intelligence_report(sqlite_engine, sqlite_session, sample_report_path):
    """Verifies complete ingestion of Phase 5 report and preservation of provenance."""
    loaded_run = load_threat_intelligence_report(
        report_source=sample_report_path,
        session=sqlite_session,
    )
    sqlite_session.commit()

    assert loaded_run.run_id.startswith("run_")
    assert loaded_run.report_name == "ThreatLenz-Phase5-Threat-Intelligence"
    assert loaded_run.pipeline_version == "1.0.0"
    assert loaded_run.source_manifest_hash == "22d6470cfb100c00"
    assert loaded_run.manifest_files_count == 21
    assert loaded_run.manifest_total_bytes == 811664902

    # Evidence provenance
    assert loaded_run.provenance_type == "curated_dataset_flows"
    assert loaded_run.traffic_source == "CSE-CIC-IDS2018 enterprise emulation lab traffic"
    assert loaded_run.is_model_prediction is False
    assert loaded_run.is_live_detection is False
    assert loaded_run.is_independently_verified is False
    assert loaded_run.window_type == "full_campaign"

    # Model governance & quarantine
    assert loaded_run.model_status == "QUARANTINED_TARGET_LEAKAGE"
    assert "label_idx" in loaded_run.model_quarantine_reason
    assert loaded_run.model_inference_executed is False
    assert loaded_run.model_evaluation_metrics_status == "QUARANTINED_EXCLUDED_FROM_EVIDENCE"

    # Summary counts
    assert loaded_run.total_profiles == 14
    assert loaded_run.attack_categories_count == 13
    assert loaded_run.benign_categories_count == 1
    assert loaded_run.unknown_categories_count == 0

    # Query profiles
    profiles = get_profiles_for_run(loaded_run.run_id, sqlite_session)
    assert len(profiles) == 14

    benign_p = next(p for p in profiles if p.canonical_label == "Benign")
    assert benign_p.is_attack is False
    assert benign_p.flow_count == 5064128
    assert benign_p.active_observation_units == 8
    assert benign_p.recurrence_denominator == 8
    assert float(benign_p.recurrence_ratio) == 1.0
    assert benign_p.model_reliability is None

    bot_p = next(p for p in profiles if p.canonical_label == "Bot")
    assert bot_p.is_attack is True
    assert bot_p.flow_count == 286191
    assert bot_p.active_observation_units == 1
    assert bot_p.recurrence_denominator == 8
    assert float(bot_p.recurrence_ratio) == 0.125
    assert bot_p.model_reliability is None


# 3. Missing Evidence & Insufficient Evidence Status Preservation
def test_preservation_of_missing_evidence_and_provisional_scores(sqlite_session, sample_report_path):
    """Verifies that missing target impact results in NULL scores and unconfirmed status."""
    load_threat_intelligence_report(sample_report_path, session=sqlite_session)
    sqlite_session.commit()

    assessments = list(sqlite_session.scalars(select(RiskAssessmentRecord)).all())
    assert len(assessments) == 14

    for ra in assessments:
        # Destination asset criticality was missing; must remain NULL
        assert ra.target_impact_score is None
        assert ra.tlrs_complete is None
        assert ra.tlrs_complete_rounded is None

        # Evidence coverage and status
        assert float(ra.evidence_coverage) == 0.85
        assert ra.scoring_status == "insufficient_evidence"
        assert ra.risk_band == "Insufficient Evidence"
        assert "DIAGNOSTIC_ONLY" in (ra.provisional_risk_band or "")

        # Crucial safeguard: provisional score is NEVER confirmed intelligence
        assert ra.is_confirmed is False


# 4. MITRE Technique Candidate Mapping Safeguards
def test_unconfirmed_mitre_mapping_safeguard(sqlite_session, sample_report_path):
    """Verifies that candidate and unverified MITRE mappings have is_confirmed=False."""
    load_threat_intelligence_report(sample_report_path, session=sqlite_session)
    sqlite_session.commit()

    mappings = list(sqlite_session.scalars(select(MitreMappingRecord)).all())
    assert len(mappings) == 14

    for m in mappings:
        # In Phase 4/5, all mappings are candidate, unverified, or not_applicable
        assert m.mapping_status in ("candidate", "unverified", "not_applicable")
        # None can be treated as confirmed intelligence
        assert m.is_confirmed is False

    # Check specific mappings
    bot_m = next(m for m in mappings if m.canonical_label == "Bot")
    assert bot_m.technique_id == "T1071.001"
    assert bot_m.mapping_status == "unverified"
    assert len(bot_m.missing_telemetry) > 0

    hoic_m = next(m for m in mappings if m.canonical_label == "DDoS-HOIC")
    assert hoic_m.technique_id == "T1498.001"
    assert hoic_m.mapping_status == "candidate"


# 5. Mandatory Analyst Validation on All Advisories
def test_mandatory_analyst_validation_on_all_advisories(sqlite_session, sample_report_path):
    """Verifies that 100% of persisted advisories require analyst validation."""
    load_threat_intelligence_report(sample_report_path, session=sqlite_session)
    sqlite_session.commit()

    advisories = list(sqlite_session.scalars(select(AdvisoryRecord)).all())
    assert len(advisories) == 27  # 1 for Benign + 2 * 13 attacks

    for adv in advisories:
        assert adv.analyst_validation_required is True
        assert adv.is_automated_action is False
        assert len(adv.recommendation_id) > 0
        assert len(adv.summary) > 0
        assert len(adv.detailed_guidance) > 0


# 6. Idempotent Ingestion Behavior
def test_idempotent_replace_behavior(sqlite_session, sample_report_path):
    """Verifies that reloading with if_exists='replace' updates cleanly without duplicating rows."""
    load_threat_intelligence_report(sample_report_path, session=sqlite_session, if_exists="replace")
    sqlite_session.commit()

    # Second load with replace
    load_threat_intelligence_report(sample_report_path, session=sqlite_session, if_exists="replace")
    sqlite_session.commit()

    assert len(list(sqlite_session.scalars(select(PipelineRun)).all())) == 1
    assert len(list(sqlite_session.scalars(select(ThreatProfileRecord)).all())) == 14
    assert len(list(sqlite_session.scalars(select(MitreMappingRecord)).all())) == 14
    assert len(list(sqlite_session.scalars(select(RiskAssessmentRecord)).all())) == 14
    assert len(list(sqlite_session.scalars(select(AdvisoryRecord)).all())) == 27


def test_idempotent_skip_behavior(sqlite_session, sample_report_path):
    """Verifies that reloading with if_exists='skip' gracefully returns existing record."""
    run1 = load_threat_intelligence_report(sample_report_path, session=sqlite_session, if_exists="replace")
    sqlite_session.commit()

    run2 = load_threat_intelligence_report(sample_report_path, session=sqlite_session, if_exists="skip")
    assert run1.run_id == run2.run_id

    assert len(list(sqlite_session.scalars(select(PipelineRun)).all())) == 1
    assert len(list(sqlite_session.scalars(select(ThreatProfileRecord)).all())) == 14


def test_duplicate_error_behavior(sqlite_session, sample_report_path):
    """Verifies that reloading with if_exists='error' raises DuplicateRunError."""
    load_threat_intelligence_report(sample_report_path, session=sqlite_session, if_exists="replace")
    sqlite_session.commit()

    with pytest.raises(DuplicateRunError):
        load_threat_intelligence_report(sample_report_path, session=sqlite_session, if_exists="error")


# 7. Transaction Rollback on Failure (Zero Orphan Records)
def test_transaction_atomic_rollback_on_failure(sqlite_session, sample_report_data):
    """Verifies that a failure during profile ingestion aborts the entire transaction."""
    corrupted_data = deepcopy(sample_report_data)
    corrupted_data["run_id"] = "run_corrupted_test_999"

    # Inject an invalid record that violates NOT NULL constraint or type
    corrupted_data["profiles"][2]["snapshot_id"] = None

    with pytest.raises(ReportPersistenceError):
        load_threat_intelligence_report(corrupted_data, session=sqlite_session)

    # Roll back session and verify zero rows were committed for the corrupted run
    sqlite_session.rollback()
    orphan_run = sqlite_session.get(PipelineRun, "run_corrupted_test_999")
    assert orphan_run is None

    orphan_profiles = list(sqlite_session.scalars(
        select(ThreatProfileRecord).where(ThreatProfileRecord.run_id == "run_corrupted_test_999")
    ).all())
    assert len(orphan_profiles) == 0


# 8. Foreign Key Cascade Deletion
def test_foreign_key_cascade_deletion(sqlite_session, sample_report_path):
    """Verifies that deleting a PipelineRun cascades to all profiles and child records."""
    pipeline_run = load_threat_intelligence_report(sample_report_path, session=sqlite_session)
    sqlite_session.commit()

    run_id = pipeline_run.run_id
    sqlite_session.delete(pipeline_run)
    sqlite_session.commit()

    assert sqlite_session.get(PipelineRun, run_id) is None
    assert len(list(sqlite_session.scalars(select(ThreatProfileRecord)).all())) == 0
    assert len(list(sqlite_session.scalars(select(MitreMappingRecord)).all())) == 0
    assert len(list(sqlite_session.scalars(select(RiskAssessmentRecord)).all())) == 0
    assert len(list(sqlite_session.scalars(select(AdvisoryRecord)).all())) == 0


# 9. Repository Helpers
def test_repository_query_helpers(sqlite_session, sample_report_path):
    """Verifies get_pipeline_run, get_latest_pipeline_run, and list_pipeline_runs."""
    run = load_threat_intelligence_report(sample_report_path, session=sqlite_session)
    sqlite_session.commit()

    fetched = get_pipeline_run(run.run_id, sqlite_session)
    assert fetched is not None
    assert fetched.run_id == run.run_id

    latest = get_latest_pipeline_run(sqlite_session)
    assert latest is not None
    assert latest.run_id == run.run_id

    runs = list_pipeline_runs(sqlite_session, limit=10)
    assert len(runs) == 1
    assert runs[0].run_id == run.run_id


# 10. Live PostgreSQL Integration Test (Conditional)
def test_live_postgresql_integration(sample_report_path):
    """Tests live PostgreSQL execution if localhost:5432 is running with test DB."""
    import psycopg2

    pg_url = "postgresql+psycopg2://postgres:admin@localhost:5432/threatlenz"
    try:
        # Check connection first with short timeout
        conn = psycopg2.connect(host="localhost", port=5432, user="postgres", password="admin", dbname="threatlenz", connect_timeout=2)
        conn.close()
    except Exception as exc:
        pytest.skip(f"Live PostgreSQL not reachable or credentials differ: {exc}")

    pg_engine = create_engine(pg_url, future=True)
    init_db(pg_engine)

    SessionLocal = sessionmaker(bind=pg_engine, expire_on_commit=False, future=True)
    with SessionLocal() as session:
        # Ingest report into actual PostgreSQL
        loaded_run = load_threat_intelligence_report(
            sample_report_path,
            session=session,
            if_exists="replace",
        )
        session.commit()

        assert loaded_run.run_id.startswith("run_")
        assert loaded_run.total_profiles == 14

        profiles = get_profiles_for_run(loaded_run.run_id, session)
        assert len(profiles) == 14

        # Verify PostgreSQL JSONB column storage
        bot_m = session.get(MitreMappingRecord, next(p.snapshot_id for p in profiles if p.canonical_label == "Bot"))
        assert bot_m is not None
        assert isinstance(bot_m.missing_telemetry, list)
        assert len(bot_m.missing_telemetry) > 0
