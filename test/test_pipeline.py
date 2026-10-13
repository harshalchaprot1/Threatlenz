"""Unit and integration tests for ThreatLenz Phase 5 Pipeline Orchestrator."""

import shutil
from pathlib import Path
import pytest
from pyspark.sql import SparkSession
from pyspark.sql.types import DoubleType, IntegerType, StringType, StructField, StructType

from src.config import settings
from src.pipeline import (
    CAMPAIGN_WINDOW_END,
    CAMPAIGN_WINDOW_START,
    build_threat_profile,
    extract_flow_aggregates,
    generate_threat_profiles,
    run_threat_intelligence,
)
from src.threat_intel import (
    ContentManifestGenerator,
    is_timestamp_in_window,
)
from src.tlrs import TLRSEngine, round_half_up
from src.utils import get_spark_session, load_json_report


@pytest.fixture(scope="session")
def spark() -> SparkSession:
    """Provides a shared local SparkSession for pipeline tests."""
    return get_spark_session(
        app_name="ThreatLenz-Pipeline-Tests",
        master="local[2]",
        driver_memory="2g",
        shuffle_partitions=2,
    )


def test_extract_flow_aggregates_rounding_and_precision(spark: SparkSession):
    """Verify that flow aggregation applies established Round Half-Up on DoubleType sums.

    Ensures that floating-point values are rounded without silent integer truncation.
    """
    schema = StructType([
        StructField("label", StringType(), True),
        StructField("tot_fwd_pkts", DoubleType(), True),
        StructField("tot_bwd_pkts", DoubleType(), True),
        StructField("totlen_fwd_pkts", DoubleType(), True),
        StructField("totlen_bwd_pkts", DoubleType(), True),
        StructField("event_date", StringType(), True),
        StructField("timestamp", StringType(), True),
    ])

    data = [
        # Benign: bytes = 100.4 + 50.1 = 150.5 -> rounds half-up to 151
        # packets = 2.0 + 1.0 = 3.0 -> 3
        {
            "label": "Benign",
            "tot_fwd_pkts": 2.0,
            "tot_bwd_pkts": 1.0,
            "totlen_fwd_pkts": 100.4,
            "totlen_bwd_pkts": 50.1,
            "event_date": "2018-02-14",
            "timestamp": "14/02/2018 08:30:00",
        },
        # Benign on second date: bytes = 200.0 + 0.0 = 200.0
        # total Benign bytes = 150.5 + 200.0 = 350.5 -> rounds half-up to 351
        {
            "label": "Benign",
            "tot_fwd_pkts": 1.0,
            "tot_bwd_pkts": 0.0,
            "totlen_fwd_pkts": 200.0,
            "totlen_bwd_pkts": 0.0,
            "event_date": "2018-02-15",
            "timestamp": "15/02/2018 09:00:00",
        },
        # Bot: bytes = 50.2 + 40.2 = 90.4 -> rounds half-up to 90
        # packets = 1.0 + 1.0 = 2.0 -> 2
        {
            "label": "Bot",
            "tot_fwd_pkts": 1.0,
            "tot_bwd_pkts": 1.0,
            "totlen_fwd_pkts": 50.2,
            "totlen_bwd_pkts": 40.2,
            "event_date": "2018-03-02",
            "timestamp": "02/03/2018 10:15:00",
        },
    ]

    df = spark.createDataFrame(data, schema=schema)
    aggregates = extract_flow_aggregates(df, window_type="full_campaign")

    assert len(aggregates) == 2
    benign_agg = next(a for a in aggregates if a["label"] == "Benign")
    bot_agg = next(a for a in aggregates if a["label"] == "Bot")

    # Flow counts
    assert benign_agg["flow_count"] == 2
    assert bot_agg["flow_count"] == 1

    # Exact packet and byte calculations using round_half_up
    assert benign_agg["total_packets"] == 4  # 3 + 1
    assert benign_agg["total_bytes"] == 351  # 150.5 + 200.0 = 350.5 -> 351
    assert bot_agg["total_packets"] == 2
    assert bot_agg["total_bytes"] == 90  # 90.4 -> 90

    # Observation units (distinct event_dates)
    assert benign_agg["active_observation_units"] == 2
    assert bot_agg["active_observation_units"] == 1

    # Timestamps
    assert benign_agg["first_seen_timestamp"] == "14/02/2018 08:30:00"
    assert benign_agg["last_seen_timestamp"] == "15/02/2018 09:00:00"


def test_extract_flow_aggregates_missing_columns_validation(spark: SparkSession):
    """Verify ValueError is raised when required aggregation columns are missing."""
    schema = StructType([
        StructField("label", StringType(), True),
        StructField("flow_count", IntegerType(), True),
    ])
    df = spark.createDataFrame([{"label": "Benign", "flow_count": 1}], schema=schema)

    with pytest.raises(ValueError, match="missing required aggregation columns"):
        extract_flow_aggregates(df)


def test_campaign_window_interval_and_half_open_boundaries():
    """Verify that CAMPAIGN_WINDOW_START and CAMPAIGN_WINDOW_END define a valid half-open interval.

    Encloses all observed campaign flows (Feb 14 through Mar 2) under [start, end).
    """
    assert CAMPAIGN_WINDOW_START == "2018-02-14T00:00:00"
    assert CAMPAIGN_WINDOW_END == "2018-03-03T00:00:00"

    # Start boundary (exact start of first campaign day)
    assert is_timestamp_in_window("2018-02-14 00:00:00", CAMPAIGN_WINDOW_START, CAMPAIGN_WINDOW_END) is True

    # Interior campaign points
    assert is_timestamp_in_window("2018-02-21 12:00:00", CAMPAIGN_WINDOW_START, CAMPAIGN_WINDOW_END) is True
    assert is_timestamp_in_window("2018-03-02 23:59:59", CAMPAIGN_WINDOW_START, CAMPAIGN_WINDOW_END) is True

    # Exclusive boundary: March 3 00:00:00 must be Excluded
    assert is_timestamp_in_window("2018-03-03 00:00:00", CAMPAIGN_WINDOW_START, CAMPAIGN_WINDOW_END) is False

    # Pre-campaign timestamp: Feb 13 23:59:59 must be Excluded
    assert is_timestamp_in_window("2018-02-13 23:59:59", CAMPAIGN_WINDOW_START, CAMPAIGN_WINDOW_END) is False


def test_recurrence_calculation_consistency():
    """Verify that distinct active_observation_units directly matches TLRSEngine recurrence score across H=8."""
    # 2 distinct active dates for Infiltration (Feb 28 and Mar 1)
    rec_2 = TLRSEngine.calculate_recurrence_score(active_observation_units=2, window_type="full_campaign")
    assert pytest.approx(rec_2, 1e-4) == 25.0

    # 8 distinct active dates for Benign
    rec_8 = TLRSEngine.calculate_recurrence_score(active_observation_units=8, window_type="full_campaign")
    assert pytest.approx(rec_8, 1e-4) == 100.0

    # 1 distinct active date for single-day attack (Bot)
    rec_1 = TLRSEngine.calculate_recurrence_score(active_observation_units=1, window_type="full_campaign")
    assert pytest.approx(rec_1, 1e-4) == 12.5


def test_evidence_provenance_and_model_reliability_none():
    """Verify ThreatProfile construction sets source_type='curated_dataset_flows' and model_reliability=None."""
    agg = {
        "label": "Bot",
        "flow_count": 1000,
        "total_bytes": 50000,
        "total_packets": 2000,
        "active_observation_units": 1,
        "first_seen_timestamp": "02/03/2018 00:00:00",
        "last_seen_timestamp": "02/03/2018 23:59:59",
    }

    profile = build_threat_profile(
        agg=agg,
        manifest_hash="abc123def456",
        run_id="run_test_001",
        window_type="full_campaign",
    )

    # Provenance
    assert profile.category.canonical_label == "Bot"
    assert profile.category.attack_status == "ATTACK"
    assert profile.category.is_attack is True

    # Window bounds
    assert profile.window_start == CAMPAIGN_WINDOW_START
    assert profile.window_end == CAMPAIGN_WINDOW_END

    # Deterministic IDs
    assert len(profile.profile_id) == 16
    assert len(profile.snapshot_id) == 16

    # Model reliability must be None for dataset ground-truth profiles
    assert profile.model_reliability is None

    # Advisory generation
    assert len(profile.advisories) > 0
    for adv in profile.advisories:
        assert adv["analyst_validation_required"] is True


def test_missing_target_impact_and_tlrs_contract():
    """Verify TLRS produces 'insufficient_evidence' and operational risk_band is withheld."""
    agg = {
        "label": "DDoS-HOIC",
        "flow_count": 50000,
        "total_bytes": 1000000,
        "total_packets": 20000,
        "active_observation_units": 1,
        "first_seen_timestamp": "21/02/2018 00:00:00",
        "last_seen_timestamp": "21/02/2018 23:59:59",
    }

    profile = build_threat_profile(
        agg=agg,
        manifest_hash="test_manifest",
        run_id="test_run",
    )

    tlrs = profile.tlrs_result
    assert tlrs is not None
    assert tlrs["components"]["target_impact"] is None
    assert tlrs["tlrs_complete"] is None
    assert tlrs["evidence_coverage"] == 0.85
    assert tlrs["scoring_status"] == "insufficient_evidence"
    assert tlrs["risk_band"] == "Insufficient Evidence"
    assert "DIAGNOSTIC_ONLY" in tlrs["provisional_risk_band"]

    # Must contain missing target impact advisory
    assert any(a["action_type"] == "Telemetry Enrichment" and "asset" in a["summary"].lower() for a in profile.advisories)


def test_advisory_analyst_validation_safeguard():
    """Verify that all generated advisory recommendations enforce analyst_validation_required=True."""
    agg = {
        "label": "SSH-BruteForce",
        "flow_count": 500,
        "total_bytes": 25000,
        "total_packets": 1000,
        "active_observation_units": 1,
        "first_seen_timestamp": "14/02/2018 00:00:00",
        "last_seen_timestamp": "14/02/2018 23:59:59",
    }

    profile = build_threat_profile(
        agg=agg,
        manifest_hash="manifest_test",
        run_id="run_001",
    )

    for adv in profile.advisories:
        assert adv["analyst_validation_required"] is True
        # Ensure purely defensive guidance, no automated blocking
        assert "iptables" not in adv["detailed_guidance"].lower()
        assert "block" not in adv["summary"].lower()


def test_deterministic_manifest_and_identity_contracts(tmp_path: Path):
    """Verify ContentManifestGenerator, compute_profile_id, and compute_snapshot_id are deterministic."""
    # Create two temporary test files
    f1 = tmp_path / "part_1.txt"
    f2 = tmp_path / "part_2.txt"
    f1.write_text("dataset content 1", encoding="utf-8")
    f2.write_text("dataset content 2", encoding="utf-8")

    manifest_1 = ContentManifestGenerator.generate_manifest(tmp_path)
    manifest_2 = ContentManifestGenerator.generate_manifest(tmp_path)

    assert manifest_1.source_manifest_hash == manifest_2.source_manifest_hash
    assert manifest_1.files_count == 2

    # Profiles with identical inputs produce identical profile_id
    agg = {
        "label": "FTP-BruteForce",
        "flow_count": 200,
        "total_bytes": 10000,
        "total_packets": 500,
        "active_observation_units": 1,
    }
    p1 = build_threat_profile(agg, manifest_1.source_manifest_hash, run_id="run_fixed")
    p2 = build_threat_profile(agg, manifest_1.source_manifest_hash, run_id="run_fixed")

    assert p1.profile_id == p2.profile_id
    assert p1.snapshot_id == p2.snapshot_id


def test_missing_parquet_error_handling():
    """Verify FileNotFoundError is raised when target Parquet dataset does not exist."""
    non_existent = Path("data/processed/non_existent_flows.parquet")
    with pytest.raises(FileNotFoundError, match="Curated Parquet dataset not found"):
        run_threat_intelligence(parquet_path=non_existent)


def test_end_to_end_threat_intelligence_smoke(spark: SparkSession, tmp_path: Path):
    """End-to-end smoke test executing run_threat_intelligence over a small synthetic Parquet fixture."""
    test_parquet_dir = tmp_path / "test_flows.parquet"
    test_report_file = tmp_path / "threat_intelligence_report.json"

    # Write small partitioned synthetic dataset
    schema = StructType([
        StructField("label", StringType(), True),
        StructField("tot_fwd_pkts", DoubleType(), True),
        StructField("tot_bwd_pkts", DoubleType(), True),
        StructField("totlen_fwd_pkts", DoubleType(), True),
        StructField("totlen_bwd_pkts", DoubleType(), True),
        StructField("event_date", StringType(), True),
        StructField("timestamp", StringType(), True),
    ])

    test_data = [
        {"label": "Benign", "tot_fwd_pkts": 2.0, "tot_bwd_pkts": 1.0, "totlen_fwd_pkts": 100.0, "totlen_bwd_pkts": 50.0, "event_date": "2018-02-14", "timestamp": "14/02/2018 08:00:00"},
        {"label": "Benign", "tot_fwd_pkts": 1.0, "tot_bwd_pkts": 0.0, "totlen_fwd_pkts": 80.0, "totlen_bwd_pkts": 0.0, "event_date": "2018-02-15", "timestamp": "15/02/2018 09:00:00"},
        {"label": "DDoS-HOIC", "tot_fwd_pkts": 5.0, "tot_bwd_pkts": 2.0, "totlen_fwd_pkts": 500.0, "totlen_bwd_pkts": 200.0, "event_date": "2018-02-21", "timestamp": "21/02/2018 10:00:00"},
        {"label": "Bot", "tot_fwd_pkts": 3.0, "tot_bwd_pkts": 1.0, "totlen_fwd_pkts": 300.0, "totlen_bwd_pkts": 100.0, "event_date": "2018-03-02", "timestamp": "02/03/2018 11:00:00"},
    ]

    df = spark.createDataFrame(test_data, schema=schema)
    df.write.mode("overwrite").partitionBy("event_date").parquet(str(test_parquet_dir))

    # Execute Phase 5 Pipeline
    report = run_threat_intelligence(
        spark=spark,
        parquet_path=test_parquet_dir,
        output_path=test_report_file,
        run_id="run_smoke_test",
    )

    # 1. Assert return dict
    assert report["report_name"] == "ThreatLenz-Phase5-Threat-Intelligence"
    assert report["run_id"] == "run_smoke_test"
    assert report["summary"]["total_profiles_generated"] == 3
    assert report["summary"]["attack_categories_count"] == 2  # DDoS-HOIC and Bot
    assert report["summary"]["benign_categories_count"] == 1  # Benign

    # 2. Assert model governance records quarantine
    assert report["model_governance"]["model_status"] == "QUARANTINED_TARGET_LEAKAGE"
    assert report["model_governance"]["inference_executed"] is False

    # 3. Assert on-disk report was saved and reloads correctly
    assert test_report_file.exists()
    loaded_report = load_json_report(test_report_file)
    assert loaded_report["run_id"] == "run_smoke_test"
    assert len(loaded_report["profiles"]) == 3
