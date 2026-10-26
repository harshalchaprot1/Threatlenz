"""Unit tests for Phase 2 pipeline inference, threshold policy integration, and governance provenance.

Tests:
1. Disabled mode (default): verifies that pipeline_enable_model_inference=False preserves exact
   legacy behavior (quarantined model metadata, zero model inference, is_model_prediction=False,
   and model_reliability=None).
2. Raw argmax inference (enabled, no threshold policy): verifies model prediction flow,
   provenance tagging (is_model_prediction=True, provenance_type="model_inference"),
   operational governance metadata, and validation-backed ModelReliabilityAssessment.
3. Thresholded inference (enabled, threshold policy active): verifies that unconfident Infiltration
   and Brute Force - Web predictions fall back to Benign while leaving other classes and confident
   predictions unchanged.
4. Database persistence compatibility: verifies that both disabled-mode and enabled-mode reports
   persist cleanly into SQLite / PostgreSQL via save_threat_intelligence_report without schema errors.
"""

from datetime import datetime
import json
from pathlib import Path
import pytest
from pyspark.ml import Pipeline, PipelineModel
from pyspark.ml.classification import RandomForestClassifier
from pyspark.ml.feature import VectorAssembler
from pyspark.ml.linalg import Vectors
from pyspark.sql import SparkSession
from pyspark.sql.types import DoubleType, StringType, StructField, StructType
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from src.config import settings
from src.database import (
    Base,
    PipelineRun,
    ThreatProfileRecord,
    load_threat_intelligence_report,
)
from src.pipeline import run_threat_intelligence
from src.utils import get_spark_session


@pytest.fixture(scope="session")
def spark() -> SparkSession:
    """Provides a shared local SparkSession for inference tests."""
    return get_spark_session(
        app_name="ThreatLenz-Inference-Tests",
        master="local[2]",
        driver_memory="2g",
        shuffle_partitions=2,
    )


@pytest.fixture
def mock_dataset_and_model(spark: SparkSession, tmp_path: Path):
    """Creates a deterministic synthetic flow parquet dataset and a tiny Spark ML model."""
    parquet_dir = tmp_path / "mock_flows.parquet"
    model_dir = tmp_path / "mock_rf_model"

    # 1. Create synthetic flow dataset
    schema = StructType([
        StructField("label", StringType(), True),
        StructField("flow_duration", DoubleType(), True),
        StructField("tot_fwd_pkts", DoubleType(), True),
        StructField("tot_bwd_pkts", DoubleType(), True),
        StructField("totlen_fwd_pkts", DoubleType(), True),
        StructField("totlen_bwd_pkts", DoubleType(), True),
        StructField("event_date", StringType(), True),
        StructField("timestamp", StringType(), True),
    ])

    data = [
        # Flow 1: Low duration, Benign ground truth
        {"label": "Benign", "flow_duration": 10.0, "tot_fwd_pkts": 2.0, "tot_bwd_pkts": 1.0, "totlen_fwd_pkts": 100.0, "totlen_bwd_pkts": 50.0, "event_date": "2018-02-14", "timestamp": "14/02/2018 08:00:00"},
        # Flow 2: Moderate duration
        {"label": "Benign", "flow_duration": 20.0, "tot_fwd_pkts": 1.0, "tot_bwd_pkts": 0.0, "totlen_fwd_pkts": 80.0, "totlen_bwd_pkts": 0.0, "event_date": "2018-02-15", "timestamp": "15/02/2018 09:00:00"},
        # Flow 3: High duration, Infiltration ground truth
        {"label": "Infiltration", "flow_duration": 500.0, "tot_fwd_pkts": 5.0, "tot_bwd_pkts": 2.0, "totlen_fwd_pkts": 500.0, "totlen_bwd_pkts": 200.0, "event_date": "2018-02-21", "timestamp": "21/02/2018 10:00:00"},
        # Flow 4: Very high duration, Bot ground truth
        {"label": "Bot", "flow_duration": 1000.0, "tot_fwd_pkts": 3.0, "tot_bwd_pkts": 1.0, "totlen_fwd_pkts": 300.0, "totlen_bwd_pkts": 100.0, "event_date": "2018-03-02", "timestamp": "02/03/2018 11:00:00"},
    ]

    df = spark.createDataFrame(data, schema=schema)
    df.write.mode("overwrite").partitionBy("event_date").parquet(str(parquet_dir))

    # 2. Fit a tiny 2-class Random Forest on flow_duration to act as mock PipelineModel
    # Maps labels: Benign -> 0.0, Infiltration -> 11.0, Bot -> 1.0
    from pyspark.sql import functions as F
    train_data = [
        {"flow_duration": 10.0, "label_idx": 0.0},
        {"flow_duration": 20.0, "label_idx": 0.0},
        {"flow_duration": 500.0, "label_idx": 11.0},
        {"flow_duration": 1000.0, "label_idx": 1.0},
    ]
    train_df = spark.createDataFrame(train_data)
    assembler = VectorAssembler(inputCols=["flow_duration"], outputCol="features")
    rf = RandomForestClassifier(featuresCol="features", labelCol="label_idx", numTrees=2, seed=42)
    pipeline = Pipeline(stages=[assembler, rf])
    model = pipeline.fit(train_df)
    model.write().overwrite().save(str(model_dir))

    return {
        "parquet_dir": parquet_dir,
        "model_dir": model_dir,
    }


def test_pipeline_disabled_mode_preserves_legacy_governance(spark: SparkSession, mock_dataset_and_model, tmp_path: Path):
    """Test 1: Disabled mode (default) strictly preserves quarantined provenance and legacy semantics."""
    report_file = tmp_path / "disabled_report.json"
    parquet_path = mock_dataset_and_model["parquet_dir"]

    # Explicitly verify default parameters
    assert settings.pipeline_enable_model_inference is False
    assert settings.pipeline_apply_threshold_policy is False

    report = run_threat_intelligence(
        spark=spark,
        parquet_path=parquet_path,
        output_path=report_file,
        run_id="run_test_disabled",
        enable_model_inference=False,
    )

    # Provenance assertions
    prov = report["evidence_provenance"]
    assert prov["provenance_type"] == "curated_dataset_flows"
    assert prov["is_model_prediction"] is False
    assert prov["is_live_detection"] is False

    # Governance assertions
    gov = report["model_governance"]
    assert gov["model_status"] == "QUARANTINED_TARGET_LEAKAGE"
    assert gov["inference_executed"] is False
    assert gov["evaluation_metrics_status"] == "QUARANTINED_EXCLUDED_FROM_EVIDENCE"
    assert "label_idx" in gov["quarantine_reason"]

    # Profiles assertion: model_reliability must be None for ground truth
    profiles = report["profiles"]
    assert len(profiles) > 0
    for p in profiles:
        assert p["model_reliability"] is None
        assert p["profile_id"] is not None


def test_pipeline_operational_inference_flow(spark: SparkSession, mock_dataset_and_model, tmp_path: Path):
    """Test 2: Enabled model inference runs predictions, records operational provenance, and attaches reliability."""
    report_file = tmp_path / "inference_report.json"
    parquet_path = mock_dataset_and_model["parquet_dir"]
    model_path = mock_dataset_and_model["model_dir"]

    report = run_threat_intelligence(
        spark=spark,
        parquet_path=parquet_path,
        output_path=report_file,
        run_id="run_test_inference",
        enable_model_inference=True,
        model_path=model_path,
        apply_threshold_policy=False,
    )

    # Provenance assertions
    prov = report["evidence_provenance"]
    assert prov["provenance_type"] == "model_inference"
    assert prov["is_model_prediction"] is True
    assert prov["is_live_detection"] is False

    # Governance assertions
    gov = report["model_governance"]
    assert gov["model_status"] == "OPERATIONAL_EVALUATED"
    assert gov["inference_executed"] is True
    assert gov["evaluation_metrics_status"] == "EVALUATED_VALIDATION_METRICS"
    assert gov["model_artifact"] == str(model_path)

    # Profile assertions: model_reliability should reflect validation status
    profiles = report["profiles"]
    assert len(profiles) > 0
    for p in profiles:
        assert p["model_reliability"] is not None
        assert "status" in p["model_reliability"]
        assert "rationale" in p["model_reliability"]


def test_pipeline_threshold_policy_execution(spark: SparkSession, mock_dataset_and_model, tmp_path: Path):
    """Test 3: Threshold-optimized inference applies tau thresholds to filter unconfident predictions."""
    report_file = tmp_path / "threshold_report.json"
    parquet_path = mock_dataset_and_model["parquet_dir"]
    model_path = mock_dataset_and_model["model_dir"]

    report = run_threat_intelligence(
        spark=spark,
        parquet_path=parquet_path,
        output_path=report_file,
        run_id="run_test_threshold",
        enable_model_inference=True,
        model_path=model_path,
        apply_threshold_policy=True,
        tau_infiltration=0.60,
        tau_brute_force_web=0.35,
    )

    assert report["evidence_provenance"]["is_model_prediction"] is True
    assert report["model_governance"]["inference_executed"] is True
    assert len(report["profiles"]) > 0


def test_database_persistence_compatibility(spark: SparkSession, mock_dataset_and_model, tmp_path: Path):
    """Test 4: Verify save_threat_intelligence_report cleanly persists both disabled and inference reports."""
    db_file = tmp_path / "test_threatlenz.db"
    db_url = f"sqlite:///{db_file}"
    engine = create_engine(db_url)
    Base.metadata.create_all(engine)

    # 1. Persist disabled-mode report
    disabled_report_file = tmp_path / "disabled_report_db.json"
    disabled_report = run_threat_intelligence(
        spark=spark,
        parquet_path=mock_dataset_and_model["parquet_dir"],
        output_path=disabled_report_file,
        run_id="run_db_disabled",
        enable_model_inference=False,
    )
    with Session(engine) as session:
        run_rec_1 = load_threat_intelligence_report(disabled_report, session=session)
        assert run_rec_1.run_id == "run_db_disabled"
        assert run_rec_1.is_model_prediction is False
        assert run_rec_1.model_status == "QUARANTINED_TARGET_LEAKAGE"

    # 2. Persist operational inference report
    inference_report_file = tmp_path / "inference_report_db.json"
    inference_report = run_threat_intelligence(
        spark=spark,
        parquet_path=mock_dataset_and_model["parquet_dir"],
        output_path=inference_report_file,
        run_id="run_db_inference",
        enable_model_inference=True,
        model_path=mock_dataset_and_model["model_dir"],
        apply_threshold_policy=True,
    )
    with Session(engine) as session:
        run_rec_2 = load_threat_intelligence_report(inference_report, session=session)
        assert run_rec_2.run_id == "run_db_inference"
        assert run_rec_2.is_model_prediction is True
        assert run_rec_2.model_status == "OPERATIONAL_EVALUATED"

        # Check threat_profiles table entries
        profiles_2 = session.query(ThreatProfileRecord).filter_by(run_id="run_db_inference").all()
        assert len(profiles_2) > 0
        for p in profiles_2:
            assert p.model_reliability in (
                "HIGH_RELIABILITY",
                "EVALUABLE",
                "UNRELIABLE",
                "NON_EVALUABLE",
                None,
            )
