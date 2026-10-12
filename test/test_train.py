"""Unit tests for ThreatLenz Phase 3 ML Training and Evaluation Pipeline."""

import shutil
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import (
    DoubleType,
    IntegerType,
    StringType,
    StructField,
    StructType,
    TimestampType,
)

from src.config import settings
from src.train import (
    COLLINEAR_SUBFLOW_COLS,
    EXCLUDED_METADATA_COLS,
    INDEX_TO_LABEL,
    LABEL_TO_INDEX,
    NUM_CLASSES,
    SHORTCUT_COLS,
    TrainingConfig,
    add_label_index,
    build_pipeline,
    compute_class_weights,
    evaluate_predictions,
    get_feature_columns,
    load_model,
    save_artifacts,
    split_dataset,
    subsample_dataset,
)
from src.utils import get_spark_session


@pytest.fixture(scope="session")
def spark() -> SparkSession:
    """Provides a shared local SparkSession for training unit tests."""
    return get_spark_session(
        app_name="ThreatLenz-Train-Tests",
        master="local[2]",
        driver_memory="2g",
        shuffle_partitions=2,
    )


def test_stable_label_mapping():
    """Verify that all 14 configured classes have fixed, bijective index assignments."""
    assert len(LABEL_TO_INDEX) == 14
    assert len(INDEX_TO_LABEL) == 14
    assert NUM_CLASSES == 14

    # Canonical Benign must be 0
    assert LABEL_TO_INDEX["Benign"] == 0
    assert INDEX_TO_LABEL[0] == "Benign"

    # All indices 0 to 13 must be present and unique
    indices = set(LABEL_TO_INDEX.values())
    assert indices == set(range(14))

    # Reverse lookup must match exactly
    for lbl, idx in LABEL_TO_INDEX.items():
        assert INDEX_TO_LABEL[idx] == lbl


def test_add_label_index(spark: SparkSession):
    """Verify add_label_index assigns deterministic double indices."""
    schema = StructType([
        StructField("label", StringType(), False),
    ])
    data = [
        {"label": "Benign"},
        {"label": "Bot"},
        {"label": "SQL Injection"},
        {"label": "UnknownClass"},
    ]
    df = spark.createDataFrame(data, schema=schema)
    indexed_df = add_label_index(df)

    rows = {r["label"]: r["label_idx"] for r in indexed_df.collect()}
    assert rows["Benign"] == 0.0
    assert rows["Bot"] == 1.0
    assert rows["SQL Injection"] == 12.0
    assert rows["UnknownClass"] == -1.0


def test_feature_exclusion_and_leakage_safeguards():
    """Verify strict exclusion of metadata, destination port, constant, and collinear columns."""
    all_dataset_columns = [
        # Targets & metadata
        "label", "raw_label", "timestamp", "timestamp_parsed", "event_date", "source_file",
        # Shortcut feature
        "dst_port",
        # Constant columns
        "bwd_psh_flags", "fwd_blk_rate_avg",
        # Collinear features
        "subflow_fwd_pkts", "subflow_bwd_pkts", "fwd_seg_size_avg",
        # Legitimate features
        "protocol", "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts",
        "flow_byts_s", "flow_pkts_s", "down_up_ratio", "init_fwd_win_byts"
    ]

    # Default config: dst_port excluded, collinear pruned
    cfg_default = TrainingConfig(include_dst_port=False, prune_collinear_subflows=True)
    features_default = get_feature_columns(all_dataset_columns, cfg_default)

    for meta in EXCLUDED_METADATA_COLS:
        assert meta not in features_default
    for shortcut in SHORTCUT_COLS:
        assert shortcut not in features_default
    for const_col in settings.constant_columns:
        assert const_col not in features_default
    for collin in COLLINEAR_SUBFLOW_COLS:
        assert collin not in features_default

    assert "flow_duration" in features_default
    assert "protocol" in features_default
    assert "down_up_ratio" in features_default

    # Comparison config: dst_port explicitly included
    cfg_with_port = TrainingConfig(include_dst_port=True, prune_collinear_subflows=False)
    features_with_port = get_feature_columns(all_dataset_columns, cfg_with_port)
    assert "dst_port" in features_with_port
    assert "subflow_fwd_pkts" in features_with_port


def test_chronological_per_class_split(spark: SparkSession):
    """Verify chronological intra-class splitting allocates contiguous time-blocks without overlap."""
    base_time = datetime(2018, 2, 14, 8, 0, 0)
    data = []

    # Create 10 flows for Benign and 10 flows for SQL Injection over time
    for i in range(10):
        t = base_time + timedelta(minutes=i)
        data.append({
            "id": f"benign_{i}",
            "label": "Benign",
            "timestamp_parsed": t,
            "flow_duration": float(i * 10),
        })
        data.append({
            "id": f"sqli_{i}",
            "label": "SQL Injection",
            "timestamp_parsed": t,
            "flow_duration": float(i * 10),
        })

    df = spark.createDataFrame(data)
    cfg = TrainingConfig(
        split_strategy="chronological_per_class",
        train_ratio=0.70,
        val_ratio=0.15,
        test_ratio=0.15,
    )

    train_df, val_df, test_df, summary = split_dataset(df, cfg)

    # 1. Zero row overlap across splits
    train_ids = set(r["id"] for r in train_df.select("id").collect())
    val_ids = set(r["id"] for r in val_df.select("id").collect())
    test_ids = set(r["id"] for r in test_df.select("id").collect())

    assert train_ids.isdisjoint(val_ids)
    assert train_ids.isdisjoint(test_ids)
    assert val_ids.isdisjoint(test_ids)
    assert len(train_ids) + len(val_ids) + len(test_ids) == 20

    # 2. Both classes represented in each split
    assert summary["class_counts_by_split"]["train"]["Benign"] == 7
    assert summary["class_counts_by_split"]["train"]["SQL Injection"] == 7
    assert summary["class_counts_by_split"]["val"]["Benign"] == 1
    assert summary["class_counts_by_split"]["val"]["SQL Injection"] == 1
    assert summary["class_counts_by_split"]["test"]["Benign"] == 2
    assert summary["class_counts_by_split"]["test"]["SQL Injection"] == 2

    # 3. Chronological time-block continuity (train timestamps strictly <= test timestamps)
    max_train_ts = train_df.agg(F.max("timestamp_parsed")).collect()[0][0]
    min_test_ts = test_df.agg(F.min("timestamp_parsed")).collect()[0][0]
    assert max_train_ts <= min_test_ts


def test_inter_day_chronological_split(spark: SparkSession):
    """Verify inter_day_chronological split partitions strictly by event date."""
    data = [
        {"id": 1, "event_date": "2018-02-14", "label": "FTP-BruteForce"},
        {"id": 2, "event_date": "2018-02-16", "label": "DoS-Hulk"},
        {"id": 3, "event_date": "2018-02-22", "label": "Brute Force - Web"},
        {"id": 4, "event_date": "2018-03-02", "label": "Bot"},
    ]
    df = spark.createDataFrame(data)
    cfg = TrainingConfig(split_strategy="inter_day_chronological")

    train_df, val_df, test_df, summary = split_dataset(df, cfg)

    train_ids = [r["id"] for r in train_df.collect()]
    val_ids = [r["id"] for r in val_df.collect()]
    test_ids = [r["id"] for r in test_df.collect()]

    assert set(train_ids) == {1, 2}
    assert set(val_ids) == {3}
    assert set(test_ids) == {4}


def test_compute_class_weights(spark: SparkSession):
    """Verify inverse-frequency class weighting assigns higher weights to rare classes."""
    data = (
        [{"label": "Benign", "label_idx": 0.0}] * 100
        + [{"label": "Bot", "label_idx": 1.0}] * 10
        + [{"label": "SQL Injection", "label_idx": 12.0}] * 1
    )
    df = spark.createDataFrame(data)

    weighted_df, weights = compute_class_weights(df, max_weight=500.0)

    assert "weight" in weighted_df.columns
    # N=111, K=3. Benign=100 -> w = 111 / (3 * 100) = 0.37
    # Bot=10 -> w = 111 / (3 * 10) = 3.7
    # SQLi=1 -> w = 111 / (3 * 1) = 37.0
    assert weights["Benign"] < weights["Bot"] < weights["SQL Injection"]
    assert weights["SQL Injection"] <= 500.0


def test_multiclass_metrics_rare_and_zero_support(spark: SparkSession):
    """Verify evaluate_predictions accurately calculates metrics with zero-support and zero-predictions."""
    # Build synthetic predictions for a 3-class subset
    # 0: Benign (10 samples, 8 correct, 2 predicted as Bot)
    # 1: Bot (10 samples, 9 correct, 1 predicted as Benign)
    # 12: SQL Injection (0 samples in test set -> zero support class)
    preds = (
        [{"label_idx": 0.0, "prediction": 0.0}] * 8
        + [{"label_idx": 0.0, "prediction": 1.0}] * 2
        + [{"label_idx": 1.0, "prediction": 0.0}] * 1
        + [{"label_idx": 1.0, "prediction": 1.0}] * 9
    )
    df = spark.createDataFrame(preds)

    report = evaluate_predictions(df, split_name="test")

    # 1. Total samples and overall accuracy (17 correct out of 20 = 0.85)
    assert report["total_evaluated_samples"] == 20
    assert report["overall_accuracy"] == 0.85
    assert report["majority_class_baseline_accuracy"] == 0.50

    # 2. Per-class metrics
    per_class_map = {item["class_name"]: item for item in report["per_class_metrics"]}

    benign_stats = per_class_map["Benign"]
    assert benign_stats["true_support"] == 10
    assert benign_stats["predicted_support"] == 9
    assert benign_stats["recall"] == 0.8
    assert benign_stats["precision"] == round(8 / 9, 4)

    sqli_stats = per_class_map["SQL Injection"]
    assert sqli_stats["true_support"] == 0
    assert sqli_stats["predicted_support"] == 0
    assert sqli_stats["zero_test_support"] is True
    assert sqli_stats["zero_predictions"] is True
    assert sqli_stats["precision"] is None
    assert sqli_stats["recall"] is None
    assert sqli_stats["f1_score"] is None

    # 3. Macro-F1 should average over classes with true support > 0
    assert report["macro_f1"] > 0.0
    assert report["balanced_accuracy"] == 0.85

    # 4. Binary threat metrics
    binary = report["binary_threat_detection"]
    assert binary["true_negatives_benign"] == 8
    assert binary["false_positives_alarms"] == 2
    assert binary["false_alarm_rate"] == 0.20
    assert binary["true_positives_detected"] == 9
    assert binary["attack_detection_rate"] == 0.90


def test_pipeline_training_and_serialization(spark: SparkSession):
    """Verify that build_pipeline fits on training data, generates predictions, and saves/loads cleanly."""
    schema = StructType([
        StructField("flow_duration", DoubleType(), True),
        StructField("tot_fwd_pkts", DoubleType(), True),
        StructField("down_up_ratio", DoubleType(), True),
        StructField("protocol", IntegerType(), True),
        StructField("label_idx", DoubleType(), False),
        StructField("weight", DoubleType(), False),
    ])

    # Include NaN in down_up_ratio to test Imputer
    data = [
        (100.0, 2.0, 1.0, 6, 0.0, 1.0),
        (200.0, 5.0, None, 6, 0.0, 1.0),
        (50.0, 1.0, 0.0, 17, 1.0, 5.0),
        (60.0, 1.0, 0.0, 17, 1.0, 5.0),
    ]
    df = spark.createDataFrame(data, schema=schema)

    cfg = TrainingConfig(
        num_trees=3,
        max_depth=2,
        use_class_weights=True,
        seed=42,
    )

    feature_cols = ["flow_duration", "tot_fwd_pkts", "down_up_ratio", "protocol"]
    pipeline = build_pipeline(feature_cols, cfg)

    # 1. Fit pipeline
    model = pipeline.fit(df)

    # 2. Predict
    predictions = model.transform(df)
    assert "prediction" in predictions.columns
    assert "probability" in predictions.columns

    # 3. Serialization and Deserialization test
    test_out_dir = Path("data/sample/test_rf_model")
    if test_out_dir.exists():
        shutil.rmtree(test_out_dir)

    try:
        model.write().overwrite().save(str(test_out_dir))
        assert test_out_dir.exists()

        loaded = load_model(test_out_dir)
        loaded_preds = loaded.transform(df)

        orig_preds = [r["prediction"] for r in predictions.collect()]
        reloaded_preds = [r["prediction"] for r in loaded_preds.collect()]
        assert orig_preds == reloaded_preds
    finally:
        if test_out_dir.exists():
            shutil.rmtree(test_out_dir)


def test_chronological_split_timestamp_ties_never_separated(spark: SparkSession):
    """Verify that multiple flows sharing identical timestamps are NEVER separated across splits."""
    base_time = datetime(2018, 2, 14, 10, 0, 0)
    data = []

    # 3 distinct timestamps, 4 rows each (total 12 rows).
    # Vary flow_duration and packet counts to ensure secondary columns do not break timestamp ties.
    for ts_idx in range(3):
        t = base_time + timedelta(minutes=ts_idx * 10)
        for row_idx in range(4):
            data.append({
                "id": f"flow_{ts_idx}_{row_idx}",
                "label": "Benign",
                "timestamp_parsed": t,
                "flow_duration": float(row_idx * 100 + ts_idx),
            })

    df = spark.createDataFrame(data)
    cfg = TrainingConfig(
        split_strategy="chronological_per_class",
        train_ratio=0.70,
        val_ratio=0.15,
        test_ratio=0.15,
    )

    train_df, val_df, test_df, summary = split_dataset(df, cfg)

    # 1. Collect split assignments by timestamp
    train_ts = set(r["timestamp_parsed"] for r in train_df.select("timestamp_parsed").collect())
    val_ts = set(r["timestamp_parsed"] for r in val_df.select("timestamp_parsed").collect())
    test_ts = set(r["timestamp_parsed"] for r in test_df.select("timestamp_parsed").collect())

    # Critical check: No timestamp can appear in more than one split
    assert train_ts.isdisjoint(val_ts), f"Overlap between train and val: {train_ts & val_ts}"
    assert train_ts.isdisjoint(test_ts), f"Overlap between train and test: {train_ts & test_ts}"
    assert val_ts.isdisjoint(test_ts), f"Overlap between val and test: {val_ts & test_ts}"

    # 2. Verify all rows at t0 are in train, t1 in val, t2 in test
    t0 = base_time
    t1 = base_time + timedelta(minutes=10)
    t2 = base_time + timedelta(minutes=20)

    assert t0 in train_ts
    assert t1 in val_ts
    assert t2 in test_ts

    # 3. All 4 rows of each timestamp stay completely intact
    assert summary["class_counts_by_split"]["train"]["Benign"] == 4
    assert summary["class_counts_by_split"]["val"]["Benign"] == 4
    assert summary["class_counts_by_split"]["test"]["Benign"] == 4

    # 4. Strict chronological ordering across split boundaries
    max_train = max(train_ts)
    min_val = min(val_ts)
    max_val = max(val_ts)
    min_test = min(test_ts)
    assert max_train < min_val <= max_val < min_test


def test_chronological_split_insufficient_timestamps(spark: SparkSession):
    """Verify correct behavior when classes have too few distinct timestamps to support all three splits."""
    t0 = datetime(2018, 2, 14, 10, 0, 0)
    t1 = datetime(2018, 2, 14, 11, 0, 0)
    data = [
        # Class with only 1 distinct timestamp (3 rows)
        {"id": "c1_0", "label": "SingleTS", "timestamp_parsed": t0},
        {"id": "c1_1", "label": "SingleTS", "timestamp_parsed": t0},
        {"id": "c1_2", "label": "SingleTS", "timestamp_parsed": t0},
        # Class with only 2 distinct timestamps (2 rows each)
        {"id": "c2_0", "label": "DoubleTS", "timestamp_parsed": t0},
        {"id": "c2_1", "label": "DoubleTS", "timestamp_parsed": t0},
        {"id": "c2_2", "label": "DoubleTS", "timestamp_parsed": t1},
        {"id": "c2_3", "label": "DoubleTS", "timestamp_parsed": t1},
    ]

    df = spark.createDataFrame(data)
    cfg = TrainingConfig(split_strategy="chronological_per_class")

    train_df, val_df, test_df, summary = split_dataset(df, cfg)

    # 1. SingleTS: all rows must go to train; val and test have 0 support
    train_c1 = train_df.filter(F.col("label") == "SingleTS").count()
    val_c1 = val_df.filter(F.col("label") == "SingleTS").count()
    test_c1 = test_df.filter(F.col("label") == "SingleTS").count()

    assert train_c1 == 3
    assert val_c1 == 0
    assert test_c1 == 0

    # 2. DoubleTS: t0 goes to train, t1 goes to test; val has 0 support
    train_c2 = train_df.filter(F.col("label") == "DoubleTS").count()
    val_c2 = val_df.filter(F.col("label") == "DoubleTS").count()
    test_c2 = test_df.filter(F.col("label") == "DoubleTS").count()

    assert train_c2 == 2
    assert val_c2 == 0
    assert test_c2 == 2


def test_chronological_split_reproducibility(spark: SparkSession):
    """Verify that chronological splitting produces identical, deterministic assignments across runs."""
    base_time = datetime(2018, 2, 14, 8, 0, 0)
    data = []
    for i in range(25):
        data.append({
            "id": f"row_{i}",
            "label": "Benign" if i % 2 == 0 else "Bot",
            "timestamp_parsed": base_time + timedelta(seconds=i * 30),
        })

    df = spark.createDataFrame(data)
    cfg = TrainingConfig(split_strategy="chronological_per_class", seed=42)

    # Run split twice
    train_1, val_1, test_1, _ = split_dataset(df, cfg)
    train_2, val_2, test_2, _ = split_dataset(df, cfg)

    ids_train_1 = set(r["id"] for r in train_1.select("id").collect())
    ids_train_2 = set(r["id"] for r in train_2.select("id").collect())
    assert ids_train_1 == ids_train_2

    ids_val_1 = set(r["id"] for r in val_1.select("id").collect())
    ids_val_2 = set(r["id"] for r in val_2.select("id").collect())
    assert ids_val_1 == ids_val_2

    ids_test_1 = set(r["id"] for r in test_1.select("id").collect())
    ids_test_2 = set(r["id"] for r in test_2.select("id").collect())
    assert ids_test_1 == ids_test_2


def test_subsample_dataset_reporting_and_rare_classes(spark: SparkSession):
    """Verify subsample_dataset preserves rare classes when configured and reports distributions."""
    data = (
        [{"label": "Benign", "val": float(i)} for i in range(200)]
        + [{"label": "SQL Injection", "val": float(i)} for i in range(5)]
    )
    df = spark.createDataFrame(data)

    cfg = TrainingConfig(
        subsample_ratio=0.10,
        subsample_strategy="stratified_per_class",
        protect_rare_classes=True,
        min_rare_class_samples=10,
        seed=42,
    )

    sampled_df, summary = subsample_dataset(df, cfg)

    assert summary["applied"] is True
    assert summary["strategy"] == "stratified_per_class"
    assert summary["protect_rare_classes"] is True

    # Pre-sampling counts
    assert summary["pre_sample_counts"]["Benign"] == 200
    assert summary["pre_sample_counts"]["SQL Injection"] == 5

    # SQL Injection has 5 <= 10 samples, so 100% must be retained
    assert summary["post_sample_counts"]["SQL Injection"] == 5
    assert "SQL Injection" in summary["protected_classes_retained_100pct"]

    # Benign (200 rows) is sampled to approx 10% (~15 to 25 rows)
    benign_post = summary["post_sample_counts"]["Benign"]
    assert 10 <= benign_post <= 35

    # Expected vs actual reporting
    assert summary["expected_rows_unprotected"] == int(205 * 0.10)
    assert summary["actual_rows_sampled"] == summary["total_post_sampling"]
    assert summary["excess_rows_from_protection"] >= 4  # 5 SQLi rows retained vs 0.5 expected
    assert summary["effective_subsample_ratio"] > 0.10


def test_unknown_and_missing_labels(spark: SparkSession):
    """Verify add_label_index handles unseen, null, and empty label strings safely."""
    schema = StructType([
        StructField("label", StringType(), True),
    ])
    data = [
        {"label": "Benign"},
        {"label": "DDoS-HOIC"},
        {"label": "CompletelyUnknownAttack"},
        {"label": None},
    ]
    df = spark.createDataFrame(data, schema=schema)
    indexed_df = add_label_index(df)

    rows = indexed_df.collect()
    label_to_idx = {r["label"]: r["label_idx"] for r in rows}

    assert label_to_idx["Benign"] == 0.0
    assert label_to_idx["DDoS-HOIC"] == 4.0
    assert label_to_idx["CompletelyUnknownAttack"] == -1.0
    assert label_to_idx[None] == -1.0


def test_global_chronological_split_zero_cross_label_leakage(spark: SparkSession):
    """Verify global chronological splitting eliminates cross-label timestamp leakage."""
    base_time = datetime(2018, 2, 14, 10, 0, 0)
    data = []

    # 4 distinct timestamps across 3 classes:
    # t0: Benign (3 rows), FTP-BruteForce (2 rows) -> both in train
    # t1: Benign (2 rows), FTP-BruteForce (2 rows) -> both in train
    # t2: Benign (2 rows), DoS-Hulk (2 rows) -> both in val
    # t3: Benign (2 rows), Bot (2 rows) -> both in test
    timestamps = [base_time + timedelta(hours=i) for i in range(4)]

    # t0
    for r in range(3):
        data.append({"id": f"b0_{r}", "label": "Benign", "timestamp_parsed": timestamps[0]})
    for r in range(2):
        data.append({"id": f"ftp0_{r}", "label": "FTP-BruteForce", "timestamp_parsed": timestamps[0]})

    # t1
    for r in range(2):
        data.append({"id": f"b1_{r}", "label": "Benign", "timestamp_parsed": timestamps[1]})
    for r in range(2):
        data.append({"id": f"ftp1_{r}", "label": "FTP-BruteForce", "timestamp_parsed": timestamps[1]})

    # t2
    for r in range(2):
        data.append({"id": f"b2_{r}", "label": "Benign", "timestamp_parsed": timestamps[2]})
    for r in range(2):
        data.append({"id": f"dos2_{r}", "label": "DoS-Hulk", "timestamp_parsed": timestamps[2]})

    # t3
    for r in range(2):
        data.append({"id": f"b3_{r}", "label": "Benign", "timestamp_parsed": timestamps[3]})
    for r in range(2):
        data.append({"id": f"bot3_{r}", "label": "Bot", "timestamp_parsed": timestamps[3]})

    df = spark.createDataFrame(data)
    cfg = TrainingConfig(
        split_strategy="global_chronological",
        train_ratio=0.50,
        val_ratio=0.25,
        test_ratio=0.25,
    )

    train_df, val_df, test_df, summary = split_dataset(df, cfg)

    # 1. Zero row overlap
    train_ids = set(r["id"] for r in train_df.select("id").collect())
    val_ids = set(r["id"] for r in val_df.select("id").collect())
    test_ids = set(r["id"] for r in test_df.select("id").collect())
    assert train_ids.isdisjoint(val_ids)
    assert train_ids.isdisjoint(test_ids)
    assert val_ids.isdisjoint(test_ids)

    # 2. CRITICAL: Zero cross-label timestamp leakage
    # Every row at t0 and t1 must be in train (regardless of Benign or FTP-BruteForce)
    # Every row at t2 must be in val (regardless of Benign or DoS-Hulk)
    # Every row at t3 must be in test (regardless of Benign or Bot)
    train_ts = set(r["timestamp_parsed"] for r in train_df.select("timestamp_parsed").collect())
    val_ts = set(r["timestamp_parsed"] for r in val_df.select("timestamp_parsed").collect())
    test_ts = set(r["timestamp_parsed"] for r in test_df.select("timestamp_parsed").collect())

    assert train_ts.isdisjoint(val_ts), f"Timestamp overlap train/val: {train_ts & val_ts}"
    assert train_ts.isdisjoint(test_ts), f"Timestamp overlap train/test: {train_ts & test_ts}"
    assert val_ts.isdisjoint(test_ts), f"Timestamp overlap val/test: {val_ts & test_ts}"

    assert train_ts == {timestamps[0], timestamps[1]}
    assert val_ts == {timestamps[2]}
    assert test_ts == {timestamps[3]}

    # 3. Documented rare-class and temporal coverage limitations
    coverage = summary["class_support_coverage"]
    assert coverage["FTP-BruteForce"]["temporal_coverage"] == "train_only"
    assert coverage["FTP-BruteForce"]["zero_test_support"] is True

    assert coverage["DoS-Hulk"]["temporal_coverage"] == "val_only"
    assert coverage["DoS-Hulk"]["zero_train_support"] is True
    assert coverage["DoS-Hulk"]["zero_test_support"] is True

    assert coverage["Bot"]["temporal_coverage"] == "test_only"
    assert coverage["Bot"]["zero_train_support"] is True
    assert coverage["Bot"]["zero_test_support"] is False

    assert coverage["Benign"]["temporal_coverage"] == "full_span"
