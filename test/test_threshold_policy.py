"""Unit tests for the opt-in ThreatLenz threshold decision policy.

Covers:
1. Target class Infiltration (11.0) below threshold (< 0.60) reassigns to Benign (0.0).
2. Target class Infiltration (11.0) equal to threshold (== 0.60) strictly preserved as Infiltration (11.0).
3. Target class Infiltration (11.0) above threshold (> 0.60) strictly preserved as Infiltration (11.0).
4. Target class Brute Force - Web (2.0) below threshold (< 0.35) reassigns to Benign (0.0).
5. Target class Brute Force - Web (2.0) equal to threshold (== 0.35) strictly preserved as Brute Force - Web (2.0).
6. Target class Brute Force - Web (2.0) above threshold (> 0.35) strictly preserved as Brute Force - Web (2.0).
7. Non-target classes (e.g. Bot=1.0, DoS-Hulk=7.0, Benign=0.0) preserved regardless of probability.
8. Invalid probability vectors (null, NaN element, short length < 14) safely fallback to original prediction.
9. Preservation of original 'prediction' column alongside newly created 'adjusted_prediction'.
10. Default configuration backward-compatibility in evaluate_predictions.
"""

import math
import pytest
from pyspark.ml.linalg import Vectors
from pyspark.sql import DataFrame, SparkSession

from src.train import (
    apply_threshold_decision_policy,
    evaluate_predictions,
    TrainingConfig,
)
from src.utils import get_spark_session


@pytest.fixture(scope="module")
def spark() -> SparkSession:
    """Fixture providing a lightweight local SparkSession for policy testing."""
    return get_spark_session(
        app_name="ThreatLenz-ThresholdPolicy-Test",
        master="local[2]",
        driver_memory="1g",
        shuffle_partitions=2,
    )


def test_threshold_policy_target_classes_and_boundaries(spark: SparkSession):
    """Verifies below-threshold, equal-to-threshold, and above-threshold rules on both target classes."""
    data = [
        # Infiltration (index 11) cases: threshold = 0.60
        {"id": 1, "prediction": 11.0, "probability": Vectors.dense([0.0]*11 + [0.59] + [0.0]*2)},  # below -> 0.0
        {"id": 2, "prediction": 11.0, "probability": Vectors.dense([0.0]*11 + [0.60] + [0.0]*2)},  # equal -> 11.0
        {"id": 3, "prediction": 11.0, "probability": Vectors.dense([0.0]*11 + [0.61] + [0.0]*2)},  # above -> 11.0

        # Brute Force - Web (index 2) cases: threshold = 0.35
        {"id": 4, "prediction": 2.0, "probability": Vectors.dense([0.0, 0.0, 0.34] + [0.0]*11)},   # below -> 0.0
        {"id": 5, "prediction": 2.0, "probability": Vectors.dense([0.0, 0.0, 0.35] + [0.0]*11)},   # equal -> 2.0
        {"id": 6, "prediction": 2.0, "probability": Vectors.dense([0.0, 0.0, 0.36] + [0.0]*11)},   # above -> 2.0
    ]

    df = spark.createDataFrame(data)
    res_df = apply_threshold_decision_policy(
        df,
        tau_infiltration=0.60,
        tau_brute_force_web=0.35,
        output_col="adjusted_prediction",
    )

    rows = {r["id"]: (r["prediction"], r["adjusted_prediction"]) for r in res_df.collect()}

    # 1. Infiltration below threshold -> 0.0
    assert rows[1] == (11.0, 0.0)
    # 2. Infiltration equal threshold -> 11.0 (strict < requirement)
    assert rows[2] == (11.0, 11.0)
    # 3. Infiltration above threshold -> 11.0
    assert rows[3] == (11.0, 11.0)

    # 4. Brute Force - Web below threshold -> 0.0
    assert rows[4] == (2.0, 0.0)
    # 5. Brute Force - Web equal threshold -> 2.0
    assert rows[5] == (2.0, 2.0)
    # 6. Brute Force - Web above threshold -> 2.0
    assert rows[6] == (2.0, 2.0)


def test_threshold_policy_non_target_classes_preserved(spark: SparkSession):
    """Verifies that non-target classes (Benign, Bot, DoS, SSH, etc.) are never mutated."""
    data = [
        {"id": 1, "prediction": 0.0, "probability": Vectors.dense([0.20] + [0.0]*13)},       # Benign
        {"id": 2, "prediction": 1.0, "probability": Vectors.dense([0.0, 0.15] + [0.0]*12)},  # Bot (low prob)
        {"id": 3, "prediction": 4.0, "probability": Vectors.dense([0.0]*4 + [0.10] + [0.0]*9)},  # DDoS-HOIC
        {"id": 4, "prediction": 7.0, "probability": Vectors.dense([0.0]*7 + [0.25] + [0.0]*6)},  # DoS-Hulk
        {"id": 5, "prediction": 13.0, "probability": Vectors.dense([0.0]*13 + [0.30])},     # SSH-BruteForce
    ]

    df = spark.createDataFrame(data)
    res_df = apply_threshold_decision_policy(df, output_col="adjusted_prediction")

    rows = {r["id"]: (r["prediction"], r["adjusted_prediction"]) for r in res_df.collect()}
    assert rows[1] == (0.0, 0.0)
    assert rows[2] == (1.0, 1.0)
    assert rows[3] == (4.0, 4.0)
    assert rows[4] == (7.0, 7.0)
    assert rows[5] == (13.0, 13.0)


def test_threshold_policy_invalid_and_null_probability_handling(spark: SparkSession):
    """Verifies safe fallback to original prediction on null, NaN, and short probability vectors."""
    data = [
        # Null probability column
        {"id": 1, "prediction": 11.0, "probability": None},
        {"id": 2, "prediction": 2.0, "probability": None},
        # NaN in probability element
        {"id": 3, "prediction": 11.0, "probability": Vectors.dense([0.0]*11 + [float("nan")] + [0.0]*2)},
        # Short vector (< 14 elements)
        {"id": 4, "prediction": 11.0, "probability": Vectors.dense([0.5, 0.5])},
    ]

    df = spark.createDataFrame(data)
    res_df = apply_threshold_decision_policy(df, output_col="adjusted_prediction")

    rows = {r["id"]: (r["prediction"], r["adjusted_prediction"]) for r in res_df.collect()}
    # All edge cases must safely preserve the original prediction without crashing
    assert rows[1] == (11.0, 11.0)
    assert rows[2] == (2.0, 2.0)
    assert rows[3] == (11.0, 11.0)
    assert rows[4] == (11.0, 11.0)


def test_threshold_policy_preserves_original_prediction_column(spark: SparkSession):
    """Verifies that the original 'prediction' column remains completely unchanged."""
    data = [
        {"id": 1, "prediction": 11.0, "probability": Vectors.dense([0.0]*11 + [0.40] + [0.0]*2)},
        {"id": 2, "prediction": 2.0, "probability": Vectors.dense([0.0, 0.0, 0.20] + [0.0]*11)},
    ]

    df = spark.createDataFrame(data)
    original_preds = [r["prediction"] for r in df.select("prediction").collect()]

    res_df = apply_threshold_decision_policy(df, output_col="adjusted_prediction")
    after_preds = [r["prediction"] for r in res_df.select("prediction").collect()]

    assert "prediction" in res_df.columns
    assert "adjusted_prediction" in res_df.columns
    assert set(original_preds) == set(after_preds)


def test_training_config_opt_in_defaults():
    """Verifies that TrainingConfig defaults apply_threshold_policy to False for full backward compatibility."""
    cfg = TrainingConfig()
    assert cfg.apply_threshold_policy is False
    assert cfg.tau_infiltration == 0.60
    assert cfg.tau_brute_force_web == 0.35


def test_evaluate_predictions_custom_prediction_column(spark: SparkSession):
    """Verifies evaluate_predictions accurately evaluates whichever column is passed (prediction or adjusted_prediction)."""
    data = [
        # label_idx, raw prediction, adjusted_prediction
        {"label_idx": 0, "prediction": 11.0, "adjusted_prediction": 0.0},
        {"label_idx": 11, "prediction": 11.0, "adjusted_prediction": 11.0},
        {"label_idx": 0, "prediction": 0.0, "adjusted_prediction": 0.0},
    ]

    df = spark.createDataFrame(data)

    # 1. Evaluate using raw argmax 'prediction' (has 1 false alarm: label 0 predicted as 11)
    rep_raw = evaluate_predictions(df, split_name="test", prediction_col="prediction")
    assert rep_raw["binary_threat_detection"]["false_positives_alarms"] == 1
    assert rep_raw["overall_accuracy"] == round(2 / 3, 4)

    # 2. Evaluate using 'adjusted_prediction' (false alarm resolved to 0.0)
    rep_adj = evaluate_predictions(df, split_name="test", prediction_col="adjusted_prediction")
    assert rep_adj["binary_threat_detection"]["false_positives_alarms"] == 0
    assert rep_adj["overall_accuracy"] == 1.0
