"""ThreatLenz Phase 3: Spark MLlib Random Forest Training and Evaluation Pipeline.

Implements a reproducible, leakage-aware Spark MLlib Random Forest multiclass
training and evaluation engine for the curated CSE-CIC-IDS2018 flows.parquet dataset.

Architectural Safeguards:
1. Contiguous chronological intra-class and inter-day time-block splitting options.
2. Strict feature leakage exclusion (metadata, partition date, and destination port shortcut).
3. Dynamic training-only feature pruning (constant zero-variance and collinear duplicates).
4. Inverse-frequency class weighting computed strictly on training data.
5. Deterministic 14-class label indexing preventing vocabulary drift across splits.
6. Honest metric reporting with explicit handling of rare and zero-support classes.
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from pydantic import BaseModel, Field
from pyspark.ml import Pipeline, PipelineModel
from pyspark.ml.classification import RandomForestClassificationModel, RandomForestClassifier
from pyspark.ml.feature import Imputer, StringIndexer, VectorAssembler
from pyspark.sql import DataFrame, SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import DoubleType
from pyspark.sql.window import Window

from src.config import settings
from src.utils import get_logger, get_spark_session, save_json_report

logger = get_logger("ThreatLenz.Train")

# Deterministic canonical label to index mapping (0 to 13)
# Benign is canonical index 0; the 13 attack categories are indices 1 to 13.
LABEL_TO_INDEX: Dict[str, int] = {
    "Benign": 0,
    "Bot": 1,
    "Brute Force - Web": 2,
    "Brute Force - XSS": 3,
    "DDoS-HOIC": 4,
    "DDoS-LOIC-UDP": 5,
    "DoS-GoldenEye": 6,
    "DoS-Hulk": 7,
    "DoS-SlowHTTPTest": 8,
    "DoS-Slowloris": 9,
    "FTP-BruteForce": 10,
    "Infiltration": 11,
    "SQL Injection": 12,
    "SSH-BruteForce": 13,
}

INDEX_TO_LABEL: Dict[int, str] = {v: k for k, v in LABEL_TO_INDEX.items()}
NUM_CLASSES: int = len(LABEL_TO_INDEX)

# Non-predictive metadata and leakage-prone columns to explicitly exclude from feature vectors
EXCLUDED_METADATA_COLS: List[str] = [
    "label",
    "raw_label",
    "timestamp",
    "timestamp_parsed",
    "event_date",
    "source_file",
    "split",
    "split_pct",
    "weight",
]

# Destination port causes severe shortcut learning in CSE-CIC-IDS2018 (e.g. 100% SSH on 22, FTP on 21)
SHORTCUT_COLS: List[str] = [
    "dst_port",
]

# Exact 1.0 collinear duplicate subflow pairs identified in Phase 2 analytics
COLLINEAR_SUBFLOW_COLS: List[str] = [
    "subflow_fwd_pkts",
    "subflow_bwd_pkts",
    "subflow_fwd_byts",
    "subflow_bwd_byts",
    "fwd_seg_size_avg",
    "bwd_seg_size_avg",
]


class TrainingConfig(BaseModel):
    """Configuration schema for Phase 3 model training and evaluation."""

    # Splitting strategy
    split_strategy: str = Field(
        default="global_chronological",
        description="Splitting method: 'global_chronological' (recommended, zero cross-label leakage), 'chronological_per_class', 'inter_day_chronological', or 'stratified_random'",
    )
    train_ratio: float = Field(default=0.70, ge=0.1, le=0.9)
    val_ratio: float = Field(default=0.15, ge=0.05, le=0.5)
    test_ratio: float = Field(default=0.15, ge=0.05, le=0.5)

    # Feature engineering safeguards
    include_dst_port: bool = Field(
        default=False,
        description="Whether to include dst_port. Excluded by default to prevent shortcut learning.",
    )
    prune_collinear_subflows: bool = Field(
        default=True,
        description="Whether to drop redundant subflow duplicates (Pearson r = 1.0).",
    )

    # Class imbalance handling
    use_class_weights: bool = Field(
        default=True,
        description="Apply inverse-frequency sample weights on training data only.",
    )
    max_class_weight: float = Field(
        default=500.0,
        description="Maximum multiplier clamp for ultra-rare class weights to stabilize variance.",
    )

    # Random Forest hyperparameters
    num_trees: int = Field(default=50, ge=1, le=500)
    max_depth: int = Field(default=10, ge=1, le=30)
    max_bins: int = Field(default=32, ge=8, le=128)
    seed: int = Field(default=42)

    # Resource and execution controls
    subsample_ratio: Optional[float] = Field(
        default=None,
        description="Optional fraction to downsample full dataset for testing or constrained execution (0.0 < ratio < 1.0).",
    )
    subsample_strategy: str = Field(
        default="stratified_per_class",
        description="Subsampling strategy: 'stratified_per_class' (preserves class distribution) or 'uniform_random'.",
    )
    protect_rare_classes: bool = Field(
        default=True,
        description="Retain 100% of classes with fewer than min_rare_class_samples during pilot subsampling.",
    )
    min_rare_class_samples: int = Field(
        default=500,
        description="Threshold below which rare classes are retained at 100% when protect_rare_classes=True.",
    )
    model_output_path: Optional[str] = None
    report_output_path: Optional[str] = None


def get_feature_columns(available_cols: List[str], config: TrainingConfig) -> List[str]:
    """Resolves and validates the strict list of features for model ingestion.

    Applies the following leakage and redundancy exclusions:
    - Metadata columns (labels, timestamps, dates, split indicators).
    - Destination port (unless explicitly enabled for shortcut comparison).
    - Known zero-variance constant columns.
    - Collinear subflow duplicate features (if enabled).

    Args:
        available_cols: Columns present in the dataset.
        config: Training configuration.

    Returns:
        List[str]: Clean, ordered list of feature column names.
    """
    excluded = set(EXCLUDED_METADATA_COLS)
    excluded.update(settings.constant_columns)

    if not config.include_dst_port:
        excluded.update(SHORTCUT_COLS)

    if config.prune_collinear_subflows:
        excluded.update(COLLINEAR_SUBFLOW_COLS)

    feature_cols = [c for c in available_cols if c not in excluded]
    logger.info(
        "Resolved %d features (Excluded: %d columns; include_dst_port=%s)",
        len(feature_cols),
        len(excluded),
        config.include_dst_port,
    )
    return feature_cols


def add_label_index(df: DataFrame) -> DataFrame:
    """Encodes canonical attack labels to deterministic numeric indices (0.0 to 13.0).

    Uses a fixed static mapping across all partitions and splits to prevent vocabulary drift.

    Args:
        df: Input DataFrame containing string 'label' column.

    Returns:
        DataFrame: DataFrame with 'label_idx' DoubleType column added.
    """
    items = list(LABEL_TO_INDEX.items())
    first_lbl, first_idx = items[0]
    label_expr = F.when(F.col("label") == first_lbl, float(first_idx))
    for lbl, idx in items[1:]:
        label_expr = label_expr.when(F.col("label") == lbl, float(idx))
    label_expr = label_expr.otherwise(-1.0)
    return df.withColumn("label_idx", label_expr.cast(DoubleType()))


def split_dataset(
    df: DataFrame,
    config: TrainingConfig,
) -> Tuple[DataFrame, DataFrame, DataFrame, Dict[str, Any]]:
    """Splits dataset into disjoint train, validation, and test sets.

    Supported strategies:
    - 'chronological_per_class': Within each class, sorts flows chronologically by
      timestamp_parsed to allocate contiguous time-blocks (train -> val -> test).
      Preserves rare single-day classes while preventing future-to-past temporal leakage.
    - 'inter_day_chronological': Partitions by calendar simulation days (train on early days,
      val on middle day, test on late days). Classes present only on early days honestly
      report zero test support.
    - 'stratified_random': Standard pseudo-random hashing across classes.

    Args:
        df: Input curated DataFrame.
        config: Training configuration.

    Returns:
        Tuple[DataFrame, DataFrame, DataFrame, Dict[str, Any]]:
            train_df, val_df, test_df, and split summary metadata.
    """
    logger.info("Executing dataset splitting with strategy: %s", config.split_strategy)

    if config.split_strategy == "global_chronological":
        # Global chronological time-block splitting across all classes simultaneously.
        # Enforces zero cross-label timestamp leakage: every flow occurring at timestamp T,
        # regardless of class, is assigned to the exact same split.
        ts_col = "timestamp_parsed" if "timestamp_parsed" in df.columns else "timestamp"
        if ts_col not in df.columns:
            raise ValueError(f"Chronological split requires timestamp column ('timestamp_parsed' or 'timestamp')")

        distinct_ts_df = df.select(ts_col).distinct()
        w_ord = Window.orderBy(ts_col)
        ranked_ts = distinct_ts_df.withColumn("_d_rank", F.dense_rank().over(w_ord))
        total_distinct = ranked_ts.count()

        if total_distinct <= 1:
            tagged_df = df.withColumn("split", F.lit("train"))
        elif total_distinct == 2:
            ts_rows = ranked_ts.collect()
            t1_val = ts_rows[0][ts_col]
            tagged_df = df.withColumn(
                "split",
                F.when(F.col(ts_col) == t1_val, F.lit("train")).otherwise(F.lit("test")),
            )
        else:
            k1 = max(1, min(int(total_distinct * config.train_ratio), total_distinct - 2))
            k2 = max(k1 + 1, min(int(total_distinct * (config.train_ratio + config.val_ratio)), total_distinct - 1))

            split_ts = ranked_ts.withColumn(
                "split",
                F.when(F.col("_d_rank") <= k1, F.lit("train"))
                .when(F.col("_d_rank") <= k2, F.lit("val"))
                .otherwise(F.lit("test")),
            ).select(ts_col, "split")

            tagged_df = df.join(split_ts, on=ts_col, how="inner")

    elif config.split_strategy == "chronological_per_class":
        # Deterministic, leakage-aware time-block splitting using distinct timestamps per class.
        ts_col = "timestamp_parsed" if "timestamp_parsed" in df.columns else "timestamp"
        if ts_col not in df.columns:
            raise ValueError(f"Chronological split requires timestamp column ('timestamp_parsed' or 'timestamp')")

        w_ord = Window.partitionBy("label").orderBy(ts_col)
        w_part = Window.partitionBy("label")

        ranked_df = df.withColumn("_d_rank", F.dense_rank().over(w_ord)).withColumn(
            "_max_d_rank", F.max("_d_rank").over(w_part)
        )

        # Dynamic cutoffs: when max_d_rank >= 3, guarantees all three splits receive >= 1 timestamp
        k1 = F.greatest(
            F.lit(1),
            F.least(
                F.floor(F.col("_max_d_rank") * F.lit(config.train_ratio)).cast("int"),
                F.col("_max_d_rank") - 2,
            ),
        )
        k2 = F.greatest(
            k1 + 1,
            F.least(
                F.floor(F.col("_max_d_rank") * F.lit(config.train_ratio + config.val_ratio)).cast("int"),
                F.col("_max_d_rank") - 1,
            ),
        )

        tagged_df = (
            ranked_df.withColumn(
                "split",
                F.when(F.col("_max_d_rank") == 1, F.lit("train"))
                .when(
                    F.col("_max_d_rank") == 2,
                    F.when(F.col("_d_rank") == 1, F.lit("train")).otherwise(F.lit("test")),
                )
                .otherwise(
                    F.when(F.col("_d_rank") <= k1, F.lit("train"))
                    .when(F.col("_d_rank") <= k2, F.lit("val"))
                    .otherwise(F.lit("test"))
                ),
            )
            .drop("_d_rank", "_max_d_rank")
        )

    elif config.split_strategy == "inter_day_chronological":
        # Train on Feb 14-21, Val on Feb 22, Test on Feb 28 - Mar 02
        train_dates = ["2018-02-14", "2018-02-15", "2018-02-16", "2018-02-21"]
        val_dates = ["2018-02-22"]

        tagged_df = df.withColumn(
            "split",
            F.when(F.col("event_date").isin(train_dates), F.lit("train"))
            .when(F.col("event_date").isin(val_dates), F.lit("val"))
            .otherwise(F.lit("test")),
        )

    elif config.split_strategy == "stratified_random":
        tagged_df = df.withColumn(
            "split_hash",
            F.abs(F.hash(F.col("label"), F.monotonically_increasing_id(), F.lit(config.seed))) % 100,
        ).withColumn(
            "split",
            F.when(F.col("split_hash") < int(config.train_ratio * 100), F.lit("train"))
            .when(
                F.col("split_hash") < int((config.train_ratio + config.val_ratio) * 100),
                F.lit("val"),
            )
            .otherwise(F.lit("test")),
        )
    else:
        raise ValueError(f"Unknown split strategy: {config.split_strategy}")

    # Isolate disjoint splits
    train_df = tagged_df.filter(F.col("split") == "train")
    val_df = tagged_df.filter(F.col("split") == "val")
    test_df = tagged_df.filter(F.col("split") == "test")

    # Aggregate distribution counts across splits
    split_counts = tagged_df.groupBy("label", "split").count().collect()
    summary: Dict[str, Dict[str, int]] = {"train": {}, "val": {}, "test": {}}
    for row in split_counts:
        lbl = str(row["label"])
        s_name = str(row["split"])
        cnt = int(row["count"])
        if s_name in summary:
            summary[s_name][lbl] = cnt

    total_train = sum(summary["train"].values())
    total_val = sum(summary["val"].values())
    total_test = sum(summary["test"].values())

    # Explicitly document rare-class and temporal coverage limitations
    class_support_coverage: Dict[str, Dict[str, Any]] = {}
    for lbl in LABEL_TO_INDEX.keys():
        n_train = summary["train"].get(lbl, 0)
        n_val = summary["val"].get(lbl, 0)
        n_test = summary["test"].get(lbl, 0)
        class_support_coverage[lbl] = {
            "train_support": n_train,
            "val_support": n_val,
            "test_support": n_test,
            "zero_train_support": n_train == 0,
            "zero_test_support": n_test == 0,
            "temporal_coverage": (
                "full_span" if n_train > 0 and n_val > 0 and n_test > 0
                else "train_only" if n_train > 0 and n_val == 0 and n_test == 0
                else "test_only" if n_train == 0 and n_val == 0 and n_test > 0
                else "val_only" if n_train == 0 and n_val > 0 and n_test == 0
                else "partial_span" if (n_train + n_val + n_test) > 0
                else "zero_dataset_support"
            ),
        }

    split_metadata = {
        "strategy": config.split_strategy,
        "ratios": {
            "train": config.train_ratio,
            "val": config.val_ratio,
            "test": config.test_ratio,
        },
        "total_rows": {
            "train": total_train,
            "val": total_val,
            "test": total_test,
            "all": total_train + total_val + total_test,
        },
        "class_counts_by_split": summary,
        "class_support_coverage": class_support_coverage,
    }

    logger.info(
        "Dataset split complete: Train=%d, Val=%d, Test=%d (Total=%d)",
        total_train,
        total_val,
        total_test,
        total_train + total_val + total_test,
    )
    return train_df, val_df, test_df, split_metadata


def subsample_dataset(
    df: DataFrame,
    config: TrainingConfig,
) -> Tuple[DataFrame, Dict[str, Any]]:
    """Applies reproducible subsampling for pilot testing while tracking rare-class support.

    Distinguishes transparently between:
    - 'stratified_per_class': samples each class independently according to config.subsample_ratio,
      with optional rare-class protection so micro-classes (like SQL Injection) are not wiped out.
    - 'uniform_random': standard DataFrame.sample(), which naturally reduces micro-classes to near-zero.

    Args:
        df: Input DataFrame.
        config: Training configuration.

    Returns:
        Tuple[DataFrame, Dict[str, Any]]: Subsampled DataFrame and sampling summary metadata.
    """
    if config.subsample_ratio is None or not (0.0 < config.subsample_ratio < 1.0):
        return df, {"applied": False}

    logger.info(
        "Applying pilot subsampling (strategy: %s, ratio: %.4f, protect_rare: %s)",
        config.subsample_strategy,
        config.subsample_ratio,
        config.protect_rare_classes,
    )

    # 1. Pre-sampling class counts
    pre_counts_rows = df.groupBy("label").count().collect()
    pre_counts = {str(r["label"]): int(r["count"]) for r in pre_counts_rows}
    total_pre = sum(pre_counts.values())

    if config.subsample_strategy == "stratified_per_class":
        fractions: Dict[str, float] = {}
        for lbl, cnt in pre_counts.items():
            if config.protect_rare_classes and cnt <= config.min_rare_class_samples:
                fractions[lbl] = 1.0
                logger.info(
                    "Protecting rare class '%s' (%d samples <= %d) with 100%% retention in pilot",
                    lbl,
                    cnt,
                    config.min_rare_class_samples,
                )
            else:
                fractions[lbl] = config.subsample_ratio

        sampled_df = df.stat.sampleBy("label", fractions, seed=config.seed)
    elif config.subsample_strategy == "uniform_random":
        sampled_df = df.sample(withReplacement=False, fraction=config.subsample_ratio, seed=config.seed)
    else:
        raise ValueError(f"Unknown subsample strategy: {config.subsample_strategy}")

    # 2. Post-sampling class counts
    post_counts_rows = sampled_df.groupBy("label").count().collect()
    post_counts = {str(r["label"]): int(r["count"]) for r in post_counts_rows}
    total_post = sum(post_counts.values())

    # Warning for classes at risk of starvation in downstream splits
    for lbl, cnt in post_counts.items():
        if cnt < 10:
            logger.warning(
                "Subsampled class '%s' has only %d samples; validation or test splits may have zero support.",
                lbl,
                cnt,
            )

    expected_unprotected = int(total_pre * (config.subsample_ratio or 1.0))
    excess_rows = max(0, total_post - expected_unprotected)
    effective_ratio = round(total_post / max(1, total_pre), 6)
    protected_classes = [
        lbl for lbl, cnt in pre_counts.items()
        if config.protect_rare_classes and cnt <= config.min_rare_class_samples
    ]

    sampling_summary = {
        "applied": True,
        "strategy": config.subsample_strategy,
        "target_subsample_ratio": config.subsample_ratio,
        "effective_subsample_ratio": effective_ratio,
        "protect_rare_classes": config.protect_rare_classes,
        "min_rare_class_samples": config.min_rare_class_samples,
        "protected_classes_retained_100pct": protected_classes,
        "expected_rows_unprotected": expected_unprotected,
        "actual_rows_sampled": total_post,
        "excess_rows_from_protection": excess_rows,
        "pre_sample_counts": pre_counts,
        "post_sample_counts": post_counts,
        "total_pre_sampling": total_pre,
        "total_post_sampling": total_post,
    }
    logger.info(
        "Subsampling complete: Pre=%d, Target Ratio=%.4f (Expected=%d), Actual Post=%d (Effective Ratio=%.4f, Excess Rows=%d)",
        total_pre,
        config.subsample_ratio or 1.0,
        expected_unprotected,
        total_post,
        effective_ratio,
        excess_rows,
    )
    return sampled_df, sampling_summary


def compute_class_weights(
    train_df: DataFrame, max_weight: float = 500.0
) -> Tuple[DataFrame, Dict[str, float]]:
    """Computes inverse-frequency balanced class weights strictly on training data.

    Formula: w_c = min(N / (K * N_c), max_weight)
    Ensures rare classes are not ignored by the tree splits while preventing
    extreme variance blowup from tiny classes.

    Args:
        train_df: Training DataFrame with 'label' and 'label_idx'.
        max_weight: Maximum multiplier clamp.

    Returns:
        Tuple[DataFrame, Dict[str, float]]: train_df with 'weight' column added, and weight dict.
    """
    logger.info("Computing balanced inverse-frequency class weights on training split...")
    counts = train_df.groupBy("label").count().collect()
    total_records = sum(int(r["count"]) for r in counts)
    active_classes = len(counts)

    weights_dict: Dict[str, float] = {}
    for r in counts:
        lbl = str(r["label"])
        c_count = int(r["count"])
        raw_w = total_records / (active_classes * c_count) if c_count > 0 else 1.0
        weights_dict[lbl] = round(float(min(raw_w, max_weight)), 4)

    w_items = list(weights_dict.items())
    if w_items:
        first_lbl, first_w = w_items[0]
        weight_expr = F.when(F.col("label") == first_lbl, F.lit(first_w))
        for lbl, w_val in w_items[1:]:
            weight_expr = weight_expr.when(F.col("label") == lbl, F.lit(w_val))
        weight_expr = weight_expr.otherwise(F.lit(1.0))
    else:
        weight_expr = F.lit(1.0)

    weighted_train_df = train_df.withColumn("weight", weight_expr.cast(DoubleType()))
    logger.info("Class weights computed for %d active classes in training split.", len(weights_dict))
    return weighted_train_df, weights_dict


def build_pipeline(feature_cols: List[str], config: TrainingConfig) -> Pipeline:
    """Assembles a modular PySpark ML Pipeline.

    Stages:
    1. StringIndexer for 'protocol' (if present in features).
    2. Imputer (median strategy) for all numeric features, fit on training data.
    3. VectorAssembler to generate dense feature vectors.
    4. RandomForestClassifier with configurable parameters and optional sample weights.

    Args:
        feature_cols: Cleaned list of input feature names.
        config: Training configuration.

    Returns:
        Pipeline: Unfitted Spark ML Pipeline.
    """
    stages: List[Any] = []
    numeric_cols = [c for c in feature_cols if c != "protocol"]

    # Impute missing or NaN values using median strategy
    imputed_output_cols = [f"{c}__imp" for c in numeric_cols]
    imputer = Imputer(
        inputCols=numeric_cols,
        outputCols=imputed_output_cols,
        strategy="median",
    )
    stages.append(imputer)

    # Encode categorical protocol if present
    assembler_inputs = list(imputed_output_cols)
    if "protocol" in feature_cols:
        protocol_indexer = StringIndexer(
            inputCol="protocol",
            outputCol="protocol_idx",
            handleInvalid="keep",
        )
        stages.append(protocol_indexer)
        assembler_inputs.append("protocol_idx")

    assembler = VectorAssembler(
        inputCols=assembler_inputs,
        outputCol="features",
        handleInvalid="error",
    )
    stages.append(assembler)

    # Instantiate Random Forest
    rf_kwargs: Dict[str, Any] = {
        "featuresCol": "features",
        "labelCol": "label_idx",
        "predictionCol": "prediction",
        "probabilityCol": "probability",
        "rawPredictionCol": "rawPrediction",
        "numTrees": config.num_trees,
        "maxDepth": config.max_depth,
        "maxBins": config.max_bins,
        "seed": config.seed,
    }
    if config.use_class_weights:
        rf_kwargs["weightCol"] = "weight"

    rf = RandomForestClassifier(**rf_kwargs)
    stages.append(rf)

    logger.info("Constructed ML Pipeline with %d stages.", len(stages))
    return Pipeline(stages=stages)


def evaluate_predictions(
    predictions: DataFrame,
    split_name: str = "test",
) -> Dict[str, Any]:
    """Computes comprehensive multiclass and binary threat evaluation metrics.

    Evaluates:
    - Overall accuracy and majority-class baseline.
    - Macro-F1, Weighted-F1, and Balanced Accuracy (averaging over non-empty true classes).
    - Per-class precision, recall, F1, true support, and predicted support.
    - Full 14x14 raw and row-normalized confusion matrices.
    - Binary threat detection: True Positive Rate (Attack Recall), False Alarm Rate (FPR),
      Attack Precision, and Attack F1.

    Args:
        predictions: DataFrame containing 'label_idx' and 'prediction' columns.
        split_name: Name of evaluated partition ('val' or 'test').

    Returns:
        Dict[str, Any]: Complete metrics report.
    """
    logger.info("Aggregating multiclass confusion matrix for %s split...", split_name)

    # Aggregate contingency table distributed in Spark (at most 14x14 = 196 rows collected)
    contingency_rows = (
        predictions.groupBy("label_idx", "prediction")
        .count()
        .collect()
    )

    # Construct 14x14 matrix
    matrix = np.zeros((NUM_CLASSES, NUM_CLASSES), dtype=np.int64)
    for r in contingency_rows:
        true_idx = int(r["label_idx"])
        pred_idx = int(r["prediction"])
        cnt = int(r["count"])
        if 0 <= true_idx < NUM_CLASSES and 0 <= pred_idx < NUM_CLASSES:
            matrix[true_idx, pred_idx] = cnt

    total_samples = int(matrix.sum())
    true_support = matrix.sum(axis=1)
    pred_support = matrix.sum(axis=0)

    # Per-class metrics
    per_class_results = []
    active_recalls = []
    active_f1s = []
    weighted_f1_sum = 0.0
    weighted_prec_sum = 0.0
    weighted_rec_sum = 0.0

    for i in range(NUM_CLASSES):
        c_name = INDEX_TO_LABEL[i]
        t_sup = int(true_support[i])
        p_sup = int(pred_support[i])
        tp = int(matrix[i, i])

        prec = round(float(tp / p_sup), 4) if p_sup > 0 else None
        rec = round(float(tp / t_sup), 4) if t_sup > 0 else None

        if prec is not None and rec is not None and (prec + rec) > 0:
            f1 = round(float(2 * prec * rec / (prec + rec)), 4)
        elif t_sup > 0:
            f1 = 0.0
        else:
            f1 = None

        if t_sup > 0:
            active_recalls.append(rec if rec is not None else 0.0)
            active_f1s.append(f1 if f1 is not None else 0.0)
            weighted_f1_sum += (f1 if f1 is not None else 0.0) * t_sup
            weighted_prec_sum += (prec if prec is not None else 0.0) * t_sup
            weighted_rec_sum += (rec if rec is not None else 0.0) * t_sup

        per_class_results.append({
            "class_index": i,
            "class_name": c_name,
            "true_support": t_sup,
            "predicted_support": p_sup,
            "precision": prec,
            "recall": rec,
            "f1_score": f1,
            "zero_test_support": t_sup == 0,
            "zero_predictions": p_sup == 0,
        })

    # Summary metrics
    overall_acc = round(float(np.trace(matrix) / total_samples), 4) if total_samples > 0 else 0.0
    majority_count = int(np.max(true_support)) if total_samples > 0 else 0
    majority_baseline_acc = round(float(majority_count / total_samples), 4) if total_samples > 0 else 0.0

    macro_f1 = round(float(np.mean(active_f1s)), 4) if active_f1s else 0.0
    balanced_acc = round(float(np.mean(active_recalls)), 4) if active_recalls else 0.0
    weighted_f1 = round(float(weighted_f1_sum / total_samples), 4) if total_samples > 0 else 0.0
    weighted_prec = round(float(weighted_prec_sum / total_samples), 4) if total_samples > 0 else 0.0
    weighted_rec = round(float(weighted_rec_sum / total_samples), 4) if total_samples > 0 else 0.0

    # Binary threat detection metrics: Benign (index 0) vs. All Attacks (indices 1 to 13)
    tn = int(matrix[0, 0])
    fp = int(matrix[0, 1:].sum())
    fn = int(matrix[1:, 0].sum())
    tp_attack = int(matrix[1:, 1:].sum())

    benign_total = tn + fp
    attack_total = tp_attack + fn

    false_alarm_rate = round(float(fp / benign_total), 4) if benign_total > 0 else 0.0
    attack_detection_rate = round(float(tp_attack / attack_total), 4) if attack_total > 0 else 0.0
    attack_prec = round(float(tp_attack / (tp_attack + fp)), 4) if (tp_attack + fp) > 0 else 0.0
    attack_f1 = (
        round(float(2 * attack_prec * attack_detection_rate / (attack_prec + attack_detection_rate)), 4)
        if (attack_prec + attack_detection_rate) > 0
        else 0.0
    )

    # Confusion matrix serialized structures
    class_names = [INDEX_TO_LABEL[i] for i in range(NUM_CLASSES)]
    norm_matrix = np.zeros((NUM_CLASSES, NUM_CLASSES), dtype=float)
    for i in range(NUM_CLASSES):
        if true_support[i] > 0:
            norm_matrix[i, :] = np.round(matrix[i, :] / true_support[i], 4)

    return {
        "evaluated_split": split_name,
        "total_evaluated_samples": total_samples,
        "overall_accuracy": overall_acc,
        "majority_class_baseline_accuracy": majority_baseline_acc,
        "macro_f1": macro_f1,
        "weighted_f1": weighted_f1,
        "weighted_precision": weighted_prec,
        "weighted_recall": weighted_rec,
        "balanced_accuracy": balanced_acc,
        "binary_threat_detection": {
            "benign_total": benign_total,
            "attack_total": attack_total,
            "true_negatives_benign": tn,
            "false_positives_alarms": fp,
            "false_negatives_missed": fn,
            "true_positives_detected": tp_attack,
            "false_alarm_rate": false_alarm_rate,
            "attack_detection_rate": attack_detection_rate,
            "attack_precision": attack_prec,
            "attack_f1_score": attack_f1,
        },
        "per_class_metrics": per_class_results,
        "confusion_matrix": {
            "class_labels": class_names,
            "raw_matrix": matrix.tolist(),
            "normalized_matrix": norm_matrix.tolist(),
        },
        "calibration_notice": (
            "RandomForestClassifier probabilities in Spark MLlib represent uncalibrated "
            "empirical tree voting fractions and should be validated before probabilistic scaling."
        ),
    }


def save_artifacts(
    pipeline_model: PipelineModel,
    feature_cols: List[str],
    config: TrainingConfig,
    split_metadata: Dict[str, Any],
    eval_report: Dict[str, Any],
    model_dir: Path,
    report_path: Path,
) -> Dict[str, str]:
    """Persists trained model, metadata, configurations, and evaluation reports.

    Args:
        pipeline_model: Fitted Spark ML PipelineModel.
        feature_cols: Ordered list of feature names.
        config: Training configuration used.
        split_metadata: Summary of dataset splitting.
        eval_report: Test evaluation results.
        model_dir: Target directory for Spark model.
        report_path: Target path for JSON evaluation report.

    Returns:
        Dict[str, str]: Paths of persisted artifacts.
    """
    model_dir = Path(model_dir)
    report_path = Path(report_path)
    model_dir.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    # 1. Save Spark ML PipelineModel
    logger.info("Persisting trained PipelineModel to %s", model_dir)
    pipeline_model.write().overwrite().save(str(model_dir))

    # 2. Extract Random Forest feature importances
    rf_stage = None
    for stage in pipeline_model.stages:
        if isinstance(stage, RandomForestClassificationModel):
            rf_stage = stage
            break

    importances_dict = {}
    if rf_stage is not None and hasattr(rf_stage, "featureImportances"):
        raw_importances = [float(x) for x in rf_stage.featureImportances.toArray()]
        # Match with assembled feature names
        imputed_features = [f"{c}__imp" for c in feature_cols if c != "protocol"]
        if "protocol" in feature_cols:
            imputed_features.append("protocol_idx")

        for idx, f_name in enumerate(imputed_features):
            if idx < len(raw_importances):
                importances_dict[f_name] = round(float(raw_importances[idx]), 6)

        # Sort descending
        importances_dict = dict(sorted(importances_dict.items(), key=lambda item: item[1], reverse=True))

    # 3. Save feature metadata
    metadata = {
        "ordered_features": feature_cols,
        "features_count": len(feature_cols),
        "excluded_metadata": EXCLUDED_METADATA_COLS,
        "collinear_subflows_pruned": config.prune_collinear_subflows,
        "include_dst_port": config.include_dst_port,
        "feature_importances": importances_dict,
    }
    metadata_path = model_dir.parent / "feature_metadata.json"
    save_json_report(metadata, metadata_path)

    # 4. Save label mapping
    label_mapping_data = {
        "label_to_index": LABEL_TO_INDEX,
        "index_to_label": INDEX_TO_LABEL,
        "num_classes": NUM_CLASSES,
    }
    label_path = model_dir.parent / "label_mapping.json"
    save_json_report(label_mapping_data, label_path)

    # 5. Save training configuration & split summary
    save_json_report(config.model_dump(), model_dir.parent / "training_config.json")
    save_json_report(split_metadata, model_dir.parent / "split_summary.json")

    # 6. Save complete evaluation report
    eval_report["timestamp"] = datetime.now().isoformat()
    eval_report["model_location"] = str(model_dir)
    eval_report["feature_metadata_location"] = str(metadata_path)
    eval_report["label_mapping_location"] = str(label_path)
    eval_report["top_10_feature_importances"] = dict(list(importances_dict.items())[:10])
    save_json_report(eval_report, report_path)

    return {
        "model_dir": str(model_dir),
        "metadata_path": str(metadata_path),
        "label_path": str(label_path),
        "report_path": str(report_path),
    }


def load_model(model_dir: Path) -> PipelineModel:
    """Loads a previously persisted Spark ML PipelineModel.

    Args:
        model_dir: Path to directory where model was saved.

    Returns:
        PipelineModel: Reconstituted PipelineModel.
    """
    return PipelineModel.load(str(model_dir))


def train_and_evaluate(
    spark: Optional[SparkSession] = None,
    parquet_path: Optional[Path] = None,
    config: Optional[TrainingConfig] = None,
) -> Dict[str, Any]:
    """Executes the complete Phase 3 Random Forest training and evaluation workflow.

    Workflow:
    1. Loads dataset from flows.parquet.
    2. Maps labels to fixed numeric indices.
    3. Resolves feature columns and prunes leakage-prone columns.
    4. Executes contiguous chronological or stratified splitting.
    5. Computes inverse-frequency class weights on training data only.
    6. Fits PySpark ML Pipeline (Imputer -> Assembler -> RandomForest).
    7. Evaluates predictions on held-out test data.
    8. Persists model and metrics artifacts.

    Args:
        spark: Active SparkSession. If None, initialized via get_spark_session().
        parquet_path: Path to input parquet. Defaults to settings.flows_parquet_path.
        config: Training configuration. Defaults to baseline TrainingConfig().

    Returns:
        Dict[str, Any]: Execution summary with evaluation report and artifact locations.
    """
    start_time = datetime.now()
    cfg = config or TrainingConfig()
    spark = spark or get_spark_session(app_name="ThreatLenz-Phase3-Training")

    target_parquet = parquet_path or settings.flows_parquet_path
    logger.info("=== Starting ThreatLenz Phase 3 ML Pipeline ===")
    logger.info("Loading flows dataset from: %s", target_parquet)

    if not target_parquet.exists():
        raise FileNotFoundError(f"Processed dataset not found at {target_parquet}")

    raw_df = spark.read.parquet(str(target_parquet))

    # Optional subsampling for constrained test runs
    sampling_summary: Dict[str, Any] = {"applied": False}
    if cfg.subsample_ratio is not None and 0.0 < cfg.subsample_ratio < 1.0:
        raw_df, sampling_summary = subsample_dataset(raw_df, cfg)

    # 1. Deterministic label indexing
    indexed_df = add_label_index(raw_df)

    # 2. Resolve leakage-safe feature columns
    feature_cols = get_feature_columns(indexed_df.columns, cfg)

    # Cast numeric feature columns to DoubleType and sanitize non-finites for Spark Imputer compatibility
    for col_name in feature_cols:
        if col_name != "protocol":
            sanitized_col = (
                F.when(
                    F.isnan(F.col(col_name))
                    | (F.col(col_name) == float("inf"))
                    | (F.col(col_name) == float("-inf")),
                    F.lit(None),
                )
                .otherwise(F.col(col_name))
                .cast(DoubleType())
            )
            indexed_df = indexed_df.withColumn(col_name, sanitized_col)

    # 3. Disjoint dataset splitting
    train_df, val_df, test_df, split_metadata = split_dataset(indexed_df, cfg)
    split_metadata["sampling_summary"] = sampling_summary

    # 4. Compute balanced class weights strictly on training data
    if cfg.use_class_weights:
        train_df, _ = compute_class_weights(train_df, max_weight=cfg.max_class_weight)
        # Assign neutral weight to val and test sets to maintain schema parity
        val_df = val_df.withColumn("weight", F.lit(1.0))
        test_df = test_df.withColumn("weight", F.lit(1.0))

    # 5. Build and fit pipeline
    pipeline = build_pipeline(feature_cols, cfg)
    logger.info("Fitting Spark ML Pipeline on training data (%d rows)...", train_df.count())
    pipeline_model = pipeline.fit(train_df)
    logger.info("PipelineModel training completed successfully.")

    # 6. Generate predictions and evaluate on held-out test split
    logger.info("Evaluating predictions on held-out test split (%d rows)...", test_df.count())
    test_predictions = pipeline_model.transform(test_df)
    eval_report = evaluate_predictions(test_predictions, split_name="test")

    # Also evaluate validation split for threshold checking
    val_predictions = pipeline_model.transform(val_df)
    val_report = evaluate_predictions(val_predictions, split_name="val")

    # 7. Persist artifacts
    model_output_dir = Path(cfg.model_output_path or (settings.models_dir / "random_forest_model"))
    report_output_path = Path(cfg.report_output_path or (settings.reports_dir / "model_evaluation_report.json"))

    full_report = {
        "pipeline_name": "ThreatLenz-Phase3-RandomForest",
        "training_duration_seconds": round((datetime.now() - start_time).total_seconds(), 2),
        "training_configuration": cfg.model_dump(),
        "split_summary": split_metadata,
        "validation_metrics": val_report,
        "test_metrics": eval_report,
    }

    artifact_paths = save_artifacts(
        pipeline_model=pipeline_model,
        feature_cols=feature_cols,
        config=cfg,
        split_metadata=split_metadata,
        eval_report=full_report,
        model_dir=model_output_dir,
        report_path=report_output_path,
    )

    logger.info("=== ThreatLenz Phase 3 ML Pipeline Completed in %.2f seconds ===", full_report["training_duration_seconds"])
    return {
        "status": "success",
        "artifacts": artifact_paths,
        "summary_metrics": {
            "test_accuracy": eval_report["overall_accuracy"],
            "majority_baseline_accuracy": eval_report["majority_class_baseline_accuracy"],
            "macro_f1": eval_report["macro_f1"],
            "balanced_accuracy": eval_report["balanced_accuracy"],
            "attack_detection_rate": eval_report["binary_threat_detection"]["attack_detection_rate"],
            "false_alarm_rate": eval_report["binary_threat_detection"]["false_alarm_rate"],
        },
    }


if __name__ == "__main__":
    train_and_evaluate()
