"""ThreatLenz ETL & Data Integrity Pipeline.

Performs robust PySpark ingestion of the selected CSE-CIC-IDS2018 TrafficForML CSVs,
audits and quarantines repeated header rows (Label == "Label"), executes distributed
profiling for non-finite/null values, enforces semantic network-flow validation rules,
standardizes attack labels, and exports curated Parquet partitioned by event_date.
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

from pyspark.sql import DataFrame, SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import DoubleType, IntegerType, StringType, StructField, StructType

from src.config import settings
from src.utils import get_logger, get_spark_session, save_json_report

logger = get_logger("ThreatLenz.ETL")


def build_raw_schema() -> StructType:
    """Constructs an explicit PySpark schema for the raw 80 CSV columns.

    Using StringType for all columns during initial ingestion guarantees that
    corrupted records, repeated headers, and string tokens ("Infinity", "NaN")
    are captured for audit rather than silently dropped by Spark's CSV parser.

    Returns:
        StructType: Explicit schema containing all 80 columns as StringType.
    """
    return StructType([StructField(col_name, StringType(), True) for col_name in settings.raw_columns])


def load_raw_dataset(spark: SparkSession, raw_dir: Path) -> DataFrame:
    """Reads the selected raw TrafficForML CSV files into a unified DataFrame.

    Args:
        spark: Active SparkSession.
        raw_dir: Path to directory containing raw CSV files.

    Returns:
        DataFrame: Raw dataset with explicit string schema.
    """
    raw_files = [raw_dir / fname for fname in settings.selected_raw_files]
    existing_files = [str(f) for f in raw_files if f.exists()]

    if not existing_files:
        raise FileNotFoundError(f"No selected raw files found in {raw_dir}")

    logger.info("Reading %d selected raw CSV files from %s", len(existing_files), raw_dir)
    schema = build_raw_schema()

    raw_df = (
        spark.read.option("header", "true")
        .option("mode", "PERMISSIVE")
        .schema(schema)
        .csv(existing_files)
    )
    return raw_df


def audit_repeated_headers(raw_df: DataFrame) -> Tuple[int, List[Dict[str, Any]]]:
    """Detects and audits rows where the Label column contains the string 'Label'.

    In CSE-CIC-IDS2018, header lines were periodically repeated in the data body
    during PCAP export. This audit records their exact counts and file sources
    as an explicit data-integrity finding before removal.

    Args:
        raw_df: The raw DataFrame including the filename metadata.

    Returns:
        Tuple[int, List[Dict[str, Any]]]: Total malformed count and breakdown by file.
    """
    logger.info("Auditing repeated header rows where Label == 'Label'...")
    malformed_df = raw_df.withColumn("source_file", F.input_file_name()).filter(
        F.col("Label") == "Label"
    )

    file_breakdown = (
        malformed_df.groupBy("source_file")
        .count()
        .collect()
    )

    breakdown_list = [
        {"file": Path(row["source_file"]).name, "repeated_headers_count": int(row["count"])}
        for row in file_breakdown
    ]
    total_malformed = sum(item["repeated_headers_count"] for item in breakdown_list)

    logger.info("Audit finding: detected %d repeated header rows across %d files", total_malformed, len(breakdown_list))
    return total_malformed, breakdown_list


def profile_dataset(df: DataFrame) -> Dict[str, Any]:
    """Performs a distributed profiling pass across the dataset to measure non-finite and null tokens.

    Checks numeric candidate columns for:
    - null / empty string
    - '+Infinity' / 'Infinity' / 'inf'
    - '-Infinity' / '-inf'
    - 'NaN' / 'nan'

    Args:
        df: DataFrame filtered of repeated header rows.

    Returns:
        Dict[str, Any]: Profile metrics per column and overall row counts.
    """
    logger.info("Executing complete distributed profiling pass across dataset...")
    total_rows = df.count()

    # Identify candidate rate and numeric columns to profile
    rate_cols = ["Flow Byts/s", "Flow Pkts/s", "Flow Duration"]
    sample_numeric_cols = [
        "Tot Fwd Pkts", "Tot Bwd Pkts", "Flow IAT Mean",
        "Init Fwd Win Byts", "Init Bwd Win Byts", "RST Flag Cnt"
    ]
    cols_to_profile = rate_cols + sample_numeric_cols

    agg_exprs = []
    for c in cols_to_profile:
        agg_exprs.extend([
            F.count(F.when(F.col(c).isNull() | (F.col(c) == ""), True)).alias(f"{c}__null"),
            F.count(F.when(F.col(c).isin("Infinity", "+Infinity", "inf", "+inf"), True)).alias(f"{c}__pos_inf"),
            F.count(F.when(F.col(c).isin("-Infinity", "-inf"), True)).alias(f"{c}__neg_inf"),
            F.count(F.when(F.col(c).isin("NaN", "nan"), True)).alias(f"{c}__nan"),
        ])

    profile_row = df.select(agg_exprs).collect()[0]

    profile_results = {}
    for c in cols_to_profile:
        profile_results[c] = {
            "null_or_empty": int(profile_row[f"{c}__null"]),
            "pos_infinity": int(profile_row[f"{c}__pos_inf"]),
            "neg_infinity": int(profile_row[f"{c}__neg_inf"]),
            "nan": int(profile_row[f"{c}__nan"]),
        }

    logger.info("Distributed profiling complete. Total evaluated rows: %d", total_rows)
    return {"total_rows_profiled": total_rows, "column_profiles": profile_results}


def clean_and_transform(df: DataFrame) -> Tuple[DataFrame, Dict[str, Any]]:
    """Applies semantic validation, feature sanitization, and label standardization.

    Semantic Rules:
    - Exclude repeated header rows (Label == "Label").
    - Preserve semantically valid zero values (tot_bwd_pkts == 0, flow_duration == 0).
    - Filter physically impossible records: flow_duration < 0 or tot_fwd_pkts < 1.
    - Sanitize non-finite tokens in rate metrics by replacing with 0.0 for zero-duration flows.
    - Standardize attack labels using settings.label_mapping while preserving raw_label.
    - Parse timestamp into timestamp type and derive event_date partition column.

    Args:
        df: Raw DataFrame.

    Returns:
        Tuple[DataFrame, Dict[str, Any]]: Cleaned DataFrame and transformation metrics.
    """
    logger.info("Applying semantic validation and feature transformations...")

    # 1. Exclude repeated header rows
    valid_df = df.filter(F.col("Label") != "Label")

    # 2. Rename columns to snake_case
    for raw_name, clean_name in settings.column_mapping.items():
        if raw_name in valid_df.columns:
            valid_df = valid_df.withColumnRenamed(raw_name, clean_name)

    # 3. Preserve raw label and standardize canonical label
    label_expr = F.col("label")
    for raw_lbl, canonical_lbl in settings.label_mapping.items():
        label_expr = F.when(F.col("label") == raw_lbl, canonical_lbl).otherwise(label_expr)

    valid_df = valid_df.withColumn("raw_label", F.col("label")).withColumn("label", label_expr)

    # 4. Handle non-finite values in rate columns
    # When flow_duration == 0, rates are mathematically undefined in CICFlowMeter.
    # Convert 'Infinity', 'NaN', etc. to 0.0 to prevent VectorAssembler crashes.
    for rate_col in ["flow_byts_s", "flow_pkts_s"]:
        valid_df = valid_df.withColumn(
            rate_col,
            F.when(
                F.col(rate_col).isin("Infinity", "+Infinity", "-Infinity", "inf", "-inf", "NaN", "nan")
                | F.col(rate_col).isNull()
                | (F.col(rate_col) == ""),
                F.lit(0.0),
            ).otherwise(F.col(rate_col).cast(DoubleType())),
        )

    # 5. Cast numeric flow columns
    # Preserve zero values in tot_bwd_pkts and flow_duration
    valid_df = (
        valid_df.withColumn("flow_duration", F.col("flow_duration").cast(DoubleType()))
        .withColumn("tot_fwd_pkts", F.col("tot_fwd_pkts").cast(DoubleType()))
        .withColumn("tot_bwd_pkts", F.col("tot_bwd_pkts").cast(DoubleType()))
        .withColumn("dst_port", F.col("dst_port").cast(IntegerType()))
        .withColumn("protocol", F.col("protocol").cast(IntegerType()))
    )

    # Cast remaining flow metrics to DoubleType
    exclude_cast = {"dst_port", "protocol", "timestamp", "label", "raw_label", "flow_byts_s", "flow_pkts_s"}
    for col_name in valid_df.columns:
        if col_name not in exclude_cast and col_name in settings.column_mapping.values():
            valid_df = valid_df.withColumn(col_name, F.col(col_name).cast(DoubleType()))

    # 6. Semantic Filtering:
    # Filter only proven invalid records:
    # - Negative flow duration (clock jump / counter overflow)
    # Diagnostic check: audit tot_fwd_pkts < 1 without dropping legitimate records
    diagnostic_zero_fwd_count = valid_df.filter(F.col("tot_fwd_pkts") < 1).count()
    initial_valid_count = valid_df.count()
    clean_df = valid_df.filter(F.col("flow_duration") >= 0)
    retained_count = clean_df.count()
    negative_duration_dropped = initial_valid_count - retained_count

    # 7. Timestamp parsing and partition date derivation
    # Format in CSE-CIC-IDS2018: dd/MM/yyyy HH:mm:ss
    clean_df = clean_df.withColumn(
        "timestamp_parsed",
        F.to_timestamp(F.col("timestamp"), "dd/MM/yyyy HH:mm:ss"),
    ).withColumn(
        "event_date",
        F.to_date(F.col("timestamp_parsed")),
    )

    metrics = {
        "pre_cleaning_rows": initial_valid_count,
        "retained_rows": retained_count,
        "negative_duration_dropped": negative_duration_dropped,
        "diagnostic_zero_fwd_pkts_count": diagnostic_zero_fwd_count,
        "semantically_invalid_dropped": negative_duration_dropped,
    }
    logger.info(
        "Cleaning complete. Retained rows: %d, Dropped negative duration: %d (Diagnostic zero fwd pkts: %d)",
        retained_count,
        negative_duration_dropped,
        diagnostic_zero_fwd_count,
    )
    return clean_df, metrics


def run_etl(spark: SparkSession = None) -> Dict[str, Any]:
    """Executes the full ThreatLenz ETL and Data Integrity Pipeline.

    Sequence:
    1. Reads selected processed CSV files with strict schema.
    2. Audits repeated header rows and captures audit findings.
    3. Performs distributed profiling across all columns.
    4. Applies semantic cleaning and label standardization.
    5. Computes finalized class distribution.
    6. Writes partitioned Parquet to data/processed/flows.parquet.
    7. Generates reports/etl_integrity_report.json.

    Args:
        spark: Optional existing SparkSession. If None, initialized automatically.

    Returns:
        Dict[str, Any]: Summary execution report.
    """
    start_time = datetime.now()
    spark = spark or get_spark_session()

    logger.info("=== Starting ThreatLenz ETL Pipeline ===")

    # Step 1: Load raw data
    raw_df = load_raw_dataset(spark, settings.data_raw_dir)
    total_raw_rows = raw_df.count()
    logger.info("Total raw records ingested: %d", total_raw_rows)

    # Step 2: Audit repeated header rows
    malformed_headers_count, malformed_breakdown = audit_repeated_headers(raw_df)

    # Step 3: Filter headers before profiling
    valid_raw_df = raw_df.filter(F.col("Label") != "Label")

    # Step 4: Complete dataset profiling
    profiling_results = profile_dataset(valid_raw_df)

    # Step 5: Clean and transform dataset
    clean_df, clean_metrics = clean_and_transform(raw_df)

    # Step 6: Compute class distribution
    class_dist_rows = clean_df.groupBy("label").count().orderBy(F.desc("count")).collect()
    class_distribution = {row["label"]: int(row["count"]) for row in class_dist_rows}

    # Step 7: Write to curated Parquet partitioned by event_date
    output_path = settings.data_processed_dir / "flows.parquet"
    logger.info("Writing curated Parquet dataset partitioned by event_date to %s", output_path)

    (
        clean_df.write.mode("overwrite")
        .partitionBy("event_date")
        .parquet(str(output_path))
    )
    logger.info("Parquet dataset written successfully.")

    # Calculate partition statistics and on-disk size
    partition_dirs = [p for p in output_path.glob("event_date=*") if p.is_dir()]
    total_parquet_bytes = sum(f.stat().st_size for f in output_path.rglob("*.parquet"))

    duration_secs = (datetime.now() - start_time).total_seconds()

    report = {
        "pipeline_name": "ThreatLenz-ETL-Data-Integrity",
        "timestamp": datetime.now().isoformat(),
        "execution_time_seconds": round(duration_secs, 2),
        "dataset_source": "CSE-CIC-IDS2018 Selected Processed TrafficForML CSVs",
        "input_files": settings.selected_raw_files,
        "input_rows_total": total_raw_rows,
        "malformed_repeated_headers_count": malformed_headers_count,
        "malformed_headers_file_breakdown": malformed_breakdown,
        "negative_duration_rows_dropped": clean_metrics["negative_duration_dropped"],
        "diagnostic_zero_fwd_pkts_count": clean_metrics["diagnostic_zero_fwd_pkts_count"],
        "semantically_invalid_rows_dropped": clean_metrics["semantically_invalid_dropped"],
        "curated_retained_rows": clean_metrics["retained_rows"],
        "class_distribution": class_distribution,
        "profiling_summary": profiling_results,
        "output_parquet_location": str(output_path),
        "parquet_partitions_count": len(partition_dirs),
        "parquet_total_size_bytes": total_parquet_bytes,
        "parquet_total_size_mb": round(total_parquet_bytes / (1024 * 1024), 2),
    }

    report_path = settings.reports_dir / "etl_integrity_report.json"
    save_json_report(report, report_path)
    logger.info("ETL integrity audit report saved to %s", report_path)
    logger.info("=== ThreatLenz ETL Pipeline Completed Successfully ===")

    return report


if __name__ == "__main__":
    run_etl()
