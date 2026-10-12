"""Unit tests for ThreatLenz ETL and Data Integrity validation."""

import pytest
from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import Row

from src.config import settings
from src.etl import (
    audit_repeated_headers,
    build_raw_schema,
    clean_and_transform,
    profile_dataset,
)
from src.utils import get_spark_session


@pytest.fixture(scope="session")
def spark() -> SparkSession:
    """Provides a shared local SparkSession for unit tests."""
    return get_spark_session(
        app_name="ThreatLenz-ETL-Tests",
        master="local[2]",
        driver_memory="2g",
        shuffle_partitions=2,
    )


def test_build_raw_schema():
    """Verify that build_raw_schema constructs an 80-column StringType schema."""
    schema = build_raw_schema()
    assert len(schema.fields) == 80
    assert schema.fields[0].name == "Dst Port"
    assert schema.fields[-1].name == "Label"
    for field in schema.fields:
        assert field.dataType.simpleString() == "string"


def test_repeated_header_detection(spark: SparkSession):
    """Verify that rows with Label == 'Label' are detected as repeated headers."""
    schema = build_raw_schema()
    # Create two rows: one normal, one repeated header
    row_benign = {col: "0" for col in settings.raw_columns}
    row_benign["Label"] = "Benign"

    row_header = {col: col for col in settings.raw_columns}
    row_header["Label"] = "Label"

    df = spark.createDataFrame([row_benign, row_header], schema=schema)

    total_malformed, breakdown = audit_repeated_headers(df)
    assert total_malformed == 1
    assert len(breakdown) == 1


def test_clean_and_transform_semantic_preservation(spark: SparkSession):
    """Verify semantic rules:

    - Preserve tot_bwd_pkts == 0 (valid unidirectional flow)
    - Preserve flow_duration == 0 (valid instantaneous flow)
    - Drop flow_duration < 0 (physically invalid)
    - Count tot_fwd_pkts < 1 diagnostically without dropping
    - Sanitize 'Infinity' and 'NaN' rate strings to 0.0
    - Standardize 'Infilteration' -> 'Infiltration' and preserve raw_label
    - Parse timestamp into timestamp and event_date
    """
    schema = build_raw_schema()

    def make_row(label, duration, fwd_pkts, bwd_pkts, byts_s="0", pkts_s="0", ts="14/02/2018 08:31:01"):
        r = {col: "0" for col in settings.raw_columns}
        r["Label"] = label
        r["Flow Duration"] = str(duration)
        r["Tot Fwd Pkts"] = str(fwd_pkts)
        r["Tot Bwd Pkts"] = str(bwd_pkts)
        r["Flow Byts/s"] = str(byts_s)
        r["Flow Pkts/s"] = str(pkts_s)
        r["Timestamp"] = ts
        return r

    rows = [
        # Row 1: Valid flow with typo label
        make_row("Infilteration", 1000, 5, 4, byts_s="1234.5", pkts_s="50.0"),
        # Row 2: Valid zero-duration and zero-bwd-pkts with Infinity/NaN rates
        make_row("Benign", 0, 1, 0, byts_s="Infinity", pkts_s="NaN"),
        # Row 3: Malformed repeated header
        {col: col for col in settings.raw_columns},
        # Row 4: Invalid negative flow duration
        make_row("Benign", -500, 2, 2),
        # Row 5: Invalid zero forward packets
        make_row("Benign", 200, 0, 1),
    ]

    df = spark.createDataFrame(rows, schema=schema)
    clean_df, metrics = clean_and_transform(df)

    # Malformed header excluded, negative duration dropped, zero fwd pkts preserved
    assert metrics["semantically_invalid_dropped"] == 1
    assert metrics["negative_duration_dropped"] == 1
    assert metrics["diagnostic_zero_fwd_pkts_count"] == 1
    assert clean_df.count() == 3

    collected = clean_df.collect()

    # Verify Row 1: Infiltration standardized, raw_label preserved
    r1 = [r for r in collected if r["raw_label"] == "Infilteration"][0]
    assert r1["label"] == "Infiltration"
    assert r1["raw_label"] == "Infilteration"
    assert r1["flow_duration"] == 1000.0
    assert r1["tot_bwd_pkts"] == 4.0
    assert str(r1["event_date"]) == "2018-02-14"

    # Verify Row 2: Zero duration and zero bwd pkts preserved, Infinity/NaN rates become 0.0
    r2 = [r for r in collected if r["raw_label"] == "Benign"][0]
    assert r2["flow_duration"] == 0.0
    assert r2["tot_bwd_pkts"] == 0.0
    assert r2["flow_byts_s"] == 0.0
    assert r2["flow_pkts_s"] == 0.0


def test_profile_dataset(spark: SparkSession):
    """Verify that profile_dataset correctly detects null, empty, inf, and nan values."""
    schema = build_raw_schema()

    def make_profile_row(**col_values):
        r = {col: "0" for col in settings.raw_columns}
        r.update(col_values)
        return r

    rows = [
        # Row 1: Positive infinity
        make_profile_row(**{"Flow Byts/s": "Infinity", "Flow Pkts/s": "+Infinity", "Fwd Pkts/s": "inf"}),
        # Row 2: Negative infinity
        make_profile_row(**{"Flow Byts/s": "-Infinity", "Fwd Pkts/s": "-inf"}),
        # Row 3: NaN
        make_profile_row(**{"Flow Byts/s": "NaN", "Down/Up Ratio": "nan"}),
        # Row 4: Null
        make_profile_row(**{"Flow Byts/s": None, "Down/Up Ratio": None}),
        # Row 5: Empty string
        make_profile_row(**{"Flow Byts/s": "", "Down/Up Ratio": ""}),
        # Row 6: Normal numeric string
        make_profile_row(**{"Flow Byts/s": "123.45", "Down/Up Ratio": "2.5"}),
    ]

    df = spark.createDataFrame(rows, schema=schema)
    profile = profile_dataset(df)

    assert profile["total_rows_profiled"] == 6
    col_profiles = profile["column_profiles"]

    assert col_profiles["Flow Byts/s"]["pos_infinity"] == 1
    assert col_profiles["Flow Byts/s"]["neg_infinity"] == 1
    assert col_profiles["Flow Byts/s"]["nan"] == 1
    assert col_profiles["Flow Byts/s"]["null_or_empty"] == 2

    assert col_profiles["Flow Pkts/s"]["pos_infinity"] == 1
    assert col_profiles["Fwd Pkts/s"]["pos_infinity"] == 1
    assert col_profiles["Fwd Pkts/s"]["neg_infinity"] == 1

    assert col_profiles["Down/Up Ratio"]["nan"] == 1
    assert col_profiles["Down/Up Ratio"]["null_or_empty"] == 2


def test_clean_and_transform_rate_sanitization(spark: SparkSession):
    """Verify sanitization of fwd_pkts_s and bwd_pkts_s alongside flow_byts_s and flow_pkts_s."""
    schema = build_raw_schema()

    def make_rate_row(byts_s, pkts_s, fwd_s, bwd_s):
        r = {col: "0" for col in settings.raw_columns}
        r["Label"] = "Benign"
        r["Flow Duration"] = "100"
        r["Tot Fwd Pkts"] = "2"
        r["Timestamp"] = "14/02/2018 08:31:01"
        r["Flow Byts/s"] = byts_s
        r["Flow Pkts/s"] = pkts_s
        r["Fwd Pkts/s"] = fwd_s
        r["Bwd Pkts/s"] = bwd_s
        return r

    rows = [
        # Non-finite string representations
        make_rate_row("Infinity", "+Infinity", "-Infinity", "NaN"),
        make_rate_row("-inf", "inf", "nan", "Infinity"),
        # Empty and None values
        make_rate_row("", None, "", None),
        # Valid numeric values
        make_rate_row("1500.5", "20.0", "15.0", "5.0"),
    ]

    df = spark.createDataFrame(rows, schema=schema)
    clean_df, _ = clean_and_transform(df)
    collected = clean_df.collect()

    # Rows 0, 1, 2 must all be sanitized to 0.0
    for r in collected[:3]:
        assert r["flow_byts_s"] == 0.0
        assert r["flow_pkts_s"] == 0.0
        assert r["fwd_pkts_s"] == 0.0
        assert r["bwd_pkts_s"] == 0.0

    # Row 3 must preserve valid values
    r3 = collected[3]
    assert r3["flow_byts_s"] == 1500.5
    assert r3["flow_pkts_s"] == 20.0
    assert r3["fwd_pkts_s"] == 15.0
    assert r3["bwd_pkts_s"] == 5.0


def test_clean_and_transform_down_up_ratio(spark: SparkSession):
    """Verify down_up_ratio sanitization for non-finite, null, empty, and zero-fwd-packet values."""
    schema = build_raw_schema()

    def make_ratio_row(ratio, fwd_pkts="1"):
        r = {col: "0" for col in settings.raw_columns}
        r["Label"] = "Benign"
        r["Flow Duration"] = "100"
        r["Tot Fwd Pkts"] = str(fwd_pkts)
        r["Timestamp"] = "14/02/2018 08:31:01"
        r["Down/Up Ratio"] = ratio
        return r

    rows = [
        make_ratio_row("Infinity", "1"),
        make_ratio_row("-Infinity", "1"),
        make_ratio_row("NaN", "1"),
        make_ratio_row("", "1"),
        make_ratio_row(None, "1"),
        make_ratio_row("3.5", "1"),
        # Zero forward packets with a nonzero ratio must be sanitized to 0.0
        make_ratio_row("2.0", "0"),
        # Positive forward packets with a valid ratio must be preserved
        make_ratio_row("4.5", "5"),
    ]

    df = spark.createDataFrame(rows, schema=schema)
    clean_df, _ = clean_and_transform(df)
    collected = clean_df.collect()

    # First 5 rows sanitized to 0.0
    for r in collected[:5]:
        assert r["down_up_ratio"] == 0.0

    # Row 5 preserved (fwd_pkts == 1)
    assert collected[5]["down_up_ratio"] == 3.5

    # Row 6 sanitized to 0.0 because fwd_pkts == 0 despite nonzero ratio string "2.0"
    assert collected[6]["down_up_ratio"] == 0.0

    # Row 7 preserved (fwd_pkts == 5, valid ratio "4.5")
    assert collected[7]["down_up_ratio"] == 4.5


def test_clean_and_transform_invalid_timestamp_handling(spark: SparkSession):
    """Verify detection, counting, exclusion of invalid timestamps, and absence of null-date partitions."""
    schema = build_raw_schema()

    def make_ts_row(ts):
        r = {col: "0" for col in settings.raw_columns}
        r["Label"] = "Benign"
        r["Flow Duration"] = "100"
        r["Tot Fwd Pkts"] = "1"
        r["Timestamp"] = ts
        return r

    rows = [
        # Valid timestamp (dd/MM/yyyy HH:mm:ss)
        make_ts_row("15/02/2018 10:20:30"),
        # Invalid format
        make_ts_row("2018-02-15 10:20:30"),
        # Malformed text
        make_ts_row("not_a_timestamp"),
        # Empty string
        make_ts_row(""),
        # Null
        make_ts_row(None),
    ]

    df = spark.createDataFrame(rows, schema=schema)
    clean_df, metrics = clean_and_transform(df)

    # 4 invalid timestamps dropped, 1 valid row retained
    assert metrics["invalid_timestamp_dropped"] == 4
    assert metrics["semantically_invalid_dropped"] == 4
    assert metrics["retained_rows"] == 1
    assert clean_df.count() == 1

    # Ensure no null event_date output row
    null_date_count = clean_df.filter(F.isnull(F.col("event_date"))).count()
    assert null_date_count == 0

    retained_row = clean_df.collect()[0]
    assert str(retained_row["event_date"]) == "2018-02-15"
