"""Unit tests for ThreatLenz ETL and Data Integrity validation."""

import pytest
from pyspark.sql import SparkSession
from pyspark.sql.types import Row

from src.config import settings
from src.etl import (
    audit_repeated_headers,
    build_raw_schema,
    clean_and_transform,
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
    - Drop tot_fwd_pkts < 1 (flow must have forward packet)
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
