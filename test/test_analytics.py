"""Unit tests for ThreatLenz Phase 2 Spark Analytics Module."""

import pytest
from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import (
    DoubleType,
    IntegerType,
    StringType,
    StructField,
    StructType,
)

from src.analytics import (
    compute_class_distribution,
    compute_destination_port_analysis,
    compute_feature_redundancy,
    compute_temporal_distribution,
    compute_traffic_characteristics,
    synthesize_phase3_observations,
)
from src.utils import get_spark_session


@pytest.fixture(scope="session")
def spark() -> SparkSession:
    """Provides a shared local SparkSession for analytics unit tests."""
    return get_spark_session(
        app_name="ThreatLenz-Analytics-Tests",
        master="local[2]",
        driver_memory="2g",
        shuffle_partitions=2,
    )


def test_compute_class_distribution(spark: SparkSession):
    """Verify class support, percentage calculation, and ratio relative to Benign."""
    schema = StructType([
        StructField("label", StringType(), False),
    ])
    # 7 Benign, 2 Bot, 1 SQL Injection
    data = [{"label": "Benign"}] * 7 + [{"label": "Bot"}] * 2 + [{"label": "SQL Injection"}] * 1
    df = spark.createDataFrame(data, schema=schema)

    result = compute_class_distribution(df, total_rows=10)

    assert result["classes_count"] == 3
    classes = result["classes"]
    assert classes[0]["class_name"] == "Benign"
    assert classes[0]["support"] == 7
    assert classes[0]["percentage"] == 70.0
    assert classes[0]["ratio_to_benign"] == 1.0

    bot_item = next(c for c in classes if c["class_name"] == "Bot")
    assert bot_item["support"] == 2
    assert bot_item["percentage"] == 20.0
    assert bot_item["ratio_to_benign"] == 3.5

    sqli_item = next(c for c in classes if c["class_name"] == "SQL Injection")
    assert sqli_item["support"] == 1
    assert sqli_item["percentage"] == 10.0
    assert sqli_item["is_ultra_rare"] is True


def test_compute_temporal_distribution(spark: SparkSession):
    """Verify temporal cross-tabulation and primary day concentration."""
    schema = StructType([
        StructField("label", StringType(), False),
        StructField("event_date", StringType(), False),
    ])
    # Benign on both days, Bot only on 2018-03-02
    data = [
        {"label": "Benign", "event_date": "2018-02-14"},
        {"label": "Benign", "event_date": "2018-03-02"},
        {"label": "Bot", "event_date": "2018-03-02"},
        {"label": "Bot", "event_date": "2018-03-02"},
    ]
    df = spark.createDataFrame(data, schema=schema)

    result = compute_temporal_distribution(df)
    assert result["event_date_totals"]["2018-02-14"] == 1
    assert result["event_date_totals"]["2018-03-02"] == 3

    profiles = result["attack_temporal_profiles"]
    bot_prof = next(p for p in profiles if p["class_name"] == "Bot")
    assert bot_prof["active_days_count"] == 1
    assert bot_prof["primary_event_date"] == "2018-03-02"
    assert bot_prof["primary_day_percentage"] == 100.0
    assert bot_prof["is_single_day_attack"] is True


def test_compute_traffic_characteristics(spark: SparkSession):
    """Verify calculation of duration, rate, zero-duration, and unidirectional flow stats."""
    schema = StructType([
        StructField("label", StringType(), False),
        StructField("flow_duration", DoubleType(), False),
        StructField("flow_pkts_s", DoubleType(), False),
        StructField("flow_byts_s", DoubleType(), False),
        StructField("tot_fwd_pkts", DoubleType(), False),
        StructField("tot_bwd_pkts", DoubleType(), False),
        StructField("totlen_fwd_pkts", DoubleType(), False),
        StructField("totlen_bwd_pkts", DoubleType(), False),
        StructField("down_up_ratio", DoubleType(), False),
        StructField("pkt_size_avg", DoubleType(), False),
    ])

    data = [
        # Flow 1: 0 duration, unidirectional (bwd=0)
        {"label": "DoS-Hulk", "flow_duration": 0.0, "flow_pkts_s": 0.0, "flow_byts_s": 0.0,
         "tot_fwd_pkts": 1.0, "tot_bwd_pkts": 0.0, "totlen_fwd_pkts": 100.0, "totlen_bwd_pkts": 0.0,
         "down_up_ratio": 0.0, "pkt_size_avg": 100.0},
        # Flow 2: 200 duration, bidirectional (bwd=2)
        {"label": "DoS-Hulk", "flow_duration": 200.0, "flow_pkts_s": 20.0, "flow_byts_s": 500.0,
         "tot_fwd_pkts": 2.0, "tot_bwd_pkts": 2.0, "totlen_fwd_pkts": 200.0, "totlen_bwd_pkts": 300.0,
         "down_up_ratio": 1.0, "pkt_size_avg": 125.0},
    ]
    df = spark.createDataFrame(data, schema=schema)

    profiles = compute_traffic_characteristics(df)
    assert "DoS-Hulk" in profiles
    hulk_prof = profiles["DoS-Hulk"]

    assert hulk_prof["flow_count"] == 2
    assert hulk_prof["duration"]["mean"] == 100.0
    assert hulk_prof["duration"]["min"] == 0.0
    assert hulk_prof["duration"]["max"] == 200.0
    assert hulk_prof["duration"]["zero_duration_flows"] == 1
    assert hulk_prof["duration"]["zero_duration_pct"] == 50.0

    assert hulk_prof["packets"]["unidirectional_zero_bwd_flows"] == 1
    assert hulk_prof["packets"]["unidirectional_pct"] == 50.0
    assert hulk_prof["packets"]["fwd_pkts_mean"] == 1.5


def test_compute_destination_port_analysis(spark: SparkSession):
    """Verify destination port ranking and concentration percentage."""
    schema = StructType([
        StructField("label", StringType(), False),
        StructField("dst_port", IntegerType(), False),
    ])

    data = [
        {"label": "SSH-BruteForce", "dst_port": 22},
        {"label": "SSH-BruteForce", "dst_port": 22},
        {"label": "SSH-BruteForce", "dst_port": 22},
        {"label": "SSH-BruteForce", "dst_port": 2222},
    ]
    df = spark.createDataFrame(data, schema=schema)

    analysis = compute_destination_port_analysis(df, top_n=2)
    assert "SSH-BruteForce" in analysis
    ssh_data = analysis["SSH-BruteForce"]

    assert ssh_data["total_flows"] == 4
    top_ports = ssh_data["top_ports"]
    assert top_ports[0]["port"] == 22
    assert top_ports[0]["service_name"] == "SSH (Secure Shell)"
    assert top_ports[0]["flow_count"] == 3
    assert top_ports[0]["percentage_within_class"] == 75.0

    assert ssh_data["concentration_top_1_port_pct"] == 75.0
    assert ssh_data["concentration_top_3_ports_pct"] == 100.0


def test_compute_feature_redundancy(spark: SparkSession):
    """Verify feature correlation and detection of duplicate feature pairs."""
    schema = StructType([
        StructField("tot_fwd_pkts", DoubleType(), False),
        StructField("subflow_fwd_pkts", DoubleType(), False),
        StructField("tot_bwd_pkts", DoubleType(), False),
        StructField("subflow_bwd_pkts", DoubleType(), False),
        StructField("totlen_fwd_pkts", DoubleType(), False),
        StructField("subflow_fwd_byts", DoubleType(), False),
        StructField("totlen_bwd_pkts", DoubleType(), False),
        StructField("subflow_bwd_byts", DoubleType(), False),
        StructField("fwd_pkt_len_mean", DoubleType(), False),
        StructField("fwd_seg_size_avg", DoubleType(), False),
        StructField("bwd_pkt_len_mean", DoubleType(), False),
        StructField("bwd_seg_size_avg", DoubleType(), False),
        StructField("pkt_len_mean", DoubleType(), False),
        StructField("pkt_size_avg", DoubleType(), False),
        StructField("flow_duration", DoubleType(), False),
        StructField("fwd_iat_tot", DoubleType(), False),
        StructField("flow_pkts_s", DoubleType(), False),
        StructField("flow_byts_s", DoubleType(), False),
    ])

    rows = []
    for i in range(1, 10):
        rows.append({
            "tot_fwd_pkts": float(i),
            "subflow_fwd_pkts": float(i),  # Exact duplicate
            "tot_bwd_pkts": float(i * 2),
            "subflow_bwd_pkts": float(i * 2),
            "totlen_fwd_pkts": float(i * 100),
            "subflow_fwd_byts": float(i * 100),
            "totlen_bwd_pkts": float(i * 200),
            "subflow_bwd_byts": float(i * 200),
            "fwd_pkt_len_mean": float(i * 50),
            "fwd_seg_size_avg": float(i * 50),
            "bwd_pkt_len_mean": float(i * 60),
            "bwd_seg_size_avg": float(i * 60),
            "pkt_len_mean": float(i * 55),
            "pkt_size_avg": float(i * 55),
            "flow_duration": float(i * 1000),
            "fwd_iat_tot": float(i * 1000),
            "flow_pkts_s": float(i * 10),
            "flow_byts_s": float(i * 500),
        })

    df = spark.createDataFrame(rows, schema=schema)
    result = compute_feature_redundancy(df)

    assert result["evaluated_pairs_count"] == 9
    redundant = result["redundant_pairs"]
    assert len(redundant) >= 7

    fwd_pair = next(r for r in redundant if r["feature_1"] == "tot_fwd_pkts")
    assert pytest.approx(fwd_pair["pearson_correlation"], 1e-4) == 1.0
    assert fwd_pair["is_near_duplicate"] is True


def test_synthesize_phase3_observations():
    """Verify that phase 3 observations contain required domain categories."""
    obs = synthesize_phase3_observations(
        class_dist={},
        temporal_dist={},
        traffic_stats={},
        port_analysis={},
        redundancy_analysis={"redundant_pairs": ["pair1", "pair2"]},
    )
    assert len(obs) == 5
    categories = [o["category"] for o in obs]
    assert "Train/Test Splitting Strategy" in categories
    assert "Extreme Class Imbalance Handling" in categories
    assert "Port Shortcut Learning Risk" in categories
    assert "Feature Redundancy Elimination" in categories
