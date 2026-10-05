"""Small Parquet write and read smoke test using ThreatLenz utils and Spark configuration."""

import shutil
from pathlib import Path
import pytest
from src.utils import get_spark_session


def test_parquet_write_read_smoke():
    """Verify that PySpark can write and read partitioned Parquet files on Windows."""
    spark = get_spark_session(
        app_name="ThreatLenz-Parquet-SmokeTest",
        master="local[2]",
        driver_memory="2g",
        shuffle_partitions=2,
    )

    test_data = [
        {"id": 1, "event_date": "2018-02-14", "label": "Benign", "flow_duration": 100.0},
        {"id": 2, "event_date": "2018-02-14", "label": "FTP-BruteForce", "flow_duration": 250.0},
        {"id": 3, "event_date": "2018-02-15", "label": "DoS-GoldenEye", "flow_duration": 5000.0},
    ]

    df = spark.createDataFrame(test_data)
    test_out_dir = Path("data/processed/smoke_test_parquet")
    if test_out_dir.exists():
        shutil.rmtree(test_out_dir)

    try:
        # 1. Write partitioned Parquet
        df.write.mode("overwrite").partitionBy("event_date").parquet(str(test_out_dir))
        assert test_out_dir.exists()

        # Check partition folders
        partition_folders = list(test_out_dir.glob("event_date=*"))
        assert len(partition_folders) == 2  # 2018-02-14 and 2018-02-15

        # 2. Read back with Spark
        read_df = spark.read.parquet(str(test_out_dir))
        assert read_df.count() == 3

        # Verify columns and contents
        labels = [r["label"] for r in read_df.collect()]
        assert set(labels) == {"Benign", "FTP-BruteForce", "DoS-GoldenEye"}

    finally:
        if test_out_dir.exists():
            shutil.rmtree(test_out_dir)
