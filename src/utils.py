"""ThreatLenz Utilities Module.

Provides SparkSession instantiation with Windows and Java 21 support,
structured logging, and report serialization utilities.
"""

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from pyspark.sql import SparkSession

from src.config import settings


def get_logger(name: str = "ThreatLenz", level: Optional[str] = None) -> logging.Logger:
    """Configures and returns a structured logger.

    Args:
        name: Name of the logger instance.
        level: Logging level string (INFO, DEBUG, WARN, ERROR). Defaults to settings.log_level.

    Returns:
        logging.Logger: Configured logger.
    """
    logger = logging.getLogger(name)
    log_level = getattr(logging, (level or settings.log_level).upper(), logging.INFO)
    logger.setLevel(log_level)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(log_level)
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


logger = get_logger("ThreatLenz.Utils")


def configure_hadoop_environment() -> Optional[str]:
    """Resolves and configures HADOOP_HOME and PATH for Windows environments.

    Resolution order:
    1. Existing os.environ["HADOOP_HOME"] if pointing to a directory with bin/winutils.exe.
    2. settings.hadoop_home (from .env or environment variable).
    3. User home directory standard location: Path.home() / ".hadoop".
    4. System-level standard location: Path("C:/hadoop").

    If a valid Hadoop directory containing bin/winutils.exe is resolved,
    sets os.environ["HADOOP_HOME"] and prepends <HADOOP_HOME>/bin to os.environ["PATH"].

    Returns:
        Optional[str]: Resolved HADOOP_HOME path or None.
    """
    if sys.platform != "win32":
        return None

    candidate_paths = []
    if os.environ.get("HADOOP_HOME"):
        candidate_paths.append(Path(os.environ["HADOOP_HOME"]))
    if settings.hadoop_home:
        candidate_paths.append(Path(settings.hadoop_home))
    candidate_paths.append(Path.home() / ".hadoop")
    candidate_paths.append(Path("C:/hadoop"))

    for path in candidate_paths:
        if path.is_dir() and (path / "bin" / "winutils.exe").exists():
            resolved = str(path.resolve())
            os.environ["HADOOP_HOME"] = resolved
            bin_path = str((path / "bin").resolve())
            current_path = os.environ.get("PATH", "")
            if bin_path not in current_path:
                os.environ["PATH"] = f"{bin_path};{current_path}"
            logger.info("Configured HADOOP_HOME for Windows: %s", resolved)
            return resolved

    logger.warning(
        "HADOOP_HOME with bin/winutils.exe not found. On Windows, file write operations "
        "may fail. Place winutils.exe in ~/.hadoop/bin or set HADOOP_HOME in .env."
    )
    return None


def get_spark_session(
    app_name: Optional[str] = None,
    master: Optional[str] = None,
    driver_memory: Optional[str] = None,
    shuffle_partitions: Optional[int] = None,
) -> SparkSession:
    """Initializes and returns an optimized PySpark SparkSession.

    Ensures Windows environment compatibility by binding PySpark worker processes
    to the active virtual environment Python executable, configuring Java 17/21 JVM flags,
    resolving Windows Hadoop environment, and tuning memory parameters.

    Args:
        app_name: Name of the Spark application. Defaults to settings.spark_app_name.
        master: Master URL. Defaults to settings.spark_master.
        driver_memory: Driver memory limit. Defaults to settings.spark_driver_memory.
        shuffle_partitions: Number of shuffle partitions. Defaults to settings.spark_shuffle_partitions.

    Returns:
        SparkSession: The initialized Spark session.
    """
    # Critical for Windows: configure Hadoop home if winutils is present
    hadoop_home = configure_hadoop_environment()

    # Critical for Windows: ensure Spark worker subprocesses use the active venv Python
    python_exe = sys.executable
    os.environ["PYSPARK_PYTHON"] = python_exe
    os.environ["PYSPARK_DRIVER_PYTHON"] = python_exe

    app_name = app_name or settings.spark_app_name
    master = master or settings.spark_master
    driver_memory = driver_memory or settings.spark_driver_memory
    shuffle_partitions = shuffle_partitions or settings.spark_shuffle_partitions

    logger.info("Initializing SparkSession [App: %s, Master: %s, Memory: %s]", app_name, master, driver_memory)

    builder = (
        SparkSession.builder.appName(app_name)
        .master(master)
        .config("spark.driver.memory", driver_memory)
        .config("spark.executor.memory", settings.spark_executor_memory)
        .config("spark.driver.maxResultSize", "4g")
        .config("spark.sql.shuffle.partitions", str(shuffle_partitions))
        .config("spark.ui.enabled", "false")
        # Java 17 / 21 compatibility flags for deep reflection
        .config(
            "spark.driver.extraJavaOptions",
            "--add-opens=java.base/java.nio=ALL-UNNAMED --add-opens=java.base/sun.nio.ch=ALL-UNNAMED",
        )
        .config(
            "spark.executor.extraJavaOptions",
            "--add-opens=java.base/java.nio=ALL-UNNAMED --add-opens=java.base/sun.nio.ch=ALL-UNNAMED",
        )
    )

    if hadoop_home:
        builder = builder.config("spark.hadoop.home.dir", hadoop_home)

    spark = builder.getOrCreate()
    spark.sparkContext.setLogLevel("WARN")
    logger.info("SparkSession initialized successfully (PySpark %s)", spark.version)
    return spark


def save_json_report(data: Dict[str, Any], filepath: Path) -> Path:
    """Serializes a dictionary to a JSON report file.

    Args:
        data: The dictionary to serialize.
        filepath: Target file path.

    Returns:
        Path: The absolute path of the written file.
    """
    filepath = Path(filepath)
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    logger.info("Saved report to %s", filepath)
    return filepath


def load_json_report(filepath: Path) -> Dict[str, Any]:
    """Loads a JSON report file into a dictionary.

    Args:
        filepath: Path to the JSON file.

    Returns:
        Dict[str, Any]: Parsed JSON data.
    """
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)
