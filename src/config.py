"""ThreatLenz Configuration Module.

Defines project settings, file paths, Spark parameters, dataset column definitions,
canonical attack label mappings, and TLRS weights using Pydantic Settings.
"""

from pathlib import Path
from typing import Dict, List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Global configuration settings for the ThreatLenz platform."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Project metadata
    app_name: str = "ThreatLenz"
    app_env: str = "development"
    log_level: str = "INFO"

    # Directory Paths
    project_root: Path = Path(__file__).resolve().parent.parent
    data_raw_dir: Path = project_root / "data" / "raw"
    data_processed_dir: Path = project_root / "data" / "processed"
    data_external_dir: Path = project_root / "data" / "external"
    data_sample_dir: Path = project_root / "data" / "sample"
    reports_dir: Path = project_root / "reports"
    models_dir: Path = project_root / "models"

    # Spark & Hadoop Configuration
    spark_app_name: str = "ThreatLenz-ETL"
    spark_master: str = "local[*]"
    spark_driver_memory: str = "6g"
    spark_executor_memory: str = "4g"
    spark_shuffle_partitions: int = 16
    hadoop_home: str | None = None

    # Selected Processed TrafficForML CSV Files
    selected_raw_files: List[str] = [
        "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv",
        "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv",
        "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv",
        "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv",
        "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv",
        "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",
        "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv",
        "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv",
    ]

    # Canonical Label Normalization Mapping (raw source label -> canonical label)
    label_mapping: Dict[str, str] = {
        "Benign": "Benign",
        "Bot": "Bot",
        "Brute Force -Web": "Brute Force - Web",
        "Brute Force -XSS": "Brute Force - XSS",
        "DDOS attack-HOIC": "DDoS-HOIC",
        "DDOS attack-LOIC-UDP": "DDoS-LOIC-UDP",
        "DoS attacks-GoldenEye": "DoS-GoldenEye",
        "DoS attacks-Hulk": "DoS-Hulk",
        "DoS attacks-SlowHTTPTest": "DoS-SlowHTTPTest",
        "DoS attacks-Slowloris": "DoS-Slowloris",
        "FTP-BruteForce": "FTP-BruteForce",
        "Infilteration": "Infiltration",
        "SQL Injection": "SQL Injection",
        "SSH-Bruteforce": "SSH-BruteForce",
    }

    # Original 80 CSV Columns in official dataset order
    raw_columns: List[str] = [
        "Dst Port", "Protocol", "Timestamp", "Flow Duration", "Tot Fwd Pkts",
        "Tot Bwd Pkts", "TotLen Fwd Pkts", "TotLen Bwd Pkts", "Fwd Pkt Len Max",
        "Fwd Pkt Len Min", "Fwd Pkt Len Mean", "Fwd Pkt Len Std", "Bwd Pkt Len Max",
        "Bwd Pkt Len Min", "Bwd Pkt Len Mean", "Bwd Pkt Len Std", "Flow Byts/s",
        "Flow Pkts/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max",
        "Flow IAT Min", "Fwd IAT Tot", "Fwd IAT Mean", "Fwd IAT Std",
        "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Tot", "Bwd IAT Mean",
        "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags",
        "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Len",
        "Bwd Header Len", "Fwd Pkts/s", "Bwd Pkts/s", "Pkt Len Min",
        "Pkt Len Max", "Pkt Len Mean", "Pkt Len Std", "Pkt Len Var",
        "FIN Flag Cnt", "SYN Flag Cnt", "RST Flag Cnt", "PSH Flag Cnt",
        "ACK Flag Cnt", "URG Flag Cnt", "CWE Flag Count", "ECE Flag Cnt",
        "Down/Up Ratio", "Pkt Size Avg", "Fwd Seg Size Avg", "Bwd Seg Size Avg",
        "Fwd Byts/b Avg", "Fwd Pkts/b Avg", "Fwd Blk Rate Avg", "Bwd Byts/b Avg",
        "Bwd Pkts/b Avg", "Bwd Blk Rate Avg", "Subflow Fwd Pkts", "Subflow Fwd Byts",
        "Subflow Bwd Pkts", "Subflow Bwd Byts", "Init Fwd Win Byts", "Init Bwd Win Byts",
        "Fwd Act Data Pkts", "Fwd Seg Size Min", "Active Mean", "Active Std",
        "Active Max", "Active Min", "Idle Mean", "Idle Std", "Idle Max",
        "Idle Min", "Label"
    ]

    # Snake_case Clean Column Mapping
    column_mapping: Dict[str, str] = {
        "Dst Port": "dst_port",
        "Protocol": "protocol",
        "Timestamp": "timestamp",
        "Flow Duration": "flow_duration",
        "Tot Fwd Pkts": "tot_fwd_pkts",
        "Tot Bwd Pkts": "tot_bwd_pkts",
        "TotLen Fwd Pkts": "totlen_fwd_pkts",
        "TotLen Bwd Pkts": "totlen_bwd_pkts",
        "Fwd Pkt Len Max": "fwd_pkt_len_max",
        "Fwd Pkt Len Min": "fwd_pkt_len_min",
        "Fwd Pkt Len Mean": "fwd_pkt_len_mean",
        "Fwd Pkt Len Std": "fwd_pkt_len_std",
        "Bwd Pkt Len Max": "bwd_pkt_len_max",
        "Bwd Pkt Len Min": "bwd_pkt_len_min",
        "Bwd Pkt Len Mean": "bwd_pkt_len_mean",
        "Bwd Pkt Len Std": "bwd_pkt_len_std",
        "Flow Byts/s": "flow_byts_s",
        "Flow Pkts/s": "flow_pkts_s",
        "Flow IAT Mean": "flow_iat_mean",
        "Flow IAT Std": "flow_iat_std",
        "Flow IAT Max": "flow_iat_max",
        "Flow IAT Min": "flow_iat_min",
        "Fwd IAT Tot": "fwd_iat_tot",
        "Fwd IAT Mean": "fwd_iat_mean",
        "Fwd IAT Std": "fwd_iat_std",
        "Fwd IAT Max": "fwd_iat_max",
        "Fwd IAT Min": "fwd_iat_min",
        "Bwd IAT Tot": "bwd_iat_tot",
        "Bwd IAT Mean": "bwd_iat_mean",
        "Bwd IAT Std": "bwd_iat_std",
        "Bwd IAT Max": "bwd_iat_max",
        "Bwd IAT Min": "bwd_iat_min",
        "Fwd PSH Flags": "fwd_psh_flags",
        "Bwd PSH Flags": "bwd_psh_flags",
        "Fwd URG Flags": "fwd_urg_flags",
        "Bwd URG Flags": "bwd_urg_flags",
        "Fwd Header Len": "fwd_header_len",
        "Bwd Header Len": "bwd_header_len",
        "Fwd Pkts/s": "fwd_pkts_s",
        "Bwd Pkts/s": "bwd_pkts_s",
        "Pkt Len Min": "pkt_len_min",
        "Pkt Len Max": "pkt_len_max",
        "Pkt Len Mean": "pkt_len_mean",
        "Pkt Len Std": "pkt_len_std",
        "Pkt Len Var": "pkt_len_var",
        "FIN Flag Cnt": "fin_flag_cnt",
        "SYN Flag Cnt": "syn_flag_cnt",
        "RST Flag Cnt": "rst_flag_cnt",
        "PSH Flag Cnt": "psh_flag_cnt",
        "ACK Flag Cnt": "ack_flag_cnt",
        "URG Flag Cnt": "urg_flag_cnt",
        "CWE Flag Count": "cwe_flag_count",
        "ECE Flag Cnt": "ece_flag_cnt",
        "Down/Up Ratio": "down_up_ratio",
        "Pkt Size Avg": "pkt_size_avg",
        "Fwd Seg Size Avg": "fwd_seg_size_avg",
        "Bwd Seg Size Avg": "bwd_seg_size_avg",
        "Fwd Byts/b Avg": "fwd_byts_b_avg",
        "Fwd Pkts/b Avg": "fwd_pkts_b_avg",
        "Fwd Blk Rate Avg": "fwd_blk_rate_avg",
        "Bwd Byts/b Avg": "bwd_byts_b_avg",
        "Bwd Pkts/b Avg": "bwd_pkts_b_avg",
        "Bwd Blk Rate Avg": "bwd_blk_rate_avg",
        "Subflow Fwd Pkts": "subflow_fwd_pkts",
        "Subflow Fwd Byts": "subflow_fwd_byts",
        "Subflow Bwd Pkts": "subflow_bwd_pkts",
        "Subflow Bwd Byts": "subflow_bwd_byts",
        "Init Fwd Win Byts": "init_fwd_win_byts",
        "Init Bwd Win Byts": "init_bwd_win_byts",
        "Fwd Act Data Pkts": "fwd_act_data_pkts",
        "Fwd Seg Size Min": "fwd_seg_size_min",
        "Active Mean": "active_mean",
        "Active Std": "active_std",
        "Active Max": "active_max",
        "Active Min": "active_min",
        "Idle Mean": "idle_mean",
        "Idle Std": "idle_std",
        "Idle Max": "idle_max",
        "Idle Min": "idle_min",
        "Label": "label"
    }

    # Zero-variance columns to drop from ML feature vectors
    constant_columns: List[str] = [
        "bwd_psh_flags", "bwd_urg_flags", "fwd_byts_b_avg", "fwd_pkts_b_avg",
        "fwd_blk_rate_avg", "bwd_byts_b_avg", "bwd_pkts_b_avg", "bwd_blk_rate_avg"
    ]

    # Non-feature metadata columns to exclude from ML feature vectors
    metadata_columns: List[str] = [
        "timestamp", "timestamp_parsed", "raw_label", "event_date"
    ]

    @property
    def flows_parquet_path(self) -> Path:
        """Returns the path to the curated flows.parquet dataset."""
        return self.data_processed_dir / "flows.parquet"

    @property
    def analytics_report_path(self) -> Path:
        """Returns the path to the Phase 2 Spark analytics report."""
        return self.reports_dir / "spark_analytics_report.json"


    # TLRS Configuration
    tlrs_weight_severity: float = 0.40
    tlrs_weight_frequency: float = 0.25
    tlrs_weight_recurrence: float = 0.20
    tlrs_weight_target_impact: float = 0.15

    # Asset Criticality Port Mapping
    asset_criticality_map: Dict[int, int] = {
        21: 95,   # FTP Control
        22: 100,  # SSH Remote Access
        443: 95,  # HTTPS Secure Web
        80: 70,   # HTTP Public Web
        8080: 70, # Web Proxy / App Server
        3306: 100,# MySQL Database
        5432: 100,# PostgreSQL Database
    }


# Singleton settings instance
settings = Settings()
