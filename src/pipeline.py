"""ThreatLenz Phase 5 Pipeline Orchestration Module.

Provides safe, reproducible threat intelligence aggregation, MITRE ATT&CK mapping,
TLRS risk scoring, and defensive advisory generation over curated network flow data.

Architectural Safeguards:
1. Zero Model Inference: Pilot ML model is quarantined due to label_idx target leakage;
   inference is strictly disabled and metrics are excluded from operational evidence.
2. Explicit Provenance: Profiles are tagged with source_type="curated_dataset_flows"
   to clearly denote curated lab traffic rather than live detections or ML predictions.
3. Half-Open Interval Semantics: Campaign window is bounded by [window_start, window_end)
   covering the full observation span while adhering to Phase 4 window evaluation logic.
4. Arithmetic Round Half-Up: Nonnegative packet and byte sums are rounded using
   established half-up rounding conventions before conversion to profile integers.
5. Missing Target Telemetry Governance: Destination asset criticality is withheld
   (target_impact=None), resulting in provisional risk scores and mandatory advisory generation.
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
import uuid

from pyspark.sql import DataFrame, SparkSession
from pyspark.sql import functions as F

from src.config import settings
from src.threat_intel import (
    CategoryNormalizer,
    ContentManifestGenerator,
    MITREMapper,
    NormalizedCategory,
    ThreatProfile,
    compute_profile_id,
    compute_snapshot_id,
)
from src.tlrs import TLRSEngine, round_half_up
from src.recommendations import RecommendationEngine
from src.utils import get_logger, get_spark_session, save_json_report

logger = get_logger("ThreatLenz.Pipeline")

# Approved full-campaign boundary interval [start, end)
# Covers observed campaign dates (2018-02-14 through 2018-03-02) with an exclusive day ceiling
CAMPAIGN_WINDOW_START: str = "2018-02-14T00:00:00"
CAMPAIGN_WINDOW_END: str = "2018-03-03T00:00:00"

REQUIRED_AGGREGATION_COLUMNS = {
    "label",
    "tot_fwd_pkts",
    "tot_bwd_pkts",
    "totlen_fwd_pkts",
    "totlen_bwd_pkts",
    "event_date",
    "timestamp",
}


def extract_flow_aggregates(
    df: DataFrame,
    window_type: str = "full_campaign",
) -> List[Dict[str, Any]]:
    """Performs distributed aggregation across curated flow records.

    Computes flow count, total packet count, total byte volume, distinct active
    observation units, and boundary timestamps for each traffic category.

    Args:
        df: Curated flows DataFrame.
        window_type: Aggregation horizon window type. Defaults to 'full_campaign'.

    Returns:
        List[Dict[str, Any]]: Aggregated category statistics collected to driver.

    Raises:
        ValueError: If required columns are missing from the input DataFrame.
    """
    missing_cols = REQUIRED_AGGREGATION_COLUMNS - set(df.columns)
    if missing_cols:
        raise ValueError(
            f"Input DataFrame is missing required aggregation columns: {sorted(missing_cols)}"
        )

    logger.info("Executing flow aggregation across traffic categories (window_type=%s)...", window_type)

    agg_df = (
        df.groupBy("label")
        .agg(
            F.count("*").alias("flow_count"),
            F.sum(F.col("totlen_fwd_pkts") + F.col("totlen_bwd_pkts")).alias("raw_total_bytes"),
            F.sum(F.col("tot_fwd_pkts") + F.col("tot_bwd_pkts")).alias("raw_total_packets"),
            F.countDistinct("event_date").alias("active_observation_units"),
            F.min("timestamp").alias("first_seen_timestamp"),
            F.max("timestamp").alias("last_seen_timestamp"),
        )
        .orderBy("label")
    )

    rows = agg_df.collect()
    aggregates: List[Dict[str, Any]] = []

    for r in rows:
        raw_label = str(r["label"]) if r["label"] is not None else ""
        flow_cnt = int(r["flow_count"])

        # Use established arithmetic Round Half-Up to convert nonnegative float sums
        raw_bytes = float(r["raw_total_bytes"]) if r["raw_total_bytes"] is not None else 0.0
        raw_packets = float(r["raw_total_packets"]) if r["raw_total_packets"] is not None else 0.0

        total_bytes = round_half_up(raw_bytes)
        total_packets = round_half_up(raw_packets)
        active_units = int(r["active_observation_units"]) if r["active_observation_units"] is not None else 0

        first_seen = str(r["first_seen_timestamp"]) if r["first_seen_timestamp"] is not None else ""
        last_seen = str(r["last_seen_timestamp"]) if r["last_seen_timestamp"] is not None else ""

        aggregates.append({
            "label": raw_label,
            "flow_count": flow_cnt,
            "total_bytes": total_bytes,
            "total_packets": total_packets,
            "active_observation_units": active_units,
            "first_seen_timestamp": first_seen,
            "last_seen_timestamp": last_seen,
            "window_type": window_type,
        })

    logger.info("Extracted flow aggregates for %d categories.", len(aggregates))
    return aggregates


def build_threat_profile(
    agg: Dict[str, Any],
    manifest_hash: str,
    run_id: str,
    window_type: str = "full_campaign",
) -> ThreatProfile:
    """Constructs an immutable ThreatProfile for an aggregated category record.

    Adheres strictly to Phase 4 governance contracts:
    - Normalizes category to canonical label and attack status.
    - Resolves MITRE ATT&CK candidate vs unverified mapping.
    - Preserves half-open campaign window bounds [CAMPAIGN_WINDOW_START, CAMPAIGN_WINDOW_END).
    - Sets model_reliability=None to reflect curated dataset ground truth rather than ML predictions.
    - Sets target_impact=None to withhold operational risk band when asset telemetry is unavailable.
    - Emits defensive advisory recommendations with analyst_validation_required=True.

    Args:
        agg: Aggregated flow statistics for a category.
        manifest_hash: SHA-256 source manifest hash prefix.
        run_id: Execution run identifier.
        window_type: Window type string. Defaults to 'full_campaign'.

    Returns:
        ThreatProfile: Populated Pydantic threat profile instance.
    """
    raw_label = str(agg["label"]).strip() if agg.get("label") else ""
    norm_category = CategoryNormalizer.normalize(raw_label)

    # Support curated datasets where label was already standardized to canonical format
    if not norm_category.is_mapped and raw_label in set(settings.label_mapping.values()):
        attack_status = "BENIGN" if raw_label == "Benign" else "ATTACK"
        is_attack = False if raw_label == "Benign" else True
        norm_category = NormalizedCategory(
            canonical_label=raw_label,
            raw_label=raw_label,
            attack_status=attack_status,
            is_attack=is_attack,
            is_mapped=True,
        )

    canonical_label = norm_category.canonical_label
    mitre_mapping = MITREMapper.map_label(canonical_label)

    # Establish window bounds: campaign interval enforces half-open [start, end)
    if window_type == "full_campaign":
        window_start = CAMPAIGN_WINDOW_START
        window_end = CAMPAIGN_WINDOW_END
    else:
        window_start = agg.get("first_seen_timestamp", "")
        window_end = agg.get("last_seen_timestamp", "")

    # Deterministic natural key (run-invariant) and immutable snapshot ID (run-specific)
    profile_id = compute_profile_id(
        source_type="curated_dataset_flows",
        category_id=canonical_label,
        window_start=window_start,
        window_end=window_end,
        window_type=window_type,
    )

    snapshot_id = compute_snapshot_id(
        profile_id=profile_id,
        run_id=run_id,
        source_manifest_hash=manifest_hash,
        schema_version="1.0",
    )

    flow_count = agg["flow_count"]
    active_units = agg["active_observation_units"]
    recurrence_denom = settings.campaign_observed_dates_count

    # Calculate multi-factor TLRS (target_impact is None -> operational band withheld)
    tlrs_res = TLRSEngine.calculate(
        canonical_label=canonical_label,
        flow_count=flow_count,
        active_observation_units=active_units,
        window_type=window_type,
        target_impact_score=None,
    )

    # Generate defensible advisory recommendations (model_reliability is None for dataset labels)
    advisories = RecommendationEngine.generate_recommendations(
        threat_category=canonical_label,
        tlrs_result=tlrs_res,
        mitre_mapping=mitre_mapping,
        model_reliability=None,
    )

    return ThreatProfile(
        profile_id=profile_id,
        snapshot_id=snapshot_id,
        run_id=run_id,
        source_manifest_hash=manifest_hash,
        schema_version="1.0",
        window_type=window_type,
        window_start=window_start,
        window_end=window_end,
        category=norm_category,
        mitre_mapping=mitre_mapping,
        flow_count=flow_count,
        total_bytes=agg["total_bytes"],
        total_packets=agg["total_packets"],
        active_observation_units=active_units,
        recurrence_denominator=recurrence_denom,
        model_reliability=None,
        tlrs_result=tlrs_res.model_dump(mode="json"),
        advisories=[a.model_dump(mode="json") for a in advisories],
    )


def generate_threat_profiles(
    aggregates: List[Dict[str, Any]],
    manifest_hash: str,
    run_id: str,
    window_type: str = "full_campaign",
) -> List[ThreatProfile]:
    """Generates structured ThreatProfile objects for all aggregated categories.

    Args:
        aggregates: List of aggregated category records.
        manifest_hash: SHA-256 source manifest hash prefix.
        run_id: Execution run identifier.
        window_type: Window type string. Defaults to 'full_campaign'.

    Returns:
        List[ThreatProfile]: Ordered list of populated threat profiles.
    """
    profiles: List[ThreatProfile] = []
    for agg in sorted(aggregates, key=lambda a: a["label"]):
        profile = build_threat_profile(
            agg=agg,
            manifest_hash=manifest_hash,
            run_id=run_id,
            window_type=window_type,
        )
        profiles.append(profile)
    return profiles


def run_threat_intelligence(
    spark: Optional[SparkSession] = None,
    parquet_path: Optional[Path] = None,
    output_path: Optional[Path] = None,
    run_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Executes the Phase 5 Threat Intelligence Pipeline over curated Parquet flows.

    Sequence:
    1. Validates input dataset existence.
    2. Generates deterministic SHA-256 content manifest.
    3. Executes distributed flow aggregation across all categories.
    4. Constructs immutable ThreatProfile instances with candidate MITRE mappings,
       multi-factor TLRS scores, and defensive advisory recommendations.
    5. Records model quarantine and dataset-level provenance in report metadata.
    6. Persists reports/threat_intelligence_report.json via structured serialization.

    Args:
        spark: Active SparkSession. If None, initialized via get_spark_session().
        parquet_path: Path to curated flows Parquet. Defaults to settings.flows_parquet_path.
        output_path: Target JSON report path. Defaults to settings.threat_intelligence_report_path.
        run_id: Optional unique run identifier. If None, generated automatically.

    Returns:
        Dict[str, Any]: Complete serialized threat intelligence report.

    Raises:
        FileNotFoundError: If the input Parquet directory does not exist.
    """
    start_time = datetime.now()
    target_parquet = Path(parquet_path or settings.flows_parquet_path)
    target_output = Path(output_path or settings.threat_intelligence_report_path)
    active_run_id = run_id or f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"

    logger.info("=== Starting ThreatLenz Phase 5 Threat Intelligence Pipeline ===")
    logger.info("Run ID: %s", active_run_id)
    logger.info("Target Dataset: %s", target_parquet)

    if not target_parquet.exists():
        raise FileNotFoundError(
            f"Curated Parquet dataset not found at {target_parquet}. "
            "Execute ETL pipeline first to produce curated flows."
        )

    # 1. Deterministic Content Manifest
    logger.info("Computing deterministic source manifest digest...")
    manifest = ContentManifestGenerator.generate_manifest(target_parquet)
    manifest_hash = manifest.source_manifest_hash
    logger.info("Manifest computed (%d files, %d bytes, hash=%s)", manifest.files_count, manifest.total_bytes, manifest_hash)

    # 2. Spark Session & Parquet Reading
    spark = spark or get_spark_session(app_name="ThreatLenz-Phase5-Intelligence")
    df = spark.read.parquet(str(target_parquet))

    # 3. Flow Aggregation Pass
    aggregates = extract_flow_aggregates(df, window_type="full_campaign")

    # 4. Generate Structured Threat Profiles
    profiles = generate_threat_profiles(
        aggregates=aggregates,
        manifest_hash=manifest_hash,
        run_id=active_run_id,
        window_type="full_campaign",
    )

    duration_secs = round((datetime.now() - start_time).total_seconds(), 2)

    # 5. Assemble Complete Report with Explicit Provenance and Governance Metadata
    attack_count = sum(1 for p in profiles if p.category.is_attack is True)
    benign_count = sum(1 for p in profiles if p.category.is_attack is False)
    unknown_count = sum(1 for p in profiles if p.category.is_attack is None)

    report: Dict[str, Any] = {
        "report_name": "ThreatLenz-Phase5-Threat-Intelligence",
        "pipeline_version": "1.0.0",
        "run_id": active_run_id,
        "timestamp": datetime.now().isoformat(),
        "execution_duration_seconds": duration_secs,
        "dataset_path": str(target_parquet),
        "source_manifest": {
            "source_manifest_hash": manifest.source_manifest_hash,
            "files_count": manifest.files_count,
            "total_bytes": manifest.total_bytes,
        },
        "evidence_provenance": {
            "provenance_type": "curated_dataset_flows",
            "traffic_source": "CSE-CIC-IDS2018 enterprise emulation lab traffic",
            "is_model_prediction": False,
            "is_live_detection": False,
            "is_independently_verified": False,
            "campaign_interval": {
                "window_type": "full_campaign",
                "window_start": CAMPAIGN_WINDOW_START,
                "window_end": CAMPAIGN_WINDOW_END,
                "interval_semantics": "[window_start, window_end) half-open",
            },
        },
        "model_governance": {
            "model_artifact": "models/pilot_rf_model",
            "model_status": "QUARANTINED_TARGET_LEAKAGE",
            "quarantine_reason": (
                "Confirmed target leakage: label_idx included in training feature vector "
                "(importance: 0.178853 in models/feature_metadata.json). "
                "Model inference is disabled for Phase 5 pipeline operations."
            ),
            "inference_executed": False,
            "evaluation_metrics_status": "QUARANTINED_EXCLUDED_FROM_EVIDENCE",
        },
        "summary": {
            "total_profiles_generated": len(profiles),
            "attack_categories_count": attack_count,
            "benign_categories_count": benign_count,
            "unknown_categories_count": unknown_count,
            "target_impact_status": "MISSING_EVIDENCE_WITHHELD",
        },
        "profiles": [p.model_dump(mode="json") for p in profiles],
    }

    # 6. Serialize Report to Disk
    save_json_report(report, target_output)
    logger.info("Threat intelligence report saved successfully to %s", target_output)
    logger.info("=== ThreatLenz Phase 5 Pipeline Completed in %.2f seconds ===", duration_secs)

    return report


if __name__ == "__main__":
    run_threat_intelligence()
