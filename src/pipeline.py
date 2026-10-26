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
import json
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
    assess_model_reliability,
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
    label_column: str = "label",
) -> List[Dict[str, Any]]:
    """Performs distributed aggregation across flow records.

    Computes flow count, total packet count, total byte volume, distinct active
    observation units, and boundary timestamps for each traffic category.

    Args:
        df: Input flows DataFrame.
        window_type: Aggregation horizon window type. Defaults to 'full_campaign'.
        label_column: Column name to group by for category classification. Defaults to 'label'.

    Returns:
        List[Dict[str, Any]]: Aggregated category statistics collected to driver.

    Raises:
        ValueError: If required columns are missing from the input DataFrame.
    """
    effective_req_cols = (REQUIRED_AGGREGATION_COLUMNS - {"label"}) | {label_column}
    missing_cols = effective_req_cols - set(df.columns)
    if missing_cols:
        raise ValueError(
            f"Input DataFrame is missing required aggregation columns: {sorted(missing_cols)}"
        )

    logger.info(
        "Executing flow aggregation across traffic categories (window_type=%s, label_column=%s)...",
        window_type,
        label_column,
    )

    agg_df = (
        df.groupBy(F.col(label_column).alias("label"))
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
    source_type: str = "curated_dataset_flows",
    model_reliability_map: Optional[Dict[str, Any]] = None,
) -> ThreatProfile:
    """Constructs an immutable ThreatProfile for an aggregated category record.

    Adheres strictly to Phase 4 & Phase 5 governance contracts:
    - Normalizes category to canonical label and attack status.
    - Resolves MITRE ATT&CK candidate vs unverified mapping.
    - Preserves half-open campaign window bounds [CAMPAIGN_WINDOW_START, CAMPAIGN_WINDOW_END).
    - Sets model_reliability from validation assessments for model inference, or None for ground truth.
    - Sets target_impact=None to withhold operational risk band when asset telemetry is unavailable.
    - Emits defensive advisory recommendations with analyst_validation_required=True.

    Args:
        agg: Aggregated flow statistics for a category.
        manifest_hash: SHA-256 source manifest hash prefix.
        run_id: Execution run identifier.
        window_type: Window type string. Defaults to 'full_campaign'.
        source_type: Evidence source provenance identifier. Defaults to 'curated_dataset_flows'.
        model_reliability_map: Optional dictionary of class_name -> ModelReliabilityAssessment.

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
        source_type=source_type,
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

    # Resolve model reliability assessment if applicable
    reliability_assessment = None
    if model_reliability_map and canonical_label in model_reliability_map:
        reliability_assessment = model_reliability_map[canonical_label]

    # Generate defensible advisory recommendations
    advisories = RecommendationEngine.generate_recommendations(
        threat_category=canonical_label,
        tlrs_result=tlrs_res,
        mitre_mapping=mitre_mapping,
        model_reliability=reliability_assessment,
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
        model_reliability=reliability_assessment,
        tlrs_result=tlrs_res.model_dump(mode="json"),
        advisories=[a.model_dump(mode="json") for a in advisories],
    )


def generate_threat_profiles(
    aggregates: List[Dict[str, Any]],
    manifest_hash: str,
    run_id: str,
    window_type: str = "full_campaign",
    source_type: str = "curated_dataset_flows",
    model_reliability_map: Optional[Dict[str, Any]] = None,
) -> List[ThreatProfile]:
    """Generates structured ThreatProfile objects for all aggregated categories.

    Args:
        aggregates: List of aggregated category records.
        manifest_hash: SHA-256 source manifest hash prefix.
        run_id: Execution run identifier.
        window_type: Window type string. Defaults to 'full_campaign'.
        source_type: Evidence source provenance identifier. Defaults to 'curated_dataset_flows'.
        model_reliability_map: Optional dictionary of class_name -> ModelReliabilityAssessment.

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
            source_type=source_type,
            model_reliability_map=model_reliability_map,
        )
        profiles.append(profile)
    return profiles


def run_threat_intelligence(
    spark: Optional[SparkSession] = None,
    parquet_path: Optional[Path] = None,
    output_path: Optional[Path] = None,
    run_id: Optional[str] = None,
    enable_model_inference: Optional[bool] = None,
    model_path: Optional[Path] = None,
    apply_threshold_policy: Optional[bool] = None,
    tau_infiltration: Optional[float] = None,
    tau_brute_force_web: Optional[float] = None,
) -> Dict[str, Any]:
    """Executes the Threat Intelligence Pipeline over curated Parquet flows.

    Supports dual operating modes:
    1. Ground Truth Aggregation (default): Quarantined pilot model; aggregates flows
       by true dataset label with source_type="curated_dataset_flows".
    2. Operational Model Inference (opt-in): Loads clean ML model; transforms flows;
       optionally applies threshold policy; maps predicted index to inferred_label;
       and assesses operational reliability per category from validation metrics.

    Args:
        spark: Active SparkSession. If None, initialized via get_spark_session().
        parquet_path: Path to curated flows Parquet. Defaults to settings.flows_parquet_path.
        output_path: Target JSON report path. Defaults to settings.threat_intelligence_report_path.
        run_id: Optional unique run identifier. If None, generated automatically.
        enable_model_inference: Opt-in flag to run model inference. Defaults to settings.pipeline_enable_model_inference.
        model_path: Path to model directory if inference is enabled. Defaults to settings.pipeline_model_path.
        apply_threshold_policy: Opt-in flag for threshold policy. Defaults to settings.pipeline_apply_threshold_policy.
        tau_infiltration: Threshold for Infiltration. Defaults to settings.tau_infiltration.
        tau_brute_force_web: Threshold for Brute Force - Web. Defaults to settings.tau_brute_force_web.

    Returns:
        Dict[str, Any]: Complete serialized threat intelligence report.

    Raises:
        FileNotFoundError: If the input Parquet directory does not exist.
    """
    start_time = datetime.now()
    target_parquet = Path(parquet_path or settings.flows_parquet_path)
    target_output = Path(output_path or settings.threat_intelligence_report_path)
    active_run_id = run_id or f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"

    is_inference_enabled = (
        enable_model_inference
        if enable_model_inference is not None
        else settings.pipeline_enable_model_inference
    )

    logger.info("=== Starting ThreatLenz Threat Intelligence Pipeline ===")
    logger.info("Run ID: %s", active_run_id)
    logger.info("Target Dataset: %s", target_parquet)
    logger.info("Model Inference Enabled: %s", is_inference_enabled)

    if not target_parquet.exists():
        raise FileNotFoundError(
            f"Curated Parquet dataset not found at {target_parquet}. "
            "Execute ETL pipeline first to produce curated flows."
        )

    # 1. Deterministic Content Manifest
    logger.info("Computing deterministic source manifest digest...")
    manifest = ContentManifestGenerator.generate_manifest(target_parquet)
    manifest_hash = manifest.source_manifest_hash
    logger.info(
        "Manifest computed (%d files, %d bytes, hash=%s)",
        manifest.files_count,
        manifest.total_bytes,
        manifest_hash,
    )

    # 2. Spark Session & Parquet Reading
    spark = spark or get_spark_session(app_name="ThreatLenz-Intelligence-Pipeline")
    df = spark.read.parquet(str(target_parquet))

    # Provenance and governance containers
    model_reliability_map: Optional[Dict[str, Any]] = None
    target_label_col = "label"
    source_type = "curated_dataset_flows"

    if not is_inference_enabled:
        # Default legacy behavior: strict quarantine, ground-truth label aggregation
        logger.info("Model inference disabled by default. Running ground truth aggregation.")
        provenance_type = "curated_dataset_flows"
        is_model_pred = False
        is_operational = False
        model_artifact_str = "models/pilot_rf_model"
        model_status_str = "QUARANTINED_TARGET_LEAKAGE"
        quarantine_reason_str = (
            "Confirmed target leakage: label_idx included in training feature vector "
            "(importance: 0.178853 in models/feature_metadata.json). "
            "Model inference is disabled for Phase 5 pipeline operations."
        )
        inference_executed_flag = False
        metrics_status_str = "QUARANTINED_EXCLUDED_FROM_EVIDENCE"
        target_impact_status_str = "MISSING_EVIDENCE_WITHHELD"
    else:
        # Opt-in operational model inference
        from src.train import INDEX_TO_LABEL, apply_threshold_decision_policy, load_model

        active_model_path = Path(model_path or settings.pipeline_model_path)
        logger.info("Executing model inference with model artifact at %s", active_model_path)
        if not active_model_path.exists():
            raise FileNotFoundError(f"Model artifact not found at {active_model_path}")

        loaded_model = load_model(active_model_path)
        pred_df = loaded_model.transform(df)

        active_apply_thresh = (
            apply_threshold_policy
            if apply_threshold_policy is not None
            else settings.pipeline_apply_threshold_policy
        )

        final_pred_col = "prediction"
        if active_apply_thresh:
            t_infil = (
                tau_infiltration
                if tau_infiltration is not None
                else settings.pipeline_tau_infiltration
            )
            t_web = (
                tau_brute_force_web
                if tau_brute_force_web is not None
                else settings.pipeline_tau_brute_force_web
            )
            logger.info("Applying threshold decision policy (tau_infil=%.2f, tau_web=%.2f)...", t_infil, t_web)
            pred_df = apply_threshold_decision_policy(
                predictions=pred_df,
                tau_infiltration=t_infil,
                tau_brute_force_web=t_web,
                prediction_col="prediction",
                probability_col="probability",
                output_col="adjusted_prediction",
            )
            final_pred_col = "adjusted_prediction"

        # Map numeric index to canonical string label
        pred_expr = F.when(F.col(final_pred_col) == 0.0, F.lit(INDEX_TO_LABEL.get(0, "Benign")))
        for idx, lbl in INDEX_TO_LABEL.items():
            if idx != 0:
                pred_expr = pred_expr.when(F.col(final_pred_col) == float(idx), F.lit(lbl))
        pred_expr = pred_expr.otherwise(F.lit("UNKNOWN"))

        df = pred_df.withColumn("inferred_label", pred_expr)
        target_label_col = "inferred_label"
        source_type = "model_inference"

        provenance_type = "model_inference"
        is_model_pred = True
        is_operational = True
        model_artifact_str = str(active_model_path)
        model_status_str = "OPERATIONAL_EVALUATED"
        quarantine_reason_str = ""
        inference_executed_flag = True
        metrics_status_str = "EVALUATED_VALIDATION_METRICS"
        target_impact_status_str = "MISSING_EVIDENCE_WITHHELD"

        # Load validation metrics for ModelReliabilityAssessment
        model_reliability_map = {}
        eval_report_path = Path("reports/clean_per_class_rf_evaluation_report.json")
        if eval_report_path.exists():
            try:
                with open(eval_report_path, "r", encoding="utf-8") as f:
                    eval_data = json.load(f)
                val_per_class = eval_data.get("validation_metrics", {}).get("per_class_metrics", [])
                for cm in val_per_class:
                    c_name = cm["class_name"]
                    supp = cm.get("true_support", 0)
                    prec = cm.get("precision")
                    rec = cm.get("recall")
                    f1 = cm.get("f1_score")
                    model_reliability_map[c_name] = assess_model_reliability(
                        class_name=c_name,
                        validation_support=supp,
                        validation_precision=prec,
                        validation_recall=rec,
                        validation_f1=f1,
                    )
            except Exception as e:
                logger.warning("Failed to load validation metrics for reliability assessment: %s", e)

    # 3. Flow Aggregation Pass
    aggregates = extract_flow_aggregates(
        df=df,
        window_type="full_campaign",
        label_column=target_label_col,
    )

    # 4. Generate Structured Threat Profiles
    profiles = generate_threat_profiles(
        aggregates=aggregates,
        manifest_hash=manifest_hash,
        run_id=active_run_id,
        window_type="full_campaign",
        source_type=source_type,
        model_reliability_map=model_reliability_map,
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
            "provenance_type": provenance_type,
            "traffic_source": "CSE-CIC-IDS2018 enterprise emulation lab traffic",
            "is_model_prediction": is_model_pred,
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
            "model_artifact": model_artifact_str,
            "model_status": model_status_str,
            "quarantine_reason": quarantine_reason_str,
            "inference_executed": inference_executed_flag,
            "evaluation_metrics_status": metrics_status_str,
        },
        "summary": {
            "total_profiles_generated": len(profiles),
            "attack_categories_count": attack_count,
            "benign_categories_count": benign_count,
            "unknown_categories_count": unknown_count,
            "target_impact_status": target_impact_status_str,
        },
        "profiles": [p.model_dump(mode="json") for p in profiles],
    }

    # 6. Serialize Report to Disk
    save_json_report(report, target_output)
    logger.info("Threat intelligence report saved successfully to %s", target_output)
    logger.info("=== ThreatLenz Pipeline Completed in %.2f seconds ===", duration_secs)

    return report


if __name__ == "__main__":
    run_threat_intelligence()
