"""Precomputed Analytics & Diagnostics Router.

Provides read-only access to precomputed analytical artifacts:
1. Temporal distribution across non-contiguous campaign dates.
2. Destination port concentration across all 14 threat categories.
3. Clean Random Forest model diagnostics (feature importances & 14x14 validation/test confusion matrices).
4. Feature redundancy audit (all 9 evaluated correlation pairs).

Preserves academic integrity, dataset provenance, and model quarantine disclosures.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, status

from backend.app.schemas_analytics import (
    CategoryGovernanceItem,
    CategoryPortAnalysis,
    ConfusionMatrixPayload,
    DestinationPortAnalyticsResponse,
    EvaluatedCorrelationPair,
    FeatureImportanceItem,
    FeatureRedundancyResponse,
    ModelDiagnosticsResponse,
    PortConcentrationItem,
    SplitClassMetrics,
    SplitMetricsSummary,
    TemporalAnalyticsResponse,
    TemporalDateSummary,
)
from src.config import settings

logger = logging.getLogger("ThreatLenz.Analytics")

router = APIRouter(prefix="/api/v1/analytics", tags=["Analytics & Diagnostics"])


def _load_report(filename: str) -> Dict[str, Any]:
    """Safely loads a JSON report from settings.reports_dir or falls back to reports/."""
    candidate_paths = [
        settings.reports_dir / filename,
        settings.project_root / "reports" / filename,
        Path("reports") / filename,
    ]

    for p in candidate_paths:
        if p.exists() and p.is_file():
            try:
                with open(p, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.error("Failed to parse report artifact at %s: %s", p, e)
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Analytical report artifact '{filename}' could not be decoded.",
                )

    logger.warning("Report artifact not found: %s (searched %s)", filename, candidate_paths)
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Analytical report artifact '{filename}' is not available.",
    )


@router.get(
    "/temporal",
    response_model=TemporalAnalyticsResponse,
    summary="Campaign Temporal Flow Distribution",
    description="Returns daily flow volume totals and category activity across the 8 non-contiguous campaign dates.",
)
def get_temporal_distribution() -> TemporalAnalyticsResponse:
    """Extracts temporal distribution metrics from the precomputed analytics artifact."""
    data = _load_report("spark_analytics_report.json")
    temporal_data = data.get("temporal_distribution")
    if not temporal_data:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Artifact 'spark_analytics_report.json' missing 'temporal_distribution' section.",
        )

    raw_totals = temporal_data.get("event_date_totals", {})
    # Format sorted chronological dates
    sorted_dates = sorted(raw_totals.keys())
    totals_list = [
        TemporalDateSummary(event_date=d, total_flows=raw_totals[d])
        for d in sorted_dates
    ]

    return TemporalAnalyticsResponse(
        report_name=str(data.get("report_name", "ThreatLenz-Spark-Analytics")),
        timestamp=str(data.get("timestamp", "")),
        dataset_path=str(data.get("dataset_path", "")),
        horizon_days=len(sorted_dates),
        dates=sorted_dates,
        event_date_totals=totals_list,
        attack_temporal_profiles=temporal_data.get("attack_temporal_profiles", []),
    )


@router.get(
    "/ports",
    response_model=DestinationPortAnalyticsResponse,
    summary="Destination Port Concentration Analysis",
    description="Returns top destination ports and concentration percentages for all 14 evaluated threat categories.",
)
def get_destination_port_analysis() -> DestinationPortAnalyticsResponse:
    """Extracts destination port concentration metrics across all evaluated categories."""
    data = _load_report("spark_analytics_report.json")
    ports_data = data.get("destination_port_analysis")
    if not ports_data:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Artifact 'spark_analytics_report.json' missing 'destination_port_analysis' section.",
        )

    categories_out: Dict[str, CategoryPortAnalysis] = {}
    for cat_name, cat_obj in ports_data.items():
        top_ports = [
            PortConcentrationItem(
                port=p["port"],
                service_name=p["service_name"],
                criticality_weight=p["criticality_weight"],
                flow_count=p["flow_count"],
                percentage_within_class=p["percentage_within_class"],
            )
            for p in cat_obj.get("top_ports", [])
        ]

        categories_out[cat_name] = CategoryPortAnalysis(
            class_name=cat_obj.get("class_name", cat_name),
            total_flows=cat_obj.get("total_flows", 0),
            top_ports=top_ports,
            concentration_top_1_port_pct=cat_obj.get("concentration_top_1_port_pct", 0.0),
            concentration_top_3_ports_pct=cat_obj.get("concentration_top_3_ports_pct", 0.0),
            has_extreme_port_concentration=cat_obj.get("has_extreme_port_concentration", False),
        )

    return DestinationPortAnalyticsResponse(
        report_name=str(data.get("report_name", "ThreatLenz-Spark-Analytics")),
        timestamp=str(data.get("timestamp", "")),
        total_categories=len(categories_out),
        categories=categories_out,
    )


@router.get(
    "/model-diagnostics",
    response_model=ModelDiagnosticsResponse,
    summary="Random Forest Evaluation & Confusion Matrices",
    description="Returns Random Forest evaluation feature importances (leakage-excluded), 14x14 validation/test confusion matrices, and verified per-category reliability gating metrics.",
)
def get_model_diagnostics() -> ModelDiagnosticsResponse:
    """Extracts Random Forest model evaluation benchmarks, per-category metrics, and confusion matrices."""
    data = _load_report("clean_per_class_rf_evaluation_report.json")

    # Format top feature importances
    top_importances_raw = data.get("top_10_feature_importances", {})
    feat_items: list[FeatureImportanceItem] = []
    for raw_name, imp_val in top_importances_raw.items():
        clean_name = raw_name.replace("__imp", "")
        feat_items.append(
            FeatureImportanceItem(
                feature_name=raw_name,
                clean_feature_name=clean_name,
                importance=float(imp_val),
            )
        )
    # Sort descending by importance
    feat_items.sort(key=lambda x: x.importance, reverse=True)

    def _parse_split(split_key: str) -> SplitMetricsSummary:
        s_data = data.get(split_key, {})
        cm_data = s_data.get("confusion_matrix", {})
        cm_payload = ConfusionMatrixPayload(
            class_labels=cm_data.get("class_labels", []),
            raw_matrix=cm_data.get("raw_matrix", []),
            normalized_matrix=cm_data.get("normalized_matrix", []),
        )
        return SplitMetricsSummary(
            evaluated_split=s_data.get("evaluated_split", split_key),
            total_evaluated_samples=s_data.get("total_evaluated_samples", 0),
            overall_accuracy=s_data.get("overall_accuracy", 0.0),
            majority_class_baseline_accuracy=s_data.get("majority_class_baseline_accuracy", 0.0),
            macro_f1=s_data.get("macro_f1", 0.0),
            weighted_f1=s_data.get("weighted_f1", 0.0),
            weighted_precision=s_data.get("weighted_precision", 0.0),
            weighted_recall=s_data.get("weighted_recall", 0.0),
            balanced_accuracy=s_data.get("balanced_accuracy", 0.0),
            confusion_matrix=cm_payload,
            calibration_notice=s_data.get("calibration_notice"),
        )

    val_metrics = _parse_split("validation_metrics")
    test_metrics = _parse_split("test_metrics")

    # Compute category-level verified metrics for both validation and held-out test splits
    labels = val_metrics.confusion_matrix.class_labels
    val_raw = val_metrics.confusion_matrix.raw_matrix
    test_raw = test_metrics.confusion_matrix.raw_matrix
    N = len(labels)
    total_val = sum(sum(row) for row in val_raw)
    total_test = sum(sum(row) for row in test_raw)

    def _extract_category_metrics(i: int, raw: list[list[int]], total: int) -> SplitClassMetrics:
        tp = raw[i][i]
        fn = sum(raw[i][j] for j in range(N) if j != i)
        fp = sum(raw[j][i] for j in range(N) if j != i)
        tn = total - tp - fp - fn

        support = tp + fn
        predicted_support = tp + fp

        prec = float(tp / predicted_support) if predicted_support > 0 else 0.0
        rec = float(tp / support) if support > 0 else 0.0
        f1 = float((2 * prec * rec) / (prec + rec)) if (prec + rec) > 0 else 0.0
        spec = float(tn / (tn + fp)) if (tn + fp) > 0 else 0.0
        fpr = float(fp / (tn + fp)) if (tn + fp) > 0 else 0.0
        fnr = float(fn / (tp + fn)) if (tp + fn) > 0 else 0.0

        return SplitClassMetrics(
            support=support,
            predicted_support=predicted_support,
            precision=round(prec, 4),
            recall=round(rec, 4),
            f1_score=round(f1, 4),
            specificity=round(spec, 4),
            fpr=round(fpr, 4),
            fnr=round(fnr, 4),
            tp=tp,
            fp=fp,
            fn=fn,
            tn=tn,
        )

    def _evaluate_gating(support: int, prec: float, rec: float, f1: float) -> tuple[str, str]:
        if support == 0:
            return "NON_EVALUABLE", "Zero validation observations (Support = 0)"
        min_metric = min(prec, rec, f1)
        if support >= settings.high_reliability_min_support and min_metric >= settings.high_reliability_min_precision:
            return "HIGH_RELIABILITY", f"Validation support >= {settings.high_reliability_min_support} and min(P,R,F1) >= {settings.high_reliability_min_precision:.2f}"
        if support >= settings.min_validation_support and min_metric >= settings.evaluable_min_precision:
            return "EVALUABLE", f"Validation support >= {settings.min_validation_support} and min(P,R,F1) >= {settings.evaluable_min_precision:.2f}"
        reasons = []
        if support < settings.min_validation_support:
            reasons.append(f"Validation support ({support}) < {settings.min_validation_support}")
        if min_metric < settings.evaluable_min_precision:
            reasons.append(f"Validation metric below threshold (min={min_metric:.4f} < {settings.evaluable_min_precision:.2f})")
        return "UNRELIABLE", "; ".join(reasons)

    category_evaluations: list[CategoryGovernanceItem] = []
    for i, c_name in enumerate(labels):
        val_cat = _extract_category_metrics(i, val_raw, total_val)
        test_cat = _extract_category_metrics(i, test_raw, total_test)

        official_tier, gating_reason = _evaluate_gating(
            val_cat.support, val_cat.precision, val_cat.recall, val_cat.f1_score
        )

        f1_delta = test_cat.f1_score - val_cat.f1_score
        if abs(f1_delta) < 0.05:
            gen_assessment = "Consistent generalization across validation and test splits"
        elif f1_delta > 0.05:
            gen_assessment = f"Higher test generalization (+{f1_delta*100:.1f}%)"
        else:
            gen_assessment = f"Generalization drop on test split ({f1_delta*100:.1f}%)"

        category_evaluations.append(
            CategoryGovernanceItem(
                class_name=c_name,
                official_reliability_tier=official_tier,
                gating_reason=gating_reason,
                generalization_assessment=gen_assessment,
                validation=val_cat,
                test=test_cat,
            )
        )

    return ModelDiagnosticsResponse(
        pipeline_name=str(data.get("pipeline_name", "Random-Forest-Evaluation")),
        model_artifact=str(data.get("model_location", "models/clean_per_class_rf/model")),
        model_governance_status="EVALUATED_VALIDATION_BENCHMARK",
        quarantine_disclosure=(
            "The evaluated Random Forest uses leakage-excluded Netflow features and is an "
            "academic evaluation benchmark only. The separate pilot Random Forest remains "
            "quarantined due to target-label leakage. Operational inference is disabled "
            "by governance policy."
        ),
        training_duration_seconds=float(data.get("training_duration_seconds", 0.0)),
        top_feature_importances=feat_items,
        validation_metrics=val_metrics,
        test_metrics=test_metrics,
        category_evaluations=category_evaluations,
    )


@router.get(
    "/feature-redundancy",
    response_model=FeatureRedundancyResponse,
    summary="Feature Redundancy & Multicollinearity Audit",
    description="Returns all 9 evaluated candidate collinear feature pairs with correlation coefficients and drop recommendations.",
)
def get_feature_redundancy() -> FeatureRedundancyResponse:
    """Extracts all 9 evaluated correlation pairs from the PySpark analytics report."""
    data = _load_report("spark_analytics_report.json")
    fr_data = data.get("feature_redundancy")
    if not fr_data:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Artifact 'spark_analytics_report.json' missing 'feature_redundancy' section.",
        )

    all_pairs = [
        EvaluatedCorrelationPair(
            feature_1=p["feature_1"],
            feature_2=p["feature_2"],
            description=p.get("description", ""),
            pearson_correlation=float(p.get("pearson_correlation", 0.0)),
            is_near_duplicate=bool(p.get("is_near_duplicate", False)),
            is_strongly_collinear=bool(p.get("is_strongly_collinear", False)),
            recommendation=p.get("recommendation", ""),
        )
        for p in fr_data.get("all_evaluated_correlations", [])
    ]

    redundant_count = sum(1 for p in all_pairs if p.is_near_duplicate or p.is_strongly_collinear)

    return FeatureRedundancyResponse(
        report_name=str(data.get("report_name", "ThreatLenz-Spark-Analytics")),
        timestamp=str(data.get("timestamp", "")),
        evaluated_pairs_count=len(all_pairs),
        redundant_pairs_count=redundant_count,
        all_evaluated_correlations=all_pairs,
    )

