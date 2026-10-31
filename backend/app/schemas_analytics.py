"""Precomputed Analytical Reports & Diagnostics Schemas."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# 1. Temporal Analytics Schemas
class DailyAttackCount(BaseModel):
    """Daily breakdown for a specific threat category."""
    class_name: str
    active_days_count: int
    primary_event_date: str
    primary_day_count: int
    primary_day_percentage: float
    is_single_day_attack: bool
    daily_counts: Dict[str, int]


class TemporalDateSummary(BaseModel):
    """Daily flow totals across captured non-contiguous campaign dates."""
    event_date: str
    total_flows: int


class TemporalAnalyticsResponse(BaseModel):
    """Temporal distribution payload across the 8-day campaign horizon."""
    report_name: str
    timestamp: str
    dataset_path: str
    horizon_days: int
    dates: List[str]
    event_date_totals: List[TemporalDateSummary]
    attack_temporal_profiles: List[DailyAttackCount]


# 2. Destination Port Concentration Schemas
class PortConcentrationItem(BaseModel):
    """Detailed port usage entry within a threat category."""
    port: int
    service_name: str
    criticality_weight: int
    flow_count: int
    percentage_within_class: float


class CategoryPortAnalysis(BaseModel):
    """Port concentration metrics for an individual threat class."""
    class_name: str
    total_flows: int
    top_ports: List[PortConcentrationItem]
    concentration_top_1_port_pct: float
    concentration_top_3_ports_pct: float
    has_extreme_port_concentration: bool


class DestinationPortAnalyticsResponse(BaseModel):
    """Destination port concentration payload across all categories."""
    report_name: str
    timestamp: str
    total_categories: int
    categories: Dict[str, CategoryPortAnalysis]


# 3. Model Evaluation Diagnostics Schemas
class ConfusionMatrixPayload(BaseModel):
    """Square confusion matrix with labels and normalized values."""
    class_labels: List[str]
    raw_matrix: List[List[int]]
    normalized_matrix: List[List[float]]


class SplitMetricsSummary(BaseModel):
    """Aggregate metrics for an evaluation data split."""
    evaluated_split: str
    total_evaluated_samples: int
    overall_accuracy: float
    majority_class_baseline_accuracy: float
    macro_f1: float
    weighted_f1: float
    weighted_precision: float
    weighted_recall: float
    balanced_accuracy: float
    confusion_matrix: ConfusionMatrixPayload
    calibration_notice: Optional[str] = None


class FeatureImportanceItem(BaseModel):
    """Feature importance entry from clean Random Forest pilot."""
    feature_name: str
    clean_feature_name: str
    importance: float


class ModelDiagnosticsResponse(BaseModel):
    """Model evaluation benchmarks, confusion matrices, and feature importances."""
    pipeline_name: str
    model_artifact: str
    model_governance_status: str
    quarantine_disclosure: str
    training_duration_seconds: float
    top_feature_importances: List[FeatureImportanceItem]
    validation_metrics: SplitMetricsSummary
    test_metrics: SplitMetricsSummary


# 4. Feature Redundancy & Multicollinearity Schemas
class EvaluatedCorrelationPair(BaseModel):
    """Evaluated candidate collinear feature pair."""
    feature_1: str
    feature_2: str
    description: str
    pearson_correlation: float
    is_near_duplicate: bool
    is_strongly_collinear: bool
    recommendation: str


class FeatureRedundancyResponse(BaseModel):
    """Full feature redundancy audit with all 9 evaluated pairs."""
    report_name: str
    timestamp: str
    evaluated_pairs_count: int
    redundant_pairs_count: int
    all_evaluated_correlations: List[EvaluatedCorrelationPair]

