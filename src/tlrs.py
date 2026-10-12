"""ThreatLenz Threat Level Risk Score (TLRS) Calculation Engine.

Implements explainable multi-factor threat risk scoring combining:
- Severity (w=0.40): Prior-based threat impact potential
- Frequency (w=0.25): Logarithmic volume scaling
- Recurrence (w=0.20): Window-specific persistence across observed intervals
- Target Impact (w=0.15): Destination asset criticality (withheld when telemetry is absent)

Adheres strictly to arithmetic Round Half-Up and half-open risk-band intervals,
withholding operational risk ratings when target telemetry is incomplete.
"""

from __future__ import annotations

import math
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field

from src.config import settings


def round_half_up(val: float) -> int:
    """Perform arithmetic Round Half-Up (ties rounded towards +infinity)."""
    return math.floor(val + 0.5)


def map_score_to_risk_band(score_rounded: int) -> str:
    """Map integer-rounded score to risk band using half-open intervals.

    Intervals:
    - [0, 20):  Informational
    - [20, 40): Low
    - [40, 60): Medium
    - [60, 80): High
    - [80, 100]: Critical
    """
    if score_rounded < 20:
        return "Informational"
    if score_rounded < 40:
        return "Low"
    if score_rounded < 60:
        return "Medium"
    if score_rounded < 80:
        return "High"
    return "Critical"


class TLRSComponents(BaseModel):
    """Individual normalized component scores (0 - 100 scale)."""

    severity: float
    frequency: float
    recurrence: float
    target_impact: Optional[float] = None


class TLRSResult(BaseModel):
    """Complete explainable TLRS calculation result and audit trail."""

    components: TLRSComponents
    weights: Dict[str, float]
    tlrs_complete: Optional[float] = None
    tlrs_complete_rounded: Optional[int] = None
    tlrs_partial_diagnostic: float
    tlrs_normalized_heuristic: float
    tlrs_normalized_rounded: int
    evidence_coverage: float
    scoring_status: str  # "complete" or "insufficient_evidence"
    risk_band: str  # Operational band, or "Insufficient Evidence"
    provisional_risk_band: Optional[str] = None  # Diagnostic-only provisional indicator


class TLRSEngine:
    """Calculates explainable risk scores adhering to ThreatLenz governance rules."""

    @staticmethod
    def calculate_severity_score(canonical_label: str) -> float:
        """Retrieve class prior severity score (0 - 100 scale)."""
        return settings.severity_priors.get(canonical_label, 50.0)

    @staticmethod
    def calculate_frequency_score(
        flow_count: int,
        max_reference_flows: int = 1_000_000,
    ) -> float:
        """Calculate frequency score using logarithmic scaling.

        Scale:
        - <= 0 flows -> 0.0
        - 1 flow -> 0.0 (log10(1) = 0)
        - 1,000 flows -> 50.0
        - 1,000,000 flows -> 100.0
        - > 1,000,000 flows -> clamped to 100.0
        """
        if flow_count <= 0:
            return 0.0

        log_val = math.log10(flow_count)
        log_max = math.log10(max_reference_flows) if max_reference_flows > 1 else 6.0
        score = (log_val / log_max) * 100.0
        return max(0.0, min(100.0, score))

    @staticmethod
    def calculate_recurrence_score(
        active_observation_units: int,
        window_type: str = "full_campaign",
        custom_denominator: Optional[int] = None,
    ) -> float:
        """Calculate recurrence score based on window-specific observation units.

        Denominators:
        - full_campaign: 8 distinct observed capture dates
        - daily: 24 active hours
        - hourly: 12 active 5-minute buckets
        """
        if active_observation_units <= 0:
            return 0.0

        if custom_denominator is not None and custom_denominator > 0:
            denom = custom_denominator
        elif window_type == "full_campaign":
            denom = settings.campaign_observed_dates_count  # 8
        elif window_type == "daily":
            denom = settings.daily_active_hours_denominator  # 24
        elif window_type == "hourly":
            denom = settings.hourly_active_buckets_denominator  # 12
        else:
            denom = max(1, settings.campaign_observed_dates_count)

        ratio = active_observation_units / float(denom)
        return min(100.0, ratio * 100.0)

    @classmethod
    def calculate(
        cls,
        canonical_label: str,
        flow_count: int,
        active_observation_units: int,
        window_type: str = "full_campaign",
        target_impact_score: Optional[float] = None,
        custom_recurrence_denominator: Optional[int] = None,
    ) -> TLRSResult:
        """Execute complete explainable TLRS calculation."""
        # 1. Component scores
        s_sev = cls.calculate_severity_score(canonical_label)
        s_freq = cls.calculate_frequency_score(flow_count, settings.frequency_max_reference_flows)
        s_rec = cls.calculate_recurrence_score(
            active_observation_units,
            window_type,
            custom_recurrence_denominator,
        )
        s_target = (
            max(0.0, min(100.0, target_impact_score))
            if target_impact_score is not None
            else None
        )

        w_sev = settings.tlrs_weight_severity
        w_freq = settings.tlrs_weight_frequency
        w_rec = settings.tlrs_weight_recurrence
        w_target = settings.tlrs_weight_target_impact

        weights_dict = {
            "severity": w_sev,
            "frequency": w_freq,
            "recurrence": w_rec,
            "target_impact": w_target,
        }

        # 2. Diagnostic partial sum (always computable)
        partial_diagnostic = (w_sev * s_sev) + (w_freq * s_freq) + (w_rec * s_rec)
        available_weight = w_sev + w_freq + w_rec  # 0.85

        # 3. Normalized heuristic score (scaled to 100%)
        normalized_heuristic = (
            (partial_diagnostic / available_weight)
            if available_weight > 0
            else 0.0
        )
        normalized_rounded = round_half_up(normalized_heuristic)

        # 4. Handle complete vs insufficient evidence
        if s_target is not None:
            tlrs_complete = partial_diagnostic + (w_target * s_target)
            tlrs_complete_rounded = round_half_up(tlrs_complete)
            evidence_coverage = 1.0
            scoring_status = "complete"
            risk_band = map_score_to_risk_band(tlrs_complete_rounded)
            provisional_band = None
        else:
            tlrs_complete = None
            tlrs_complete_rounded = None
            evidence_coverage = available_weight  # 0.85 (85%)
            scoring_status = "insufficient_evidence"
            # Strict governance: operational rating is withheld when evidence is incomplete
            risk_band = "Insufficient Evidence"
            provisional_band = f"DIAGNOSTIC_ONLY: {map_score_to_risk_band(normalized_rounded)}"

        return TLRSResult(
            components=TLRSComponents(
                severity=s_sev,
                frequency=s_freq,
                recurrence=s_rec,
                target_impact=s_target,
            ),
            weights=weights_dict,
            tlrs_complete=round(tlrs_complete, 4) if tlrs_complete is not None else None,
            tlrs_complete_rounded=tlrs_complete_rounded,
            tlrs_partial_diagnostic=round(partial_diagnostic, 4),
            tlrs_normalized_heuristic=round(normalized_heuristic, 4),
            tlrs_normalized_rounded=normalized_rounded,
            evidence_coverage=round(evidence_coverage, 4),
            scoring_status=scoring_status,
            risk_band=risk_band,
            provisional_risk_band=provisional_band,
        )
