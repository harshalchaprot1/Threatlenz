"""Unit tests for Threat Level Risk Score (TLRS) engine (src/tlrs.py)."""

import pytest

from src.tlrs import (
    TLRSEngine,
    round_half_up,
    map_score_to_risk_band,
)


def test_round_half_up_arithmetic():
    """Verify arithmetic Round Half-Up behavior on exact half boundaries."""
    assert round_half_up(19.4) == 19
    assert round_half_up(19.5) == 20
    assert round_half_up(39.4) == 39
    assert round_half_up(39.5) == 40
    assert round_half_up(59.4) == 59
    assert round_half_up(59.5) == 60
    assert round_half_up(79.4) == 79
    assert round_half_up(79.5) == 80
    assert round_half_up(100.0) == 100


def test_half_open_risk_band_intervals():
    """Verify half-open interval mapping [0,20), [20,40), [40,60), [60,80), [80,100]."""
    assert map_score_to_risk_band(0) == "Informational"
    assert map_score_to_risk_band(19) == "Informational"
    assert map_score_to_risk_band(20) == "Low"
    assert map_score_to_risk_band(39) == "Low"
    assert map_score_to_risk_band(40) == "Medium"
    assert map_score_to_risk_band(59) == "Medium"
    assert map_score_to_risk_band(60) == "High"
    assert map_score_to_risk_band(79) == "High"
    assert map_score_to_risk_band(80) == "Critical"
    assert map_score_to_risk_band(100) == "Critical"


def test_frequency_logarithmic_scaling():
    """Verify logarithmic frequency scoring across key order-of-magnitude milestones."""
    assert TLRSEngine.calculate_frequency_score(0) == 0.0
    assert TLRSEngine.calculate_frequency_score(1) == 0.0
    assert pytest.approx(TLRSEngine.calculate_frequency_score(10), 1e-4) == 16.6667
    assert pytest.approx(TLRSEngine.calculate_frequency_score(1_000), 1e-4) == 50.0
    assert pytest.approx(TLRSEngine.calculate_frequency_score(10_000), 1e-4) == 66.6667
    assert pytest.approx(TLRSEngine.calculate_frequency_score(1_000_000), 1e-4) == 100.0
    assert TLRSEngine.calculate_frequency_score(5_000_000) == 100.0


def test_recurrence_window_denominators_and_horizons():
    """Verify recurrence calculation across campaign (H=8), daily (H=24), and hourly (H=12)."""
    # Campaign: 8 distinct observed dates (not 17 calendar days)
    assert pytest.approx(TLRSEngine.calculate_recurrence_score(4, window_type="full_campaign"), 1e-4) == 50.0
    assert pytest.approx(TLRSEngine.calculate_recurrence_score(8, window_type="full_campaign"), 1e-4) == 100.0
    assert TLRSEngine.calculate_recurrence_score(0, window_type="full_campaign") == 0.0

    # Daily: 24 active hours
    assert pytest.approx(TLRSEngine.calculate_recurrence_score(6, window_type="daily"), 1e-4) == 25.0
    assert pytest.approx(TLRSEngine.calculate_recurrence_score(24, window_type="daily"), 1e-4) == 100.0

    # Hourly: 12 active 5-minute buckets
    assert pytest.approx(TLRSEngine.calculate_recurrence_score(3, window_type="hourly"), 1e-4) == 25.0
    assert pytest.approx(TLRSEngine.calculate_recurrence_score(1, window_type="hourly"), 1e-4) == 8.3333
    assert pytest.approx(TLRSEngine.calculate_recurrence_score(12, window_type="hourly"), 1e-4) == 100.0


def test_tlrs_worked_example_missing_target_impact():
    """Verify worked example with missing Target Impact: diagnostic partial sum and withheld operational rating."""
    # DDoS-HOIC: severity=75, frequency=1,000,000 (score=100), active=1 of 8 dates (recurrence=12.5)
    res = TLRSEngine.calculate(
        canonical_label="DDoS-HOIC",
        flow_count=1_000_000,
        active_observation_units=1,
        window_type="full_campaign",
        target_impact_score=None,
    )

    assert res.components.severity == 75.0
    assert res.components.frequency == 100.0
    assert res.components.recurrence == 12.5
    assert res.components.target_impact is None

    # Partial diagnostic sum: 0.40(75) + 0.25(100) + 0.20(12.5) = 30 + 25 + 2.5 = 57.50
    assert res.tlrs_partial_diagnostic == 57.50

    # Normalized heuristic: 57.50 / 0.85 = 67.6471 -> 68
    assert pytest.approx(res.tlrs_normalized_heuristic, 1e-4) == 67.6471
    assert res.tlrs_normalized_rounded == 68

    # Evidence coverage: 85%
    assert res.evidence_coverage == 0.85
    assert res.scoring_status == "insufficient_evidence"

    # Operational rating must be withheld
    assert res.tlrs_complete is None
    assert res.risk_band == "Insufficient Evidence"
    assert res.provisional_risk_band == "DIAGNOSTIC_ONLY: High"


def test_tlrs_complete_evidence():
    """Verify complete TLRS calculation when Target Impact telemetry is provided."""
    res = TLRSEngine.calculate(
        canonical_label="DDoS-HOIC",
        flow_count=1_000_000,
        active_observation_units=1,
        window_type="full_campaign",
        target_impact_score=80.0,
    )

    # Complete sum: 57.50 + 0.15(80.0) = 57.50 + 12.0 = 69.50
    assert res.tlrs_complete == 69.50
    assert res.tlrs_complete_rounded == 70
    assert res.evidence_coverage == 1.0
    assert res.scoring_status == "complete"
    assert res.risk_band == "High"
    assert res.provisional_risk_band is None
