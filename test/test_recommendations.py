"""Unit tests for Recommendation engine (src/recommendations.py)."""

from src.threat_intel import MITREMapper, ModelReliabilityAssessment
from src.tlrs import TLRSEngine
from src.recommendations import RecommendationEngine


def test_recommendation_defensive_governance():
    """Verify all recommendations require analyst validation and propose defensive actions only."""
    recs = RecommendationEngine.generate_recommendations("DDoS-HOIC")
    assert len(recs) > 0
    for rec in recs:
        assert rec.analyst_validation_required is True
        assert rec.action_type in ("Telemetry Enrichment", "Investigation", "Rate Limiting Review", "Policy Hardening")
        # Ensure no destructive commands or scripts
        assert "iptables" not in rec.detailed_guidance.lower()
        assert "block" not in rec.summary.lower()


def test_category_matching_rules():
    """Verify threat category matching to appropriate defensive guidance."""
    # DDoS / DoS
    ddos_recs = RecommendationEngine.generate_recommendations("DDoS-HOIC")
    assert any(r.action_type == "Rate Limiting Review" for r in ddos_recs)

    # Brute Force
    bf_recs = RecommendationEngine.generate_recommendations("SSH-BruteForce")
    assert any(r.action_type == "Investigation" and "auth" in r.summary.lower() for r in bf_recs)

    # Bot
    bot_recs = RecommendationEngine.generate_recommendations("Bot")
    assert any(r.action_type == "Investigation" and "beaconing" in r.summary.lower() for r in bot_recs)

    # Infiltration / SQL Injection
    infil_recs = RecommendationEngine.generate_recommendations("Infiltration")
    assert any(r.action_type == "Telemetry Enrichment" and "payload" in r.recommendation_id.lower() for r in infil_recs)


def test_missing_evidence_and_unreliable_ml_advisories():
    """Verify advisories emitted when target telemetry is missing or ML classifier is unreliable."""
    tlrs_missing = TLRSEngine.calculate("DDoS-HOIC", flow_count=1000, active_observation_units=1)
    unreliable_model = ModelReliabilityAssessment(
        class_name="DDoS-HOIC",
        validation_support=10,
        status="UNRELIABLE",
        rationale="Validation support below threshold",
    )

    recs = RecommendationEngine.generate_recommendations(
        threat_category="DDoS-HOIC",
        tlrs_result=tlrs_missing,
        model_reliability=unreliable_model,
    )

    # Should contain:
    # 1. Category advisory (Rate Limiting Review)
    # 2. Missing target impact enrichment advisory
    # 3. ML reliability warning advisory
    assert len(recs) >= 3

    action_types = [r.action_type for r in recs]
    assert "Rate Limiting Review" in action_types
    assert "Telemetry Enrichment" in action_types
    assert "Investigation" in action_types

    # Find the ML verification advisory
    ml_adv = next(r for r in recs if "VERIFY_ML" in r.recommendation_id)
    assert "manual" in ml_adv.summary.lower() or "verify" in ml_adv.summary.lower()
    assert ml_adv.analyst_validation_required is True

    # Find the Asset enrichment advisory
    asset_adv = next(r for r in recs if "ENRICH_ASSET" in r.recommendation_id)
    assert "asset" in asset_adv.summary.lower() or "cmdb" in asset_adv.summary.lower()
