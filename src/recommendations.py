"""ThreatLenz Explainable Recommendation Engine.

Generates defensible, rule-based advisory recommendations for security analysts.
Strict Safety Governance:
- All recommendations require human analyst validation (analyst_validation_required = True).
- No automated remediation or destructive blocking actions are generated.
- Emits explicit guidance for unverified ML classifications and missing target telemetries.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from src.threat_intel import MITRETechniqueMapping, ModelReliabilityAssessment
from src.tlrs import TLRSResult


class AdvisoryRecommendation(BaseModel):
    """Structured advisory recommendation for security analysts."""

    recommendation_id: str
    threat_category: str
    priority: str  # "Low", "Medium", "High", "Critical"
    action_type: str  # "Telemetry Enrichment", "Investigation", "Rate Limiting Review", "Policy Hardening"
    summary: str
    detailed_guidance: str
    missing_evidence_required: List[str] = Field(default_factory=list)
    analyst_validation_required: bool = True


class RecommendationEngine:
    """Matches threat intelligence findings to defensive advisory recommendations."""

    @classmethod
    def generate_recommendations(
        cls,
        threat_category: str,
        tlrs_result: Optional[TLRSResult] = None,
        mitre_mapping: Optional[MITRETechniqueMapping] = None,
        model_reliability: Optional[ModelReliabilityAssessment] = None,
    ) -> List[AdvisoryRecommendation]:
        """Generate structured advisory recommendations based on threat context."""
        recommendations: List[AdvisoryRecommendation] = []

        # Determine baseline priority from TLRS or class severity
        if tlrs_result and tlrs_result.scoring_status == "complete":
            priority = tlrs_result.risk_band
            if priority == "Informational":
                priority = "Low"
        elif tlrs_result and tlrs_result.provisional_risk_band:
            # Extract provisional band (e.g. "DIAGNOSTIC_ONLY: High" -> "High")
            provisional = tlrs_result.provisional_risk_band.split(":")[-1].strip()
            priority = provisional if provisional != "Informational" else "Low"
        else:
            priority = "Medium"

        # 1. Category-specific defensive recommendations
        if "DDoS" in threat_category or "DoS" in threat_category:
            rec_id = cls._generate_id("RATE_LIMIT", threat_category)
            recommendations.append(
                AdvisoryRecommendation(
                    recommendation_id=rec_id,
                    threat_category=threat_category,
                    priority=priority,
                    action_type="Rate Limiting Review",
                    summary="Review application rate limiting and connection pool thresholds.",
                    detailed_guidance=(
                        "Inspect ingress reverse proxy and firewall connection metrics to identify "
                        "unusually dense connection clusters. Verify that connection timeout thresholds "
                        "and keep-alive limits protect service availability without dropping legitimate traffic."
                    ),
                    missing_evidence_required=(
                        mitre_mapping.missing_telemetry
                        if mitre_mapping
                        else ["Upstream link saturation telemetries"]
                    ),
                    analyst_validation_required=True,
                )
            )

        elif "Brute" in threat_category:
            rec_id = cls._generate_id("INVESTIGATE_AUTH", threat_category)
            recommendations.append(
                AdvisoryRecommendation(
                    recommendation_id=rec_id,
                    threat_category=threat_category,
                    priority=priority,
                    action_type="Investigation",
                    summary="Correlate repetitive connection attempts with authentication daemon audit logs.",
                    detailed_guidance=(
                        "Examine host authentication logs (e.g. sshd auth.log, web access logs) to evaluate "
                        "whether credential spraying or password dictionary attempts occurred, and verify "
                        "that multi-factor authentication or account lockouts were successfully enforced."
                    ),
                    missing_evidence_required=(
                        mitre_mapping.missing_telemetry
                        if mitre_mapping
                        else ["Authentication failure logs"]
                    ),
                    analyst_validation_required=True,
                )
            )

        elif threat_category == "Bot":
            rec_id = cls._generate_id("INVESTIGATE_C2", threat_category)
            recommendations.append(
                AdvisoryRecommendation(
                    recommendation_id=rec_id,
                    threat_category=threat_category,
                    priority=priority,
                    action_type="Investigation",
                    summary="Investigate internal endpoints exhibiting periodic outbound beaconing.",
                    detailed_guidance=(
                        "Perform host forensic triage on systems initiating recurring communication intervals. "
                        "Inspect DNS query logs, active socket states, and scheduled tasks to verify if "
                        "unauthorized background processes or malware implants are active."
                    ),
                    missing_evidence_required=(
                        mitre_mapping.missing_telemetry
                        if mitre_mapping
                        else ["Process execution telemetry", "DNS logs"]
                    ),
                    analyst_validation_required=True,
                )
            )

        elif threat_category in ("Infiltration", "SQL Injection"):
            rec_id = cls._generate_id("ENRICH_PAYLOAD", threat_category)
            recommendations.append(
                AdvisoryRecommendation(
                    recommendation_id=rec_id,
                    threat_category=threat_category,
                    priority=priority,
                    action_type="Telemetry Enrichment",
                    summary="Correlate network flow anomalies with application and host security telemetries.",
                    detailed_guidance=(
                        "Flow statistics suggest potential exploitation activity, but Netflow lacks payload inspection. "
                        "Cross-reference events against Web Application Firewall (WAF) logs, database error logs, "
                        "and endpoint detection alerts before concluding a breach attempt occurred."
                    ),
                    missing_evidence_required=(
                        mitre_mapping.missing_telemetry
                        if mitre_mapping
                        else ["WAF transaction logs", "Payload captures"]
                    ),
                    analyst_validation_required=True,
                )
            )

        # 2. Advisory for Missing Target Asset Telemetry
        if tlrs_result and tlrs_result.scoring_status == "insufficient_evidence":
            rec_id = cls._generate_id("ENRICH_ASSET", threat_category)
            recommendations.append(
                AdvisoryRecommendation(
                    recommendation_id=rec_id,
                    threat_category=threat_category,
                    priority="Medium",
                    action_type="Telemetry Enrichment",
                    summary="Query enterprise asset inventory (CMDB) to resolve missing target impact.",
                    detailed_guidance=(
                        "The operational risk band was withheld because destination asset criticality telemetry "
                        "is missing from flow records. Link the observed destination port and network segment to "
                        "an authoritative asset management database to calculate a verified complete TLRS."
                    ),
                    missing_evidence_required=[
                        "Destination host asset criticality",
                        "Device role classification",
                    ],
                    analyst_validation_required=True,
                )
            )

        # 3. Advisory for Unreliable or Non-Evaluable ML Classification
        if model_reliability and model_reliability.status in ("UNRELIABLE", "NON_EVALUABLE"):
            rec_id = cls._generate_id("VERIFY_ML", threat_category)
            recommendations.append(
                AdvisoryRecommendation(
                    recommendation_id=rec_id,
                    threat_category=threat_category,
                    priority="Medium",
                    action_type="Investigation",
                    summary="Classifier validation reliability is low; verify flow characteristics manually.",
                    detailed_guidance=(
                        f"The ML classifier's validation reliability for '{threat_category}' is '{model_reliability.status}' "
                        f"({model_reliability.rationale}). Analysts must manually inspect flow duration, packet rates, "
                        "and protocol flags rather than relying on automated ML prediction labels."
                    ),
                    missing_evidence_required=[
                        "Independent packet trace capture",
                        "Validation ground truth confirmation",
                    ],
                    analyst_validation_required=True,
                )
            )

        return recommendations

    @staticmethod
    def _generate_id(prefix: str, threat_category: str) -> str:
        """Generate deterministic recommendation identifier."""
        clean_cat = threat_category.replace(" ", "_").replace("-", "_").upper()
        digest = hashlib.sha256(f"{prefix}:{clean_cat}".encode("utf-8")).hexdigest()[:6]
        return f"REC-{prefix}-{clean_cat}-{digest}"
