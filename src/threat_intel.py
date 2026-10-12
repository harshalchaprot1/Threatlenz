"""ThreatLenz Threat Intelligence Layer.

Implements normalized attack categorization, MITRE ATT&CK candidate mapping,
deterministic content manifest hashing, identity generation (profile vs snapshot),
and model reliability gating based on validation-split evaluation metrics.
"""

from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from src.config import settings


class NormalizedCategory(BaseModel):
    """Structured representation of a normalized network traffic label."""

    canonical_label: str
    raw_label: str
    attack_status: str  # "ATTACK", "BENIGN", or "UNKNOWN"
    is_attack: Optional[bool] = None  # None for UNKNOWN
    is_mapped: bool = True


class MITRETechniqueMapping(BaseModel):
    """Structured MITRE ATT&CK mapping with verifiable candidate status."""

    canonical_label: str
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None
    tactic: Optional[str] = None
    mapping_status: str  # "candidate", "unverified", or "not_applicable"
    rationale: str
    missing_telemetry: List[str] = Field(default_factory=list)


class ManifestFileEntry(BaseModel):
    """Canonical record of a dataset file for content manifest hashing."""

    path: str
    sha256: str
    size_bytes: int


class ManifestResult(BaseModel):
    """Deterministic content manifest for source data ingestion."""

    source_manifest_hash: str
    files_count: int
    total_bytes: int
    entries: List[ManifestFileEntry]


class ModelReliabilityAssessment(BaseModel):
    """Operational reliability evaluation of a threat classifier using validation data."""

    class_name: str
    validation_support: int
    validation_precision: Optional[float] = None
    validation_recall: Optional[float] = None
    validation_f1: Optional[float] = None
    status: str  # "HIGH_RELIABILITY", "EVALUABLE", "UNRELIABLE", "NON_EVALUABLE"
    rationale: str


class ThreatProfile(BaseModel):
    """Immutable structured threat profile aggregating threat event evidence."""

    profile_id: str
    snapshot_id: str
    run_id: str
    source_manifest_hash: str
    schema_version: str = "1.0"
    window_type: str
    window_start: str
    window_end: str
    category: NormalizedCategory
    mitre_mapping: MITRETechniqueMapping
    flow_count: int
    total_bytes: int
    total_packets: int
    active_observation_units: int
    recurrence_denominator: int
    model_reliability: Optional[ModelReliabilityAssessment] = None
    tlrs_result: Optional[Dict[str, Any]] = None
    advisories: List[Dict[str, Any]] = Field(default_factory=list)


class CategoryNormalizer:
    """Normalizes raw flow labels into canonical ThreatLenz threat classes."""

    @staticmethod
    def normalize(raw_label: str) -> NormalizedCategory:
        """Map raw dataset label to canonical class and safe tri-state attack status."""
        raw_clean = raw_label.strip() if raw_label else ""
        canonical = settings.label_mapping.get(raw_clean)

        if canonical is None:
            return NormalizedCategory(
                canonical_label="UNKNOWN",
                raw_label=raw_clean,
                attack_status="UNKNOWN",
                is_attack=None,
                is_mapped=False,
            )

        if canonical == "Benign":
            return NormalizedCategory(
                canonical_label="Benign",
                raw_label=raw_clean,
                attack_status="BENIGN",
                is_attack=False,
                is_mapped=True,
            )

        return NormalizedCategory(
            canonical_label=canonical,
            raw_label=raw_clean,
            attack_status="ATTACK",
            is_attack=True,
            is_mapped=True,
        )


class MITREMapper:
    """Maps canonical attack categories to official MITRE ATT&CK techniques."""

    # Official MITRE ATT&CK Enterprise Matrix v14/v15 mappings
    _MAPPINGS: Dict[str, Dict[str, Any]] = {
        "Benign": {
            "technique_id": None,
            "technique_name": None,
            "tactic": None,
            "mapping_status": "not_applicable",
            "rationale": "Benign baseline network traffic without adversary activity.",
            "missing_telemetry": [],
        },
        "Bot": {
            "technique_id": "T1071.001",
            "technique_name": "Application Layer Protocol: Web Protocols",
            "tactic": "Command and Control",
            "mapping_status": "unverified",
            "rationale": (
                "Netflow captures periodic outbound communication patterns consistent with "
                "C2 beaconing, but lacks application-layer payload and host process context "
                "to verify command-and-control protocol structure."
            ),
            "missing_telemetry": [
                "Application layer payload content",
                "HTTP request URI and headers",
                "Endpoint process execution tree",
            ],
        },
        "Brute Force - Web": {
            "technique_id": "T1110.001",
            "technique_name": "Password Guessing",
            "tactic": "Credential Access",
            "mapping_status": "candidate",
            "rationale": (
                "Repetitive short HTTP TCP flows targeting web ports (80/8080) characteristic of "
                "automated password spraying/guessing."
            ),
            "missing_telemetry": [
                "HTTP 401/403 response error status codes",
                "Web application authentication endpoint logs",
            ],
        },
        "Brute Force - XSS": {
            "technique_id": "T1110.001",
            "technique_name": "Password Guessing",
            "tactic": "Credential Access",
            "mapping_status": "candidate",
            "rationale": (
                "Dataset artifact labeled as brute force attack leveraging automated submission tools "
                "against web input vectors."
            ),
            "missing_telemetry": [
                "HTTP request parameters and POST body",
                "Web application response logs",
            ],
        },
        "DDoS-HOIC": {
            "technique_id": "T1498.001",
            "technique_name": "Network Denial of Service: Direct Network Flood",
            "tactic": "Impact",
            "mapping_status": "candidate",
            "rationale": (
                "High-volume distributed HTTP flood from multiple source addresses exhausting "
                "network bandwidth and connection pools."
            ),
            "missing_telemetry": [
                "Upstream link saturation telemetries",
                "Web server connection backlog metrics",
            ],
        },
        "DDoS-LOIC-UDP": {
            "technique_id": "T1498.001",
            "technique_name": "Network Denial of Service: Direct Network Flood",
            "tactic": "Impact",
            "mapping_status": "candidate",
            "rationale": (
                "High-rate volumetric UDP packet flood targeting endpoint services."
            ),
            "missing_telemetry": [
                "Router interface discard counters",
                "Per-link bandwidth saturation telemetry",
            ],
        },
        "DoS-GoldenEye": {
            "technique_id": "T1499.003",
            "technique_name": "Endpoint Denial of Service: Application Exhaustion Flood",
            "tactic": "Impact",
            "mapping_status": "candidate",
            "rationale": (
                "Application-layer HTTP Keep-Alive and Cache-Control abuse keeping sockets "
                "open and depleting worker thread pools."
            ),
            "missing_telemetry": [
                "Web server worker thread status",
                "Connection pool exhaustion logs",
            ],
        },
        "DoS-Hulk": {
            "technique_id": "T1499.003",
            "technique_name": "Endpoint Denial of Service: Application Exhaustion Flood",
            "tactic": "Impact",
            "mapping_status": "candidate",
            "rationale": (
                "High-rate HTTP GET flood with randomized user-agents and cache-busting headers "
                "exhausting web application request queues."
            ),
            "missing_telemetry": [
                "Web server queue depth",
                "Endpoint CPU and memory consumption metrics",
            ],
        },
        "DoS-SlowHTTPTest": {
            "technique_id": "T1499.003",
            "technique_name": "Endpoint Denial of Service: Application Exhaustion Flood",
            "tactic": "Impact",
            "mapping_status": "candidate",
            "rationale": (
                "Slow HTTP POST/headers holding web connections open until limits are reached."
            ),
            "missing_telemetry": [
                "Active TCP connection table holding durations",
                "Web server timeout logs",
            ],
        },
        "DoS-Slowloris": {
            "technique_id": "T1499.003",
            "technique_name": "Endpoint Denial of Service: Application Exhaustion Flood",
            "tactic": "Impact",
            "mapping_status": "candidate",
            "rationale": (
                "Periodic partial HTTP request headers keeping connections open indefinitely."
            ),
            "missing_telemetry": [
                "Concurrent open socket states",
                "Web server timeout logs",
            ],
        },
        "FTP-BruteForce": {
            "technique_id": "T1110.001",
            "technique_name": "Password Guessing",
            "tactic": "Credential Access",
            "mapping_status": "candidate",
            "rationale": (
                "High-frequency TCP connection attempts on port 21 characteristic of automated "
                "credential dictionary attacks."
            ),
            "missing_telemetry": [
                "FTP server daemon authentication logs",
                "Failed login error 530 records",
            ],
        },
        "Infiltration": {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "mapping_status": "unverified",
            "rationale": (
                "Simulated client-side software exploitation followed by pivot; Netflow alone "
                "cannot verify binary exploit payloads or host execution traces."
            ),
            "missing_telemetry": [
                "Host process audit logs",
                "Endpoint EDR alerts",
                "Packet payloads",
            ],
        },
        "SQL Injection": {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "mapping_status": "unverified",
            "rationale": (
                "Web application vulnerability exploitation requiring payload inspection; Netflow "
                "only observes packet sizes and inter-arrival times without SQL query visibility."
            ),
            "missing_telemetry": [
                "Decrypted HTTP request URI and body",
                "WAF inspection alerts",
                "Database error and audit logs",
            ],
        },
        "SSH-BruteForce": {
            "technique_id": "T1110.001",
            "technique_name": "Password Guessing",
            "tactic": "Credential Access",
            "mapping_status": "candidate",
            "rationale": (
                "Repetitive rapid TCP handshakes on port 22 matching SSH credential brute forcing."
            ),
            "missing_telemetry": [
                "sshd auth.log failed password attempts",
            ],
        },
    }

    @classmethod
    def map_label(cls, canonical_label: str) -> MITRETechniqueMapping:
        """Retrieve verified MITRE ATT&CK technique mapping for canonical category."""
        entry = cls._MAPPINGS.get(canonical_label)
        if entry is None:
            return MITRETechniqueMapping(
                canonical_label=canonical_label,
                technique_id=None,
                technique_name=None,
                tactic=None,
                mapping_status="unverified",
                rationale="Unrecognized or unmapped traffic category without verified attack evidence.",
                missing_telemetry=["Ground truth telemetry and payload captures"],
            )

        return MITRETechniqueMapping(
            canonical_label=canonical_label,
            technique_id=entry["technique_id"],
            technique_name=entry["technique_name"],
            tactic=entry["tactic"],
            mapping_status=entry["mapping_status"],
            rationale=entry["rationale"],
            missing_telemetry=list(entry["missing_telemetry"]),
        )


class ContentManifestGenerator:
    """Computes deterministic content manifests and hashes for data provenance."""

    @staticmethod
    def hash_file_sha256(file_path: Path) -> str:
        """Compute SHA-256 digest of a single file in chunks."""
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    @classmethod
    def generate_manifest(
        cls,
        target_path: Path | List[Path],
        base_dir: Optional[Path] = None,
    ) -> ManifestResult:
        """Generate deterministic file manifest and overall content digest.

        Canonicalization rules:
        - If target_path is a directory, recursively discover all data files (ignoring metadata like .crc).
        - Sort relative POSIX paths in strictly ascending ASCII order.
        - Hash each file via SHA-256.
        - Form canonical JSON payload (sorted keys, compact separators).
        - Hash the canonical JSON with SHA-256[:16] for source_manifest_hash.
        """
        raw_files: List[Path] = []
        if isinstance(target_path, list):
            raw_files = list(target_path)
            ref_dir = base_dir or (raw_files[0].parent if raw_files else Path("."))
        elif target_path.is_dir():
            ref_dir = base_dir or target_path
            for p in target_path.rglob("*"):
                # Exclude hidden files, Spark checksums, and metadata
                if p.is_file() and not p.name.startswith(".") and not p.name.startswith("_"):
                    raw_files.append(p)
        else:
            ref_dir = base_dir or target_path.parent
            raw_files = [target_path]

        entries: List[ManifestFileEntry] = []
        for file_p in sorted(raw_files, key=lambda x: x.resolve().as_posix()):
            try:
                rel_path = file_p.relative_to(ref_dir).as_posix()
            except ValueError:
                rel_path = file_p.name

            file_hash = cls.hash_file_sha256(file_p)
            file_size = file_p.stat().st_size
            entries.append(
                ManifestFileEntry(
                    path=rel_path,
                    sha256=file_hash,
                    size_bytes=file_size,
                )
            )

        # Sort entries strictly by relative POSIX path for determinism
        entries.sort(key=lambda e: e.path)

        canonical_data = [
            {"path": e.path, "sha256": e.sha256, "size_bytes": e.size_bytes}
            for e in entries
        ]
        canonical_json = json.dumps(canonical_data, sort_keys=True, separators=(",", ":"))
        source_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()[:16]

        total_bytes = sum(e.size_bytes for e in entries)
        return ManifestResult(
            source_manifest_hash=source_hash,
            files_count=len(entries),
            total_bytes=total_bytes,
            entries=entries,
        )

    @classmethod
    def is_duplicate_file(cls, manifest: ManifestResult, file_path: Path) -> bool:
        """Check if an incoming file matches an existing entry in the manifest."""
        incoming_hash = cls.hash_file_sha256(file_path)
        return any(entry.sha256 == incoming_hash for entry in manifest.entries)


def compute_profile_id(
    source_type: str,
    category_id: str,
    window_start: str,
    window_end: str,
    window_type: str,
) -> str:
    """Generate deterministic, run-invariant profile identifier (natural key)."""
    key_str = f"{source_type}:{category_id}:{window_start}:{window_end}:{window_type}"
    return hashlib.sha256(key_str.encode("utf-8")).hexdigest()[:16]


def compute_snapshot_id(
    profile_id: str,
    run_id: str,
    source_manifest_hash: str,
    schema_version: str = "1.0",
) -> str:
    """Generate run-specific immutable snapshot identifier."""
    key_str = f"{profile_id}:{run_id}:{source_manifest_hash}:{schema_version}"
    return hashlib.sha256(key_str.encode("utf-8")).hexdigest()[:16]


def assess_model_reliability(
    class_name: str,
    validation_support: int,
    validation_precision: Optional[float] = None,
    validation_recall: Optional[float] = None,
    validation_f1: Optional[float] = None,
    precision: Optional[float] = None,
    recall: Optional[float] = None,
    f1: Optional[float] = None,
) -> ModelReliabilityAssessment:
    """Evaluate operational model reliability for a class using validation metrics only.

    Configurable Policy:
    - Zero validation support -> NON_EVALUABLE
    - Support < min_validation_support (30) -> UNRELIABLE
    - Any missing metric (None) -> UNRELIABLE
    - Support >= high_reliability_min_support (100) and P, R, F1 >= 0.75 -> HIGH_RELIABILITY
    - Support >= min_validation_support (30) and P, R, F1 >= 0.60 -> EVALUABLE
    - Otherwise -> UNRELIABLE
    """
    val_precision = validation_precision if validation_precision is not None else precision
    val_recall = validation_recall if validation_recall is not None else recall
    val_f1 = validation_f1 if validation_f1 is not None else f1

    if validation_support == 0:
        return ModelReliabilityAssessment(
            class_name=class_name,
            validation_support=0,
            validation_precision=val_precision,
            validation_recall=val_recall,
            validation_f1=val_f1,
            status="NON_EVALUABLE",
            rationale=(
                f"Class '{class_name}' had 0 validation instances; model predictions cannot "
                "be verified on validation data."
            ),
        )

    if validation_support < settings.min_validation_support:
        return ModelReliabilityAssessment(
            class_name=class_name,
            validation_support=validation_support,
            validation_precision=val_precision,
            validation_recall=val_recall,
            validation_f1=val_f1,
            status="UNRELIABLE",
            rationale=(
                f"Validation support ({validation_support}) is below the required operational "
                f"threshold ({settings.min_validation_support})."
            ),
        )

    if val_precision is None or val_recall is None or val_f1 is None:
        return ModelReliabilityAssessment(
            class_name=class_name,
            validation_support=validation_support,
            validation_precision=val_precision,
            validation_recall=val_recall,
            validation_f1=val_f1,
            status="UNRELIABLE",
            rationale=f"Class '{class_name}' has incomplete validation metrics.",
        )

    # Check High Reliability criteria
    is_high_support = validation_support >= settings.high_reliability_min_support
    meets_high_metrics = (
        val_precision >= settings.high_reliability_min_precision
        and val_recall >= settings.high_reliability_min_recall
        and val_f1 >= settings.high_reliability_min_f1
    )

    if is_high_support and meets_high_metrics:
        return ModelReliabilityAssessment(
            class_name=class_name,
            validation_support=validation_support,
            validation_precision=val_precision,
            validation_recall=val_recall,
            validation_f1=val_f1,
            status="HIGH_RELIABILITY",
            rationale=(
                f"Class '{class_name}' meets high-reliability validation criteria: "
                f"support={validation_support}, precision={val_precision:.3f}, "
                f"recall={val_recall:.3f}, F1={val_f1:.3f}."
            ),
        )

    # Check Evaluable criteria
    meets_evaluable_metrics = (
        val_precision >= settings.evaluable_min_precision
        and val_recall >= settings.evaluable_min_recall
        and val_f1 >= settings.evaluable_min_f1
    )

    if meets_evaluable_metrics:
        return ModelReliabilityAssessment(
            class_name=class_name,
            validation_support=validation_support,
            validation_precision=val_precision,
            validation_recall=val_recall,
            validation_f1=val_f1,
            status="EVALUABLE",
            rationale=(
                f"Class '{class_name}' meets evaluable operational criteria: "
                f"support={validation_support}, precision={val_precision:.3f}, "
                f"recall={val_recall:.3f}, F1={val_f1:.3f}."
            ),
        )

    return ModelReliabilityAssessment(
        class_name=class_name,
        validation_support=validation_support,
        validation_precision=val_precision,
        validation_recall=val_recall,
        validation_f1=val_f1,
        status="UNRELIABLE",
        rationale=(
            f"Class '{class_name}' validation performance is below operational threshold: "
            f"precision={val_precision:.3f}, recall={val_recall:.3f}, "
            f"F1={val_f1:.3f}."
        ),
    )


def parse_timestamp(ts: datetime | str) -> datetime:
    """Parse string or datetime into a standard datetime object."""
    if isinstance(ts, datetime):
        return ts
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%d/%m/%Y %H:%M:%S"):
            try:
                return datetime.strptime(ts, fmt)
            except ValueError:
                continue
        raise ValueError(f"Unable to parse timestamp: {ts}")


def is_timestamp_in_window(
    timestamp: datetime | str,
    window_start: datetime | str,
    window_end: datetime | str,
) -> bool:
    """Evaluate whether a timestamp falls within the half-open window [window_start, window_end).

    Enforces strict half-open interval semantics:
    window_start <= timestamp < window_end
    - Timestamp exactly at window_start is INCLUDED.
    - Timestamp exactly at window_end is EXCLUDED.
    """
    t = parse_timestamp(timestamp)
    start = parse_timestamp(window_start)
    end = parse_timestamp(window_end)
    return start <= t < end
