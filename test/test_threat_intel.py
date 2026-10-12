"""Unit tests for Threat Intelligence module (src/threat_intel.py)."""

import tempfile
from pathlib import Path
import pytest

from src.threat_intel import (
    CategoryNormalizer,
    MITREMapper,
    ContentManifestGenerator,
    assess_model_reliability,
    compute_profile_id,
    compute_snapshot_id,
    is_timestamp_in_window,
)


def test_category_normalization_canonical_and_unknown():
    """Verify label normalization and tri-state attack status."""
    # Benign
    norm_benign = CategoryNormalizer.normalize("Benign")
    assert norm_benign.canonical_label == "Benign"
    assert norm_benign.attack_status == "BENIGN"
    assert norm_benign.is_attack is False
    assert norm_benign.is_mapped is True

    # Known attacks with raw variations
    norm_infil = CategoryNormalizer.normalize("Infilteration")
    assert norm_infil.canonical_label == "Infiltration"
    assert norm_infil.attack_status == "ATTACK"
    assert norm_infil.is_attack is True

    norm_web = CategoryNormalizer.normalize("Brute Force -Web")
    assert norm_web.canonical_label == "Brute Force - Web"
    assert norm_web.attack_status == "ATTACK"
    assert norm_web.is_attack is True

    # Unmapped / Unknown label
    norm_unknown = CategoryNormalizer.normalize("ZeroDayExploit_404")
    assert norm_unknown.canonical_label == "UNKNOWN"
    assert norm_unknown.attack_status == "UNKNOWN"
    assert norm_unknown.is_attack is None
    assert norm_unknown.is_mapped is False


def test_mitre_mapping_candidate_and_unverified():
    """Verify official MITRE ATT&CK technique IDs and candidate vs unverified status."""
    # Candidate volumetric attacks
    ddos = MITREMapper.map_label("DDoS-HOIC")
    assert ddos.technique_id == "T1498.001"
    assert ddos.mapping_status == "candidate"
    assert ddos.tactic == "Impact"
    assert len(ddos.missing_telemetry) > 0

    hulk = MITREMapper.map_label("DoS-Hulk")
    assert hulk.technique_id == "T1499.003"
    assert hulk.mapping_status == "candidate"
    assert hulk.tactic == "Impact"

    ssh = MITREMapper.map_label("SSH-BruteForce")
    assert ssh.technique_id == "T1110.001"
    assert ssh.mapping_status == "candidate"
    assert ssh.tactic == "Credential Access"

    # Unverified payload/host-dependent attacks
    bot = MITREMapper.map_label("Bot")
    assert bot.technique_id == "T1071.001"
    assert bot.mapping_status == "unverified"
    assert "payload content" in bot.missing_telemetry[0].lower()

    sqli = MITREMapper.map_label("SQL Injection")
    assert sqli.technique_id == "T1190"
    assert sqli.mapping_status == "unverified"
    assert sqli.tactic == "Initial Access"

    infil = MITREMapper.map_label("Infiltration")
    assert infil.technique_id == "T1190"
    assert infil.mapping_status == "unverified"

    # Benign
    benign = MITREMapper.map_label("Benign")
    assert benign.technique_id is None
    assert benign.mapping_status == "not_applicable"

    # Unmapped category
    unknown = MITREMapper.map_label("UnrecognizedAttack")
    assert unknown.technique_id is None
    assert unknown.mapping_status == "unverified"


def test_deterministic_content_manifest_hashing():
    """Verify content manifest produces identical hashes regardless of input order."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        file_a = tmp_path / "part-00000.parquet"
        file_b = tmp_path / "part-00001.parquet"
        file_c = tmp_path / "part-00002.parquet"

        file_a.write_bytes(b"data block A content")
        file_b.write_bytes(b"data block B content")
        file_c.write_bytes(b"data block C content")

        # Manifest from directory discovery
        manifest1 = ContentManifestGenerator.generate_manifest(tmp_path)

        # Manifest from shuffled file list
        manifest2 = ContentManifestGenerator.generate_manifest([file_c, file_a, file_b], base_dir=tmp_path)

        assert manifest1.source_manifest_hash == manifest2.source_manifest_hash
        assert manifest1.files_count == 3
        assert manifest1.total_bytes == manifest2.total_bytes

        # Whole-file duplicate detection
        assert ContentManifestGenerator.is_duplicate_file(manifest1, file_a) is True

        # Non-duplicate file
        file_d = tmp_path / "different.parquet"
        file_d.write_bytes(b"completely different content")
        assert ContentManifestGenerator.is_duplicate_file(manifest1, file_d) is False


def test_profile_and_snapshot_identity_decoupling():
    """Verify profile_id is run-invariant while snapshot_id changes across runs."""
    p1 = compute_profile_id("flow_aggregation", "DDoS-HOIC", "2018-02-21T00:00:00", "2018-02-21T01:00:00", "hourly")
    p2 = compute_profile_id("flow_aggregation", "DDoS-HOIC", "2018-02-21T00:00:00", "2018-02-21T01:00:00", "hourly")
    p_diff = compute_profile_id("flow_aggregation", "DDoS-HOIC", "2018-02-21T01:00:00", "2018-02-21T02:00:00", "hourly")

    assert p1 == p2
    assert p1 != p_diff

    # Snapshot ID decoupling
    manifest_hash = "abc123def456"
    snap_run1 = compute_snapshot_id(p1, "run-20261013-001", manifest_hash)
    snap_run2 = compute_snapshot_id(p1, "run-20261013-002", manifest_hash)

    assert snap_run1 != snap_run2


def test_model_reliability_operational_gating():
    """Verify validation-only model reliability evaluation under various conditions."""
    # 1. Zero validation support
    r_zero = assess_model_reliability("Bot", validation_support=0)
    assert r_zero.status == "NON_EVALUABLE"

    # 2. Insufficient validation support (< 30)
    r_low_sup = assess_model_reliability("Infiltration", validation_support=15, precision=0.90, recall=0.90, f1=0.90)
    assert r_low_sup.status == "UNRELIABLE"

    # 3. Missing validation metric
    r_missing = assess_model_reliability("DoS-Hulk", validation_support=50, precision=0.85, recall=None, f1=0.80)
    assert r_missing.status == "UNRELIABLE"

    # 4. High reliability (support >= 100, P/R/F1 >= 0.75)
    r_high = assess_model_reliability("DDoS-HOIC", validation_support=120, precision=0.80, recall=0.85, f1=0.82)
    assert r_high.status == "HIGH_RELIABILITY"

    # 5. Evaluable (support >= 30, P/R/F1 >= 0.60)
    r_eval = assess_model_reliability("SSH-BruteForce", validation_support=45, precision=0.65, recall=0.62, f1=0.63)
    assert r_eval.status == "EVALUABLE"

    # 6. Below metric threshold (support >= 30, but F1 < 0.60)
    r_sub = assess_model_reliability("FTP-BruteForce", validation_support=50, precision=0.70, recall=0.55, f1=0.58)
    assert r_sub.status == "UNRELIABLE"

    # 7. Exact boundary tests for evaluable (N=30, metrics=0.60 vs 0.599)
    r_boundary_eval = assess_model_reliability("Test", validation_support=30, precision=0.60, recall=0.60, f1=0.60)
    assert r_boundary_eval.status == "EVALUABLE"

    r_boundary_fail = assess_model_reliability("Test", validation_support=30, precision=0.599, recall=0.60, f1=0.60)
    assert r_boundary_fail.status == "UNRELIABLE"

    # 8. High reliability boundaries at N=100 and metrics 0.75 vs 0.749
    r_high_exact = assess_model_reliability("Test", validation_support=100, precision=0.75, recall=0.75, f1=0.75)
    assert r_high_exact.status == "HIGH_RELIABILITY"

    r_high_p_fail = assess_model_reliability("Test", validation_support=100, precision=0.749, recall=0.75, f1=0.75)
    assert r_high_p_fail.status == "EVALUABLE"

    r_high_r_fail = assess_model_reliability("Test", validation_support=100, precision=0.75, recall=0.749, f1=0.75)
    assert r_high_r_fail.status == "EVALUABLE"

    r_high_f1_fail = assess_model_reliability("Test", validation_support=100, precision=0.75, recall=0.75, f1=0.749)
    assert r_high_f1_fail.status == "EVALUABLE"

    r_high_support_fail = assess_model_reliability("Test", validation_support=99, precision=0.80, recall=0.80, f1=0.80)
    assert r_high_support_fail.status == "EVALUABLE"

    # 9. Independent single-metric failures below evaluable threshold (0.60)
    r_fail_p = assess_model_reliability("Test", validation_support=50, precision=0.599, recall=0.70, f1=0.70)
    assert r_fail_p.status == "UNRELIABLE"

    r_fail_r = assess_model_reliability("Test", validation_support=50, precision=0.70, recall=0.599, f1=0.70)
    assert r_fail_r.status == "UNRELIABLE"

    r_fail_f1 = assess_model_reliability("Test", validation_support=50, precision=0.70, recall=0.70, f1=0.599)
    assert r_fail_f1.status == "UNRELIABLE"


def test_timestamp_window_half_open_interval():
    """Verify strict half-open window semantics: [window_start, window_end).

    Boundary expectations:
    - Exactly at window_start -> Included (True)
    - Strictly between window_start and window_end -> Included (True)
    - Exactly at window_end -> Excluded (False)
    - Before window_start -> Excluded (False)
    - After window_end -> Excluded (False)
    """
    start = "2018-02-14T08:00:00"
    end = "2018-02-14T09:00:00"

    # Exact start boundary (Included)
    assert is_timestamp_in_window("2018-02-14T08:00:00", start, end) is True

    # Interior point (Included)
    assert is_timestamp_in_window("2018-02-14T08:30:00", start, end) is True

    # Exact end boundary (Excluded)
    assert is_timestamp_in_window("2018-02-14T09:00:00", start, end) is False

    # Pre-window timestamp (Excluded)
    assert is_timestamp_in_window("2018-02-14T07:59:59", start, end) is False

    # Post-window timestamp (Excluded)
    assert is_timestamp_in_window("2018-02-14T09:00:01", start, end) is False
