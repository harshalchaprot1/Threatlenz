"""Unit tests for ThreatLenz configuration."""

import pytest
from src.config import settings


def test_settings_initialization():
    """Verify settings loads expected baseline defaults."""
    assert settings.app_name == "ThreatLenz"
    assert settings.project_root.exists()
    assert settings.data_raw_dir.exists()


def test_raw_columns_count():
    """Verify official CSE-CIC-IDS2018 80-column definition."""
    assert len(settings.raw_columns) == 80
    assert settings.raw_columns[0] == "Dst Port"
    assert settings.raw_columns[-1] == "Label"


def test_column_mapping_completeness():
    """Verify all 80 raw columns map to clean unique snake_case names."""
    assert len(settings.column_mapping) == 80
    clean_names = set(settings.column_mapping.values())
    assert len(clean_names) == 80
    assert "dst_port" in clean_names
    assert "flow_duration" in clean_names
    assert "label" in clean_names


def test_label_mapping_integrity():
    """Verify all 14 dataset attack classes are mapped correctly."""
    assert len(settings.label_mapping) == 14
    assert settings.label_mapping["Infilteration"] == "Infiltration"
    assert settings.label_mapping["Brute Force -Web"] == "Brute Force - Web"
    assert settings.label_mapping["Brute Force -XSS"] == "Brute Force - XSS"
    assert settings.label_mapping["SSH-Bruteforce"] == "SSH-BruteForce"
    assert settings.label_mapping["Benign"] == "Benign"


def test_tlrs_weights_sum_to_one():
    """Verify mathematical consistency of the four approved TLRS weights."""
    total_weight = (
        settings.tlrs_weight_severity
        + settings.tlrs_weight_frequency
        + settings.tlrs_weight_recurrence
        + settings.tlrs_weight_target_impact
    )
    assert pytest.approx(total_weight, 1e-6) == 1.0
