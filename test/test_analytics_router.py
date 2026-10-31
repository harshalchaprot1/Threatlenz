"""Tests for Phase 8 Analytics & Diagnostics Read-Only Router."""

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app


@pytest.fixture(scope="module")
def client():
    """Test client for FastAPI app."""
    return TestClient(app)


def test_temporal_analytics_endpoint(client: TestClient):
    """Verify GET /api/v1/analytics/temporal returns 8 campaign dates and counts."""
    response = client.get("/api/v1/analytics/temporal")
    assert response.status_code == 200
    data = response.json()
    assert data["horizon_days"] == 8
    assert len(data["dates"]) == 8
    assert len(data["event_date_totals"]) == 8
    # Assert specific non-contiguous dates
    assert "2018-02-14" in data["dates"]
    assert "2018-03-02" in data["dates"]
    # Check total sum across dates is 7,235,606
    total_flows = sum(d["total_flows"] for d in data["event_date_totals"])
    assert total_flows == 7235606
    assert len(data["attack_temporal_profiles"]) == 14


def test_ports_analytics_endpoint(client: TestClient):
    """Verify GET /api/v1/analytics/ports returns 14 categories with top port breakdowns."""
    response = client.get("/api/v1/analytics/ports")
    assert response.status_code == 200
    data = response.json()
    assert data["total_categories"] == 14
    assert "Benign" in data["categories"]
    benign_ports = data["categories"]["Benign"]
    assert benign_ports["total_flows"] == 5064128
    assert len(benign_ports["top_ports"]) >= 3
    # First port for benign is DNS (port 53)
    assert benign_ports["top_ports"][0]["port"] == 53


def test_model_diagnostics_endpoint(client: TestClient):
    """Verify GET /api/v1/analytics/model-diagnostics returns importances and both confusion matrices."""
    response = client.get("/api/v1/analytics/model-diagnostics")
    assert response.status_code == 200
    data = response.json()
    assert "model_artifact" in data
    assert data["model_governance_status"] == "EVALUATED_VALIDATION_BENCHMARK"
    assert "quarantined" in data["quarantine_disclosure"].lower()
    assert len(data["top_feature_importances"]) == 10

    # Validation Confusion Matrix (14x14)
    val_cm = data["validation_metrics"]["confusion_matrix"]
    assert len(val_cm["class_labels"]) == 14
    assert len(val_cm["raw_matrix"]) == 14
    assert len(val_cm["raw_matrix"][0]) == 14
    assert len(val_cm["normalized_matrix"]) == 14

    # Test Confusion Matrix (14x14)
    test_cm = data["test_metrics"]["confusion_matrix"]
    assert len(test_cm["class_labels"]) == 14
    assert len(test_cm["raw_matrix"]) == 14
    assert len(test_cm["raw_matrix"][0]) == 14
    assert len(test_cm["normalized_matrix"]) == 14


def test_feature_redundancy_endpoint(client: TestClient):
    """Verify GET /api/v1/analytics/feature-redundancy returns all 9 evaluated pairs."""
    response = client.get("/api/v1/analytics/feature-redundancy")
    assert response.status_code == 200
    data = response.json()
    assert data["evaluated_pairs_count"] == 9
    assert len(data["all_evaluated_correlations"]) == 9
    assert data["redundant_pairs_count"] == 8  # 6 duplicate + 2 collinear pairs

    # Verify non-collinear pair is present
    non_collinear = [
        p for p in data["all_evaluated_correlations"]
        if p["feature_1"] == "flow_pkts_s" and p["feature_2"] == "flow_byts_s"
    ]
    assert len(non_collinear) == 1
    assert pytest.approx(non_collinear[0]["pearson_correlation"], 0.001) == 0.283
    assert non_collinear[0]["is_near_duplicate"] is False

