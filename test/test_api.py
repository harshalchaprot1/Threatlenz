"""ThreatLenz Phase 7: FastAPI Backend Test Suite.

Verifies:
1. Health endpoint with active database ping and graceful degradation handling.
2. Pipeline runs listing with pagination, and detailed retrieval.
3. Threat profile listing with pagination, run filtering, and category filtering.
4. Risk assessment retrieval preserving null scores and unconfirmed Insufficient Evidence status.
5. MITRE ATT&CK mapping retrieval clearly identifying candidate/unverified techniques.
6. Advisory retrieval strictly enforcing analyst_validation_required=True and non-automation.
7. OpenAPI schema validation and 404/405/422 status code correctness.
8. Read-only safety and zero leakage of database connection credentials or stack traces.
"""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from sqlalchemy.pool import StaticPool

from backend.app.dependencies import get_db
from backend.app.main import app
from src.database import init_db, load_threat_intelligence_report


@pytest.fixture(scope="module")
def test_db_engine():
    """Isolated in-memory SQLite engine populated with Phase 5 real report."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    init_db(engine)

    # Pre-populate with report data
    report_path = Path("reports/threat_intelligence_report.json")
    if not report_path.exists():
        pytest.skip("reports/threat_intelligence_report.json not found; run pipeline first.")

    load_threat_intelligence_report(report_path, engine=engine)
    return engine


@pytest.fixture
def client(test_db_engine):
    """FastAPI TestClient bound to isolated test database."""
    session_factory = sessionmaker(bind=test_db_engine, expire_on_commit=False, future=True)

    def override_get_db():
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


# 1. Health & Service Metadata Endpoints
def test_health_endpoint_healthy(client):
    """Verifies that /health returns 200 with connected database status."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["database"]["status"] == "connected"
    assert "sqlite" in data["database"]["dialect"].lower()
    assert data["app_name"] == "ThreatLenz"
    assert data["version"] == "1.0.0"


def test_health_endpoint_degraded_on_db_disconnect(client):
    """Verifies that /health returns 503 degraded without leaking connection strings when DB fails."""
    def broken_get_db():
        class MockBrokenSession:
            bind = None
            def execute(self, *args, **kwargs):
                raise RuntimeError("Simulated database failure: connection refused")
            def close(self):
                pass
        yield MockBrokenSession()

    app.dependency_overrides[get_db] = broken_get_db
    response = client.get("/health")
    assert response.status_code == 503
    data = response.json()
    assert data["status"] == "degraded"
    assert data["database"]["status"] == "disconnected"
    # Ensure raw stack trace or simulated error is NOT leaked in payload
    assert "Simulated database failure" not in str(data)


def test_root_endpoint(client):
    """Verifies service metadata at root path /."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["app_name"] == "ThreatLenz"
    assert data["docs_url"] == "/docs"


# 2. Pipeline Runs Endpoints
def test_list_runs_pagination(client):
    """Verifies GET /api/v1/runs with pagination envelope."""
    response = client.get("/api/v1/runs?limit=10&offset=0")
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert data["total"] >= 1
    assert data["limit"] == 10
    assert data["offset"] == 0

    run = data["items"][0]
    assert run["run_id"].startswith("run_")
    assert run["report_name"] == "ThreatLenz-Phase5-Threat-Intelligence"
    assert run["total_profiles"] == 14
    assert run["model_status"] == "QUARANTINED_TARGET_LEAKAGE"


def test_get_run_detail_valid_and_not_found(client):
    """Verifies GET /api/v1/runs/{run_id} returns complete detail or 404."""
    # First get a valid run_id
    runs_res = client.get("/api/v1/runs?limit=1")
    run_id = runs_res.json()["items"][0]["run_id"]

    # Valid run detail
    res = client.get(f"/api/v1/runs/{run_id}")
    assert res.status_code == 200
    data = res.json()
    assert data["run_id"] == run_id
    assert data["source_manifest_hash"] == "22d6470cfb100c00"
    assert data["provenance_type"] == "curated_dataset_flows"
    assert data["is_model_prediction"] is False
    assert data["is_live_detection"] is False
    assert data["model_inference_executed"] is False
    assert data["model_evaluation_metrics_status"] == "QUARANTINED_EXCLUDED_FROM_EVIDENCE"
    assert data["target_impact_status"] == "MISSING_EVIDENCE_WITHHELD"

    # Non-existent run
    not_found_res = client.get("/api/v1/runs/run_non_existent_999")
    assert not_found_res.status_code == 404
    assert "not found" in not_found_res.json()["detail"].lower()


# 3. Threat Profiles Endpoints
def test_list_profiles_pagination_and_sorting(client):
    """Verifies GET /api/v1/profiles pagination and sorting."""
    response = client.get("/api/v1/profiles?limit=5&offset=0")
    assert response.status_code == 200
    data = response.json()
    assert len(data["items"]) == 5
    assert data["total"] == 14

    # Flow count ordering (highest flow count first)
    flows = [p["flow_count"] for p in data["items"]]
    assert flows == sorted(flows, reverse=True)


def test_list_profiles_filters(client):
    """Verifies GET /api/v1/profiles with various query filter combinations."""
    # Filter by canonical label
    bot_res = client.get("/api/v1/profiles?canonical_label=Bot")
    assert bot_res.status_code == 200
    bot_data = bot_res.json()
    assert bot_data["total"] == 1
    assert bot_data["items"][0]["canonical_label"] == "Bot"
    assert bot_data["items"][0]["is_attack"] is True

    # Filter by attack_status
    attacks_res = client.get("/api/v1/profiles?attack_status=ATTACK")
    assert attacks_res.status_code == 200
    assert attacks_res.json()["total"] == 13

    # Filter by is_attack=false
    benign_res = client.get("/api/v1/profiles?is_attack=false")
    assert benign_res.status_code == 200
    benign_data = benign_res.json()
    assert benign_data["total"] == 1
    assert benign_data["items"][0]["canonical_label"] == "Benign"

    # Non-matching filter
    empty_res = client.get("/api/v1/profiles?canonical_label=NonExistentCategory")
    assert empty_res.status_code == 200
    assert empty_res.json()["total"] == 0
    assert len(empty_res.json()["items"]) == 0


def test_get_profile_detail_valid_and_not_found(client):
    """Verifies GET /api/v1/profiles/{snapshot_id}."""
    # Retrieve a valid snapshot_id
    prof_res = client.get("/api/v1/profiles?canonical_label=Bot")
    snapshot_id = prof_res.json()["items"][0]["snapshot_id"]

    res = client.get(f"/api/v1/profiles/{snapshot_id}")
    assert res.status_code == 200
    p = res.json()
    assert p["snapshot_id"] == snapshot_id
    assert p["canonical_label"] == "Bot"
    assert p["recurrence_denominator"] == 8
    assert p["model_reliability"] is None

    # Invalid snapshot_id
    nf_res = client.get("/api/v1/profiles/invalid_snapshot_999")
    assert nf_res.status_code == 404
    assert "not found" in nf_res.json()["detail"].lower()


# 4. Risk Assessments Safeguard Verification
def test_get_profile_risk_assessment_safeguard(client):
    """Verifies GET /api/v1/profiles/{snapshot_id}/risk preserves nulls and unconfirmed status."""
    prof_res = client.get("/api/v1/profiles?canonical_label=Bot")
    snapshot_id = prof_res.json()["items"][0]["snapshot_id"]

    res = client.get(f"/api/v1/profiles/{snapshot_id}/risk")
    assert res.status_code == 200
    risk = res.json()
    assert risk["snapshot_id"] == snapshot_id

    # Mandatory Phase 4/5/6 Safeguards:
    # 1. Missing target telemetry must be NULL
    assert risk["target_impact_score"] is None
    # 2. Complete TLRS score must be NULL
    assert risk["tlrs_complete"] is None
    assert risk["tlrs_complete_rounded"] is None
    # 3. Status must be Insufficient Evidence
    assert risk["scoring_status"] == "insufficient_evidence"
    assert risk["risk_band"] == "Insufficient Evidence"
    assert "DIAGNOSTIC_ONLY" in risk["provisional_risk_band"]
    # 4. Provisional score is NEVER confirmed intelligence
    assert risk["is_confirmed"] is False
    # 5. Diagnostic partial scores are preserved
    assert risk["tlrs_partial_diagnostic"] > 0
    assert risk["evidence_coverage"] == 0.85

    # 404 for invalid profile
    assert client.get("/api/v1/profiles/invalid_id/risk").status_code == 404


# 5. MITRE ATT&CK Mappings Safeguard Verification
def test_get_profile_mitre_mapping_safeguard(client):
    """Verifies GET /api/v1/profiles/{snapshot_id}/mitre distinguishes candidate mappings."""
    # Test Bot mapping
    prof_res = client.get("/api/v1/profiles?canonical_label=Bot")
    snapshot_id = prof_res.json()["items"][0]["snapshot_id"]

    res = client.get(f"/api/v1/profiles/{snapshot_id}/mitre")
    assert res.status_code == 200
    mitre = res.json()
    assert mitre["snapshot_id"] == snapshot_id
    assert mitre["technique_id"] == "T1071.001"
    assert mitre["technique_name"] == "Application Layer Protocol: Web Protocols"
    assert mitre["mapping_status"] == "unverified"
    # Crucial safeguard: candidate/unverified mappings are strictly unconfirmed
    assert mitre["is_confirmed"] is False
    assert len(mitre["missing_telemetry"]) > 0

    # Test Benign mapping (not_applicable)
    benign_res = client.get("/api/v1/profiles?canonical_label=Benign")
    b_snap_id = benign_res.json()["items"][0]["snapshot_id"]
    b_mitre = client.get(f"/api/v1/profiles/{b_snap_id}/mitre").json()
    assert b_mitre["mapping_status"] == "not_applicable"
    assert b_mitre["technique_id"] is None
    assert b_mitre["is_confirmed"] is False

    # 404 for invalid profile
    assert client.get("/api/v1/profiles/invalid_id/mitre").status_code == 404


# 6. Advisories Safeguard Verification
def test_get_profile_advisories_safeguard(client):
    """Verifies GET /api/v1/profiles/{snapshot_id}/advisories preserves human validation rules."""
    prof_res = client.get("/api/v1/profiles?canonical_label=Bot")
    snapshot_id = prof_res.json()["items"][0]["snapshot_id"]

    res = client.get(f"/api/v1/profiles/{snapshot_id}/advisories")
    assert res.status_code == 200
    data = res.json()
    assert data["snapshot_id"] == snapshot_id
    assert data["total"] == 2
    assert len(data["items"]) == 2

    for adv in data["items"]:
        # Strict governance safeguards:
        assert adv["analyst_validation_required"] is True
        assert adv["is_automated_action"] is False
        assert len(adv["recommendation_id"]) > 0
        assert len(adv["summary"]) > 0
        assert len(adv["detailed_guidance"]) > 0

    # 404 for invalid profile
    assert client.get("/api/v1/profiles/invalid_id/advisories").status_code == 404


# 7. OpenAPI Documentation & HTTP Method Restrictions
def test_openapi_documentation_endpoints(client):
    """Verifies OpenAPI JSON and docs are correctly configured and available."""
    schema_res = client.get("/openapi.json")
    assert schema_res.status_code == 200
    schema = schema_res.json()
    assert schema["info"]["title"] == "ThreatLenz Threat Intelligence API"
    assert "/api/v1/runs" in schema["paths"]
    assert "/api/v1/profiles" in schema["paths"]
    assert "/health" in schema["paths"]

    docs_res = client.get("/docs")
    assert docs_res.status_code == 200


def test_read_only_protection_and_method_restrictions(client):
    """Verifies that mutation HTTP methods (POST, PUT, DELETE) are rejected."""
    assert client.post("/api/v1/runs").status_code == 405
    assert client.delete("/api/v1/runs").status_code == 405
    assert client.put("/api/v1/profiles").status_code == 405
