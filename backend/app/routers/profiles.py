"""Threat Profiles, MITRE Mappings, Risk Assessments, and Advisories Endpoints."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.dependencies import get_db
from backend.app.schemas import (
    AdvisoriesListResponse,
    AdvisoryResponse,
    MitreMappingResponse,
    PaginatedResponse,
    RiskAssessmentResponse,
    ThreatProfileSummary,
)
from src.database import (
    AdvisoryRecord,
    MitreMappingRecord,
    RiskAssessmentRecord,
    ThreatProfileRecord,
)

router = APIRouter(prefix="/api/v1/profiles", tags=["Threat Profiles"])


@router.get(
    "",
    response_model=PaginatedResponse[ThreatProfileSummary],
    summary="List Threat Profiles",
    description="Returns a paginated list of threat profile snapshots with optional category and run filters.",
)
def list_profiles(
    run_id: Optional[str] = Query(None, description="Filter profiles by pipeline execution run_id"),
    canonical_label: Optional[str] = Query(None, description="Filter by canonical category label (e.g., 'Bot', 'Benign')"),
    search: Optional[str] = Query(None, description="Case-insensitive partial search across canonical and raw category labels"),
    attack_status: Optional[str] = Query(None, description="Filter by attack status ('ATTACK', 'BENIGN', 'UNKNOWN')"),
    is_attack: Optional[bool] = Query(None, description="Filter by boolean attack indicator"),
    limit: int = Query(default=20, ge=1, le=100, description="Maximum profiles to return"),
    offset: int = Query(default=0, ge=0, description="Number of profiles to skip"),
    session: Session = Depends(get_db),
) -> PaginatedResponse[ThreatProfileSummary]:
    """Retrieves paginated threat profiles matching criteria."""
    # Base filter expressions
    conditions = []
    if run_id:
        conditions.append(ThreatProfileRecord.run_id == run_id)
    if canonical_label:
        conditions.append(ThreatProfileRecord.canonical_label == canonical_label)
    if search and search.strip():
        search_term = f"%{search.strip()}%"
        conditions.append(
            ThreatProfileRecord.canonical_label.ilike(search_term)
            | ThreatProfileRecord.raw_label.ilike(search_term)
        )
    if attack_status:
        conditions.append(ThreatProfileRecord.attack_status == attack_status)
    if is_attack is not None:
        conditions.append(ThreatProfileRecord.is_attack == is_attack)

    # Count matching items
    count_stmt = select(func.count(ThreatProfileRecord.snapshot_id))
    if conditions:
        count_stmt = count_stmt.where(*conditions)
    total_count = session.scalar(count_stmt) or 0

    # Query paginated rows
    query = (
        select(ThreatProfileRecord)
        .order_by(ThreatProfileRecord.flow_count.desc())
        .offset(offset)
        .limit(limit)
    )
    if conditions:
        query = query.where(*conditions)

    profiles = list(session.scalars(query).all())
    items = [ThreatProfileSummary.model_validate(p) for p in profiles]

    return PaginatedResponse(
        items=items,
        total=total_count,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{snapshot_id}",
    response_model=ThreatProfileSummary,
    summary="Get Threat Profile Detail",
    description="Retrieves a specific threat profile snapshot by its unique snapshot identifier.",
)
def get_profile_detail(
    snapshot_id: str,
    session: Session = Depends(get_db),
) -> ThreatProfileSummary:
    """Retrieves a single threat profile snapshot."""
    profile = session.get(ThreatProfileRecord, snapshot_id)
    if not profile:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat profile snapshot '{snapshot_id}' not found.",
        )
    return ThreatProfileSummary.model_validate(profile)


@router.get(
    "/{snapshot_id}/risk",
    response_model=RiskAssessmentResponse,
    summary="Get Profile TLRS Risk Assessment",
    description=(
        "Retrieves the Threat Level Risk Score assessment for a profile. "
        "Preserves unconfirmed status and null scores when target impact telemetry is missing."
    ),
)
def get_profile_risk_assessment(
    snapshot_id: str,
    session: Session = Depends(get_db),
) -> RiskAssessmentResponse:
    """Retrieves the TLRS assessment associated with a threat profile snapshot."""
    profile = session.get(ThreatProfileRecord, snapshot_id)
    if not profile:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat profile snapshot '{snapshot_id}' not found.",
        )

    risk = session.get(RiskAssessmentRecord, snapshot_id)
    if not risk:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No risk assessment found for profile '{snapshot_id}'.",
        )
    return RiskAssessmentResponse.model_validate(risk)


@router.get(
    "/{snapshot_id}/mitre",
    response_model=MitreMappingResponse,
    summary="Get Profile MITRE ATT&CK Mapping",
    description=(
        "Retrieves adversary technique mapping from MITRE ATT&CK Enterprise. "
        "Clearly delineates candidate and unverified statuses with is_confirmed=False."
    ),
)
def get_profile_mitre_mapping(
    snapshot_id: str,
    session: Session = Depends(get_db),
) -> MitreMappingResponse:
    """Retrieves the MITRE ATT&CK technique mapping for a threat profile snapshot."""
    profile = session.get(ThreatProfileRecord, snapshot_id)
    if not profile:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat profile snapshot '{snapshot_id}' not found.",
        )

    mitre = session.get(MitreMappingRecord, snapshot_id)
    if not mitre:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No MITRE mapping found for profile '{snapshot_id}'.",
        )
    return MitreMappingResponse.model_validate(mitre)


@router.get(
    "/{snapshot_id}/advisories",
    response_model=AdvisoriesListResponse,
    summary="Get Profile Defensive Advisories",
    description=(
        "Retrieves actionable recommendations linked to a profile snapshot. "
        "Enforces analyst_validation_required=True and confirms non-automated execution."
    ),
)
def get_profile_advisories(
    snapshot_id: str,
    session: Session = Depends(get_db),
) -> AdvisoriesListResponse:
    """Retrieves all defensive advisories generated for a threat profile snapshot."""
    profile = session.get(ThreatProfileRecord, snapshot_id)
    if not profile:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat profile snapshot '{snapshot_id}' not found.",
        )

    stmt = (
        select(AdvisoryRecord)
        .where(AdvisoryRecord.snapshot_id == snapshot_id)
        .order_by(AdvisoryRecord.id.asc())
    )
    advisories = list(session.scalars(stmt).all())
    items = [AdvisoryResponse.model_validate(a) for a in advisories]

    return AdvisoriesListResponse(
        snapshot_id=snapshot_id,
        total=len(items),
        items=items,
    )
