"""Pipeline Runs Endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.dependencies import get_db
from backend.app.schemas import (
    PaginatedResponse,
    PipelineRunDetail,
    PipelineRunSummary,
)
from src.database import PipelineRun

router = APIRouter(prefix="/api/v1/runs", tags=["Pipeline Runs"])


@router.get(
    "",
    response_model=PaginatedResponse[PipelineRunSummary],
    summary="List Pipeline Execution Runs",
    description="Returns a paginated list of historical ThreatLenz intelligence pipeline executions.",
)
def list_runs(
    limit: int = Query(default=20, ge=1, le=100, description="Maximum runs to return"),
    offset: int = Query(default=0, ge=0, description="Number of runs to skip"),
    session: Session = Depends(get_db),
) -> PaginatedResponse[PipelineRunSummary]:
    """Retrieves paginated pipeline execution records ordered by timestamp descending."""
    # Count total runs
    total_count = session.scalar(select(func.count(PipelineRun.run_id))) or 0

    # Retrieve paginated items
    stmt = (
        select(PipelineRun)
        .order_by(PipelineRun.run_timestamp.desc())
        .offset(offset)
        .limit(limit)
    )
    runs = list(session.scalars(stmt).all())

    items = [PipelineRunSummary.model_validate(r) for r in runs]
    return PaginatedResponse(
        items=items,
        total=total_count,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{run_id}",
    response_model=PipelineRunDetail,
    summary="Get Pipeline Run Detail",
    description="Retrieves comprehensive provenance, manifest hashes, and governance details for a specific run.",
)
def get_run_detail(
    run_id: str,
    session: Session = Depends(get_db),
) -> PipelineRunDetail:
    """Retrieves detailed metadata for a specific pipeline execution run."""
    run = session.get(PipelineRun, run_id)
    if not run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Pipeline run '{run_id}' not found.",
        )
    return PipelineRunDetail.model_validate(run)
