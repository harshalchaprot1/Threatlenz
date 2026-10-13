"""System and Database Health Check Endpoints."""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.dependencies import get_db
from backend.app.schemas import DatabaseHealth, HealthResponse
from src.config import settings

router = APIRouter(tags=["Health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Service and Database Health Check",
    description="Validates API runtime availability and checks live database connectivity.",
)
def get_health(session: Session = Depends(get_db)):
    """Performs an active database ping to verify relational connectivity."""
    db_dialect = session.bind.dialect.name if session.bind else "unknown"
    try:
        session.execute(text("SELECT 1"))
        db_health = DatabaseHealth(status="connected", dialect=db_dialect)
        return HealthResponse(
            status="healthy",
            database=db_health,
            app_name=settings.app_name,
            version="1.0.0",
            timestamp=datetime.now(timezone.utc),
        )
    except Exception:
        # Never expose raw connection strings or stack traces
        db_health = DatabaseHealth(status="disconnected", dialect=db_dialect)
        payload = HealthResponse(
            status="degraded",
            database=db_health,
            app_name=settings.app_name,
            version="1.0.0",
            timestamp=datetime.now(timezone.utc),
        )
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=payload.model_dump(mode="json"),
        )
