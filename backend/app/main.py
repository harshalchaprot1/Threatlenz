"""ThreatLenz Phase 7: FastAPI Backend Application.

Main entry point providing REST endpoints for pipeline runs, threat profiles,
MITRE ATT&CK technique mappings, TLRS risk scores, and advisory recommendations.
"""

from contextlib import asynccontextmanager
import sys
from pathlib import Path
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Ensure repository root is on sys.path for direct imports
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.routers import health, profiles, runs
from src.config import settings
from src.utils import get_logger

logger = get_logger("ThreatLenz.API")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle management context for FastAPI backend."""
    logger.info("Initializing ThreatLenz FastAPI Backend [Env: %s]", settings.app_env)
    yield
    logger.info("Shutting down ThreatLenz FastAPI Backend.")


def create_app() -> FastAPI:
    """Application factory for ThreatLenz FastAPI service."""
    application = FastAPI(
        title="ThreatLenz Threat Intelligence API",
        description=(
            "Production-ready REST API for network flow threat intelligence, "
            "MITRE ATT&CK Enterprise technique mappings, Threat Level Risk Scores (TLRS), "
            "and defensive advisory recommendations."
        ),
        version="1.0.0",
        openapi_tags=[
            {"name": "Health", "description": "Liveness and database connectivity verification."},
            {"name": "Pipeline Runs", "description": "Historical pipeline execution runs and provenance."},
            {"name": "Threat Profiles", "description": "Categorized flow profiles, risk assessments, MITRE mappings, and advisories."},
        ],
        lifespan=lifespan,
    )

    # 1. CORS Middleware Configuration
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["GET", "OPTIONS"],
        allow_headers=["*"],
    )

    # 2. Global Safe Exception Handler (Prevents stack trace / credential leaks)
    @application.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error("Unhandled API error processing %s: %s", request.url.path, exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "An internal server error occurred. Please contact the system administrator."},
        )

    # 3. Register Modular Routers
    application.include_router(health.router)
    application.include_router(runs.router)
    application.include_router(profiles.router)

    # 4. Root Service Metadata Endpoint
    @application.get(
        "/",
        tags=["Health"],
        summary="Service Metadata",
        description="Returns basic service information and documentation link.",
    )
    def root():
        return {
            "app_name": settings.app_name,
            "version": "1.0.0",
            "environment": settings.app_env,
            "docs_url": "/docs",
            "openapi_url": "/openapi.json",
        }

    return application


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backend.app.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=False,
    )
