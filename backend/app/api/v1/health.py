from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from backend.app.core.config import settings
from backend.app.core.database import get_db
from backend.app.models.case import Case
from backend.app.models.evidence import Evidence
from backend.app.api.v1.schemas import SystemStatusResponse

router = APIRouter(tags=["System & Health"])


@router.get("/health", summary="Basic health check")
def health_check():
    """Returns simple status indicating backend service is alive."""
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@router.get("/status", response_model=SystemStatusResponse, summary="Comprehensive system status and statistics")
def system_status(db: Session = Depends(get_db)):
    """Returns system status, active database connection check, and statistics for the dashboard."""
    db_connected = False
    cases_count = 0
    evidence_count = 0
    
    try:
        db.execute(text("SELECT 1"))
        db_connected = True
        cases_count = db.query(Case).count()
        evidence_count = db.query(Evidence).count()
    except Exception:
        db_connected = False

    return SystemStatusResponse(
        app_name=settings.APP_NAME,
        app_version=settings.APP_VERSION,
        academic_title=settings.ACADEMIC_TITLE,
        environment=settings.APP_ENV,
        status="ONLINE" if db_connected else "DEGRADED",
        database_connected=db_connected,
        active_cases_count=cases_count,
        total_evidence_count=evidence_count,
        system_time=datetime.now(timezone.utc)
    )
