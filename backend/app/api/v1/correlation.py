from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models.case import Case
from backend.app.models.finding import ForensicFinding
from backend.app.forensics.correlation import correlate_case_events
from backend.app.api.v1.schemas import (
    CorrelationRunRequest,
    CorrelationReportResponse,
    ForensicFindingBase,
    ForensicFindingResponse,
)

router = APIRouter(tags=["Multi-Evidence Correlation Engine"])


@router.post(
    "/cases/{case_id}/correlate",
    response_model=CorrelationReportResponse,
    summary="Execute multi-evidence correlation engine for a case",
)
def run_correlation(
    case_id: str,
    payload: Optional[CorrelationRunRequest] = None,
    db: Session = Depends(get_db),
):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' not found.",
        )

    options = payload or CorrelationRunRequest()

    try:
        report = correlate_case_events(
            case_id=case_id,
            db=db,
            time_window_seconds=options.time_window_seconds,
            min_cluster_size=options.min_cluster_size,
            generate_findings=options.generate_findings,
        )
        return report
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Correlation engine execution failed: {str(e)}",
        )


@router.get(
    "/cases/{case_id}/correlations",
    response_model=CorrelationReportResponse,
    summary="Query detected correlation clusters for a case",
)
def get_case_correlations(
    case_id: str,
    time_window_seconds: int = Query(60, ge=5, le=3600),
    min_cluster_size: int = Query(2, ge=2, le=50),
    db: Session = Depends(get_db),
):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' not found.",
        )

    return correlate_case_events(
        case_id=case_id,
        db=db,
        time_window_seconds=time_window_seconds,
        min_cluster_size=min_cluster_size,
        generate_findings=False,
    )


@router.get(
    "/cases/{case_id}/findings",
    response_model=List[ForensicFindingResponse],
    summary="List all forensic findings and anomalies for a case",
)
def get_case_findings(case_id: str, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' not found.",
        )

    findings = (
        db.query(ForensicFinding)
        .filter(ForensicFinding.case_id == case_id)
        .order_by(ForensicFinding.created_at.desc())
        .all()
    )
    return findings


@router.post(
    "/cases/{case_id}/findings",
    response_model=ForensicFindingResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a manual or confirmed forensic finding",
)
def create_case_finding(
    case_id: str,
    payload: ForensicFindingBase,
    db: Session = Depends(get_db),
):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' not found.",
        )

    finding = ForensicFinding(
        case_id=case_id,
        title=payload.title,
        finding_type=payload.finding_type,
        classification=payload.classification,
        severity=payload.severity,
        confidence=payload.confidence,
        reason=payload.reason,
        explanation=payload.explanation,
        supporting_artifacts=payload.supporting_artifacts,
        recommendation=payload.recommendation,
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


@router.delete(
    "/findings/{finding_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a forensic finding",
)
def delete_finding(finding_id: str, db: Session = Depends(get_db)):
    finding = db.query(ForensicFinding).filter(ForensicFinding.id == finding_id).first()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding with ID '{finding_id}' not found.",
        )
    db.delete(finding)
    db.commit()
    return None

