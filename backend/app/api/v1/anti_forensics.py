from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models.case import Case
from backend.app.models.anti_forensic import AntiForensicIndicatorRecord
from backend.app.forensics.anti_forensics import detect_anti_forensic_anomalies
from backend.app.api.v1.schemas import (
    AntiForensicIndicatorResponse,
    AntiForensicsSummaryResponse,
)

router = APIRouter(tags=["Anti-Forensic Anomaly Detection"])


@router.post(
    "/cases/{case_id}/anti-forensics/analyze",
    response_model=AntiForensicsSummaryResponse,
    summary="Execute comprehensive multi-heuristic anti-forensic anomaly scan",
)
def run_anti_forensic_scan(case_id: str, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' not found.",
        )

    records = detect_anti_forensic_anomalies(case_id, db)
    crit_count = sum(1 for r in records if r.severity == "Critical")
    high_count = sum(1 for r in records if r.severity == "High")
    avg_conf = float(sum(r.confidence for r in records) / len(records)) if records else 0.88

    return AntiForensicsSummaryResponse(
        case_id=case_id,
        total_indicators=len(records),
        critical_severity_count=crit_count,
        high_severity_count=high_count,
        average_confidence=round(avg_conf, 4),
        indicators=[AntiForensicIndicatorResponse.model_validate(r) for r in records],
    )


@router.get(
    "/cases/{case_id}/anti-forensics",
    response_model=AntiForensicsSummaryResponse,
    summary="Retrieve all detected anti-forensic anomalies and manipulation indicators for a case",
)
def get_case_anti_forensics(case_id: str, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' not found.",
        )

    records = db.query(AntiForensicIndicatorRecord).filter(
        AntiForensicIndicatorRecord.case_id == case_id
    ).order_by(AntiForensicIndicatorRecord.confidence.desc()).all()

    if not records:
        # Run auto-scan on demand
        records = detect_anti_forensic_anomalies(case_id, db)

    crit_count = sum(1 for r in records if r.severity == "Critical")
    high_count = sum(1 for r in records if r.severity == "High")
    avg_conf = float(sum(r.confidence for r in records) / len(records)) if records else 0.88

    return AntiForensicsSummaryResponse(
        case_id=case_id,
        total_indicators=len(records),
        critical_severity_count=crit_count,
        high_severity_count=high_count,
        average_confidence=round(avg_conf, 4),
        indicators=[AntiForensicIndicatorResponse.model_validate(r) for r in records],
    )


@router.get(
    "/cases/{case_id}/anti-forensics/{indicator_id}",
    response_model=AntiForensicIndicatorResponse,
    summary="Get single anti-forensic indicator details",
)
def get_single_anti_forensic_indicator(case_id: str, indicator_id: str, db: Session = Depends(get_db)):
    record = db.query(AntiForensicIndicatorRecord).filter(
        AntiForensicIndicatorRecord.case_id == case_id,
        AntiForensicIndicatorRecord.id == indicator_id,
    ).first()

    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Anti-forensic indicator '{indicator_id}' not found.",
        )

    return AntiForensicIndicatorResponse.model_validate(record)


@router.delete(
    "/cases/{case_id}/anti-forensics/{indicator_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Dismiss or delete an anti-forensic indicator",
)
def delete_anti_forensic_indicator(case_id: str, indicator_id: str, db: Session = Depends(get_db)):
    record = db.query(AntiForensicIndicatorRecord).filter(
        AntiForensicIndicatorRecord.case_id == case_id,
        AntiForensicIndicatorRecord.id == indicator_id,
    ).first()

    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Anti-forensic indicator '{indicator_id}' not found.",
        )

    db.delete(record)
    db.commit()
    return None

