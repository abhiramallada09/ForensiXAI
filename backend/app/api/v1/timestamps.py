from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models.case import Case
from backend.app.models.timestamp_reconstruction import TimestampReconstructionRecord
from backend.app.forensics.timestamp_reconstruction import reconstruct_timestamp_windows
from backend.app.api.v1.schemas import (
    TimestampReconstructionResponse,
    TimestampAnalysisSummaryResponse,
)

router = APIRouter(tags=["Timestamp Reconstruction & Event Windows"])


@router.post(
    "/cases/{case_id}/timestamps/reconstruct",
    response_model=TimestampAnalysisSummaryResponse,
    summary="Execute multi-source timestamp reconstruction, consistency diagnostics, and probable window calculation",
)
def run_timestamp_reconstruction(
    case_id: str,
    window_threshold_seconds: float = Query(120.0, ge=10.0, le=1800.0),
    db: Session = Depends(get_db),
):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' not found.",
        )

    records = reconstruct_timestamp_windows(case_id, db, window_threshold_seconds=window_threshold_seconds)
    consistent_cnt = sum(1 for r in records if r.consistency_status == "CONSISTENT")
    inconsistent_cnt = sum(1 for r in records if r.consistency_status in {"INCONSISTENT", "MISSING"})
    avg_conf = float(sum(r.confidence for r in records) / len(records)) if records else 0.85

    return TimestampAnalysisSummaryResponse(
        case_id=case_id,
        total_windows_evaluated=len(records),
        consistent_count=consistent_cnt,
        inconsistent_count=inconsistent_cnt,
        average_confidence=round(avg_conf, 4),
        reconstructed_windows=[TimestampReconstructionResponse.model_validate(r) for r in records],
    )


@router.get(
    "/cases/{case_id}/timestamps",
    response_model=TimestampAnalysisSummaryResponse,
    summary="Retrieve all reconstructed timestamp windows and consistency evaluations for a case",
)
def get_case_timestamp_windows(case_id: str, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' not found.",
        )

    records = db.query(TimestampReconstructionRecord).filter(
        TimestampReconstructionRecord.case_id == case_id
    ).order_by(TimestampReconstructionRecord.probable_window_start.asc()).all()

    if not records:
        # Run auto-reconstruction on demand
        records = reconstruct_timestamp_windows(case_id, db)

    consistent_cnt = sum(1 for r in records if r.consistency_status == "CONSISTENT")
    inconsistent_cnt = sum(1 for r in records if r.consistency_status in {"INCONSISTENT", "MISSING"})
    avg_conf = float(sum(r.confidence for r in records) / len(records)) if records else 0.85

    return TimestampAnalysisSummaryResponse(
        case_id=case_id,
        total_windows_evaluated=len(records),
        consistent_count=consistent_cnt,
        inconsistent_count=inconsistent_cnt,
        average_confidence=round(avg_conf, 4),
        reconstructed_windows=[TimestampReconstructionResponse.model_validate(r) for r in records],
    )


@router.get(
    "/cases/{case_id}/timestamps/{record_id}",
    response_model=TimestampReconstructionResponse,
    summary="Get single reconstructed timestamp window details",
)
def get_single_timestamp_window(case_id: str, record_id: str, db: Session = Depends(get_db)):
    record = db.query(TimestampReconstructionRecord).filter(
        TimestampReconstructionRecord.case_id == case_id,
        TimestampReconstructionRecord.id == record_id,
    ).first()

    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Timestamp reconstruction record '{record_id}' not found.",
        )

    return TimestampReconstructionResponse.model_validate(record)


@router.delete(
    "/cases/{case_id}/timestamps/{record_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a reconstructed timestamp window record",
)
def delete_timestamp_window(case_id: str, record_id: str, db: Session = Depends(get_db)):
    record = db.query(TimestampReconstructionRecord).filter(
        TimestampReconstructionRecord.case_id == case_id,
        TimestampReconstructionRecord.id == record_id,
    ).first()

    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Timestamp reconstruction record '{record_id}' not found.",
        )

    db.delete(record)
    db.commit()
    return None

