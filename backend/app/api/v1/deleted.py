from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models.case import Case
from backend.app.models.deleted_file import DeletedFileRecord
from backend.app.forensics.deleted_analysis import analyze_deleted_file_traces
from backend.app.api.v1.schemas import (
    DeletedFileResponse,
    DeletedAnalysisSummaryResponse,
)

router = APIRouter(tags=["Deleted File Trace Analysis"])


@router.post(
    "/cases/{case_id}/deleted-files/analyze",
    response_model=DeletedAnalysisSummaryResponse,
    summary="Execute deleted-file remnant analysis across memory handles, MFT residue, and event logs",
)
def run_deleted_analysis(case_id: str, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' not found.",
        )

    records = analyze_deleted_file_traces(case_id, db)
    mem_count = sum(1 for r in records if any("memory" in s.lower() or "handle" in s.lower() for s in r.corroborating_sources))
    log_count = sum(1 for r in records if any("log" in s.lower() or "audit" in s.lower() or "timeline" in s.lower() for s in r.corroborating_sources))
    avg_conf = float(sum(r.confidence for r in records) / len(records)) if records else 0.84

    return DeletedAnalysisSummaryResponse(
        case_id=case_id,
        total_deleted_artifacts=len(records),
        memory_corroborated_count=mem_count,
        log_corroborated_count=log_count,
        average_confidence=round(avg_conf, 4),
        artifacts=[DeletedFileResponse.model_validate(r) for r in records],
    )


@router.get(
    "/cases/{case_id}/deleted-files",
    response_model=DeletedAnalysisSummaryResponse,
    summary="Retrieve all probable deleted file remnants and carved artifacts for a case",
)
def get_deleted_files_for_case(case_id: str, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' not found.",
        )

    records = db.query(DeletedFileRecord).filter(DeletedFileRecord.case_id == case_id).order_by(DeletedFileRecord.confidence.desc()).all()
    if not records:
        # Run auto-analysis if not yet triggered
        records = analyze_deleted_file_traces(case_id, db)

    mem_count = sum(1 for r in records if any("memory" in s.lower() or "handle" in s.lower() for s in r.corroborating_sources))
    log_count = sum(1 for r in records if any("log" in s.lower() or "audit" in s.lower() or "timeline" in s.lower() for s in r.corroborating_sources))
    avg_conf = float(sum(r.confidence for r in records) / len(records)) if records else 0.84

    return DeletedAnalysisSummaryResponse(
        case_id=case_id,
        total_deleted_artifacts=len(records),
        memory_corroborated_count=mem_count,
        log_corroborated_count=log_count,
        average_confidence=round(avg_conf, 4),
        artifacts=[DeletedFileResponse.model_validate(r) for r in records],
    )


@router.get(
    "/cases/{case_id}/deleted-files/{record_id}",
    response_model=DeletedFileResponse,
    summary="Get single deleted file artifact record details",
)
def get_single_deleted_file(case_id: str, record_id: str, db: Session = Depends(get_db)):
    record = db.query(DeletedFileRecord).filter(
        DeletedFileRecord.case_id == case_id,
        DeletedFileRecord.id == record_id,
    ).first()

    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Deleted file record '{record_id}' not found.",
        )

    return DeletedFileResponse.model_validate(record)


@router.delete(
    "/cases/{case_id}/deleted-files/{record_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a reconstructed deleted file record",
)
def delete_deleted_file_record(case_id: str, record_id: str, db: Session = Depends(get_db)):
    record = db.query(DeletedFileRecord).filter(
        DeletedFileRecord.case_id == case_id,
        DeletedFileRecord.id == record_id,
    ).first()

    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Deleted file record '{record_id}' not found.",
        )

    db.delete(record)
    db.commit()
    return None

