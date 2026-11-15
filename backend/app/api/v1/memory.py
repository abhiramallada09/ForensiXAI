from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models.case import Case
from backend.app.models.evidence import Evidence
from backend.app.models.memory import MemoryAnalysisRecord
from backend.app.forensics.volatility_engine import run_volatility_analysis
from backend.app.api.v1.schemas import (
    MemoryAnalysisRequest,
    MemoryAnalysisResponse,
    ProcessItem,
    NetworkItem,
    InjectedModuleItem,
)

router = APIRouter(tags=["Volatility 3 Memory Forensics"])


@router.post(
    "/cases/{case_id}/memory/analyze",
    response_model=MemoryAnalysisResponse,
    summary="Execute Volatility 3 memory analysis on an uploaded memory dump",
)
def analyze_memory_dump(
    case_id: str,
    payload: MemoryAnalysisRequest,
    db: Session = Depends(get_db),
):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' not found.",
        )

    evidence = (
        db.query(Evidence)
        .filter(Evidence.id == payload.evidence_id, Evidence.case_id == case_id)
        .first()
    )
    if not evidence:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence with ID '{payload.evidence_id}' not found in case '{case_id}'.",
        )

    try:
        response = run_volatility_analysis(
            case_id=case_id,
            evidence_id=payload.evidence_id,
            plugins=payload.plugins,
            db=db,
            sync_timeline=payload.sync_timeline,
        )
        return response
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Volatility 3 execution failed: {str(e)}",
        )


@router.get(
    "/cases/{case_id}/memory/latest",
    response_model=Optional[MemoryAnalysisResponse],
    summary="Retrieve the most recent memory analysis results for a case",
)
def get_latest_memory_analysis(
    case_id: str,
    evidence_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' not found.",
        )

    query = db.query(MemoryAnalysisRecord).filter(MemoryAnalysisRecord.case_id == case_id)
    if evidence_id:
        query = query.filter(MemoryAnalysisRecord.evidence_id == evidence_id)

    record = query.order_by(MemoryAnalysisRecord.created_at.desc()).first()
    if not record:
        return None

    evidence = db.query(Evidence).filter(Evidence.id == record.evidence_id).first()

    return MemoryAnalysisResponse(
        id=record.id,
        case_id=record.case_id,
        evidence_id=record.evidence_id,
        evidence_filename=evidence.filename if evidence else "memory.raw",
        plugins_run=record.plugins_run or [],
        processes=[ProcessItem(**p) for p in (record.processes or [])],
        network_connections=[NetworkItem(**n) for n in (record.network_connections or [])],
        injected_regions=[InjectedModuleItem(**i) for i in (record.injected_regions or [])],
        handles=record.handles or [],
        cmdlines=record.cmdlines or [],
        raw_output=record.raw_output,
        timeline_events_created=0,
        findings_created=0,
        created_at=record.created_at,
    )


@router.get(
    "/cases/{case_id}/memory/processes",
    response_model=List[ProcessItem],
    summary="List active processes extracted from volatile memory",
)
def get_memory_processes(case_id: str, db: Session = Depends(get_db)):
    record = (
        db.query(MemoryAnalysisRecord)
        .filter(MemoryAnalysisRecord.case_id == case_id)
        .order_by(MemoryAnalysisRecord.created_at.desc())
        .first()
    )
    if not record or not record.processes:
        return []
    return [ProcessItem(**p) for p in record.processes]


@router.get(
    "/cases/{case_id}/memory/network",
    response_model=List[NetworkItem],
    summary="List network socket endpoints extracted from volatile memory",
)
def get_memory_network(case_id: str, db: Session = Depends(get_db)):
    record = (
        db.query(MemoryAnalysisRecord)
        .filter(MemoryAnalysisRecord.case_id == case_id)
        .order_by(MemoryAnalysisRecord.created_at.desc())
        .first()
    )
    if not record or not record.network_connections:
        return []
    return [NetworkItem(**n) for n in record.network_connections]


@router.get(
    "/cases/{case_id}/memory/injections",
    response_model=List[InjectedModuleItem],
    summary="List injected code regions and shellcode detected by malfind",
)
def get_memory_injections(case_id: str, db: Session = Depends(get_db)):
    record = (
        db.query(MemoryAnalysisRecord)
        .filter(MemoryAnalysisRecord.case_id == case_id)
        .order_by(MemoryAnalysisRecord.created_at.desc())
        .first()
    )
    if not record or not record.injected_regions:
        return []
    return [InjectedModuleItem(**i) for i in record.injected_regions]

