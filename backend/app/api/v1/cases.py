from typing import List, Optional
import time
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import or_
from backend.app.core.database import get_db
from backend.app.models.case import Case
from backend.app.models.evidence import Evidence
from backend.app.models.event import TimelineEvent
from backend.app.models.finding import ForensicFinding
from backend.app.api.v1.schemas import (
    CaseCreate,
    CaseUpdate,
    CaseResponse,
    CaseDetailResponse,
    CaseExportResponse,
    VALID_CASE_STATUSES,
)

router = APIRouter(prefix="/cases", tags=["Case Management"])


@router.get("", response_model=List[CaseDetailResponse], summary="List all forensic investigation cases")
def list_cases(
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status"),
    search: Optional[str] = Query(None, description="Search by name, case number, or investigator"),
    db: Session = Depends(get_db),
):
    """Fetch cases ordered by newest first with optional search and status filter."""
    query = db.query(Case)

    if status_filter:
        query = query.filter(Case.status == status_filter)

    if search:
        search_fmt = f"%{search.strip()}%"
        query = query.filter(
            or_(
                Case.name.ilike(search_fmt),
                Case.case_number.ilike(search_fmt),
                Case.investigator.ilike(search_fmt),
                Case.description.ilike(search_fmt),
            )
        )

    cases = query.order_by(Case.created_at.desc()).all()

    result = []
    for c in cases:
        result.append(
            CaseDetailResponse(
                id=c.id,
                case_number=c.case_number,
                name=c.name,
                description=c.description,
                investigator=c.investigator,
                status=c.status,
                created_at=c.created_at,
                updated_at=c.updated_at,
                evidence_count=len(c.evidence_items) if c.evidence_items else 0,
                timeline_events_count=len(c.timeline_events) if c.timeline_events else 0,
                findings_count=len(c.findings) if c.findings else 0,
            )
        )
    return result


@router.post("", response_model=CaseDetailResponse, status_code=status.HTTP_201_CREATED, summary="Create a new investigation case")
def create_case(case_in: CaseCreate, db: Session = Depends(get_db)):
    """Create a new forensic case with an auto-generated or custom case number."""
    if case_in.status not in VALID_CASE_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status '{case_in.status}'. Valid statuses: {VALID_CASE_STATUSES}",
        )

    import uuid
    import re
    if case_in.case_number:
        case_num = re.sub(r"[^A-Za-z0-9_\-]", "", case_in.case_number.strip())
        if not case_num:
            case_num = f"CAS-{int(time.time())}-{uuid.uuid4().hex[:4].upper()}"
    else:
        case_num = f"CAS-{int(time.time())}-{uuid.uuid4().hex[:4].upper()}"
    
    # Check if case_number already exists
    existing = db.query(Case).filter(Case.case_number == case_num).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"Case number '{case_num}' already exists.")

    new_case = Case(
        case_number=case_num,
        name=case_in.name,
        description=case_in.description,
        investigator=case_in.investigator,
        status=case_in.status,
    )
    db.add(new_case)
    db.commit()
    db.refresh(new_case)

    return CaseDetailResponse(
        id=new_case.id,
        case_number=new_case.case_number,
        name=new_case.name,
        description=new_case.description,
        investigator=new_case.investigator,
        status=new_case.status,
        created_at=new_case.created_at,
        updated_at=new_case.updated_at,
        evidence_count=0,
        timeline_events_count=0,
        findings_count=0,
    )


@router.get("/{case_id}", response_model=CaseDetailResponse, summary="Get case details by ID")
def get_case(case_id: str, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    return CaseDetailResponse(
        id=case.id,
        case_number=case.case_number,
        name=case.name,
        description=case.description,
        investigator=case.investigator,
        status=case.status,
        created_at=case.created_at,
        updated_at=case.updated_at,
        evidence_count=len(case.evidence_items) if case.evidence_items else 0,
        timeline_events_count=len(case.timeline_events) if case.timeline_events else 0,
        findings_count=len(case.findings) if case.findings else 0,
    )


@router.patch("/{case_id}", response_model=CaseDetailResponse, summary="Update / rename an existing case")
def update_case(case_id: str, case_in: CaseUpdate, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    if case_in.name is not None:
        case.name = case_in.name.strip()
    if case_in.description is not None:
        case.description = case_in.description.strip()
    if case_in.investigator is not None:
        case.investigator = case_in.investigator.strip()
    if case_in.status is not None:
        if case_in.status not in VALID_CASE_STATUSES:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid status '{case_in.status}'. Valid statuses: {VALID_CASE_STATUSES}",
            )
        case.status = case_in.status

    case.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(case)

    return CaseDetailResponse(
        id=case.id,
        case_number=case.case_number,
        name=case.name,
        description=case.description,
        investigator=case.investigator,
        status=case.status,
        created_at=case.created_at,
        updated_at=case.updated_at,
        evidence_count=len(case.evidence_items) if case.evidence_items else 0,
        timeline_events_count=len(case.timeline_events) if case.timeline_events else 0,
        findings_count=len(case.findings) if case.findings else 0,
    )


@router.post("/{case_id}/archive", response_model=CaseDetailResponse, summary="Archive an investigation case")
def archive_case(case_id: str, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    case.status = "Archived"
    case.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(case)

    return CaseDetailResponse(
        id=case.id,
        case_number=case.case_number,
        name=case.name,
        description=case.description,
        investigator=case.investigator,
        status=case.status,
        created_at=case.created_at,
        updated_at=case.updated_at,
        evidence_count=len(case.evidence_items) if case.evidence_items else 0,
        timeline_events_count=len(case.timeline_events) if case.timeline_events else 0,
        findings_count=len(case.findings) if case.findings else 0,
    )


@router.delete("/{case_id}", status_code=status.HTTP_200_OK, summary="Delete an investigation case")
def delete_case(case_id: str, db: Session = Depends(get_db)):
    """
    Delete a case record and database associations.
    Note: Raw files in data/uploads/ are preserved to protect evidentiary chain of custody.
    """
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    deleted_case_number = case.case_number
    db.delete(case)
    db.commit()

    return {
        "success": True,
        "message": f"Case {deleted_case_number} successfully deleted from active database.",
        "case_id": case_id,
    }


@router.get("/{case_id}/export", response_model=CaseExportResponse, summary="Export case metadata dossier as JSON")
def export_case(case_id: str, db: Session = Depends(get_db)):
    """Export complete case dossier including metadata, evidence register, timeline, and findings."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    evidence_data = [
        {
            "id": e.id,
            "filename": e.filename,
            "sha256": e.sha256,
            "file_type": e.file_type,
            "file_size_bytes": e.file_size_bytes,
            "classification": e.classification,
            "status": e.status,
            "created_time": e.created_time.isoformat() if e.created_time else None,
            "modified_time": e.modified_time.isoformat() if e.modified_time else None,
            "accessed_time": e.accessed_time.isoformat() if e.accessed_time else None,
        }
        for e in case.evidence_items
    ]

    events_data = [
        {
            "id": ev.id,
            "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
            "timestamp_source": ev.timestamp_source,
            "event_type": ev.event_type,
            "description": ev.description,
            "confidence": ev.confidence,
            "classification": ev.classification,
        }
        for ev in case.timeline_events
    ]

    findings_data = [
        {
            "id": f.id,
            "title": f.title,
            "finding_type": f.finding_type,
            "classification": f.classification,
            "severity": f.severity,
            "confidence": f.confidence,
            "reason": f.reason,
            "recommendation": f.recommendation,
        }
        for f in case.findings
    ]

    return CaseExportResponse(
        case=CaseResponse.model_validate(case),
        evidence=evidence_data,
        timeline_events=events_data,
        findings=findings_data,
        exported_at=datetime.now(timezone.utc),
        format_version="1.0",
    )
