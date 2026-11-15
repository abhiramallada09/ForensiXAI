from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import or_

from backend.app.core.database import get_db
from backend.app.models.case import Case
from backend.app.models.evidence import Evidence
from backend.app.models.event import TimelineEvent
from backend.app.forensics.timeline import sync_case_timeline_from_evidence
from backend.app.api.v1.schemas import (
    TimelineEventCreate,
    TimelineEventResponse,
    TimelineEventDetailResponse,
    VALID_EVENT_TYPES,
    VALID_CLASSIFICATIONS,
)

router = APIRouter(tags=["Chronological Timeline Engine"])


@router.get(
    "/timeline",
    response_model=List[TimelineEventDetailResponse],
    summary="Query unified chronological forensic timeline events",
)
def get_timeline(
    case_id: Optional[str] = Query(None, description="Filter by case ID"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    classification: Optional[str] = Query(None, description="Filter by classification (OBSERVED, RECONSTRUCTED, etc.)"),
    timestamp_source: Optional[str] = Query(None, description="Filter by timestamp source"),
    search: Optional[str] = Query(None, description="Search event description"),
    start_date: Optional[datetime] = Query(None, description="Start date window"),
    end_date: Optional[datetime] = Query(None, description="End date window"),
    min_confidence: Optional[float] = Query(None, ge=0.0, le=1.0, description="Minimum confidence threshold"),
    order: str = Query("desc", pattern="^(asc|desc)$", description="Chronological ordering: 'asc' or 'desc'"),
    db: Session = Depends(get_db),
):
    query = db.query(TimelineEvent)

    if case_id:
        query = query.filter(TimelineEvent.case_id == case_id)
    if event_type and event_type != "All":
        query = query.filter(TimelineEvent.event_type == event_type)
    if classification and classification != "All":
        query = query.filter(TimelineEvent.classification == classification)
    if timestamp_source and timestamp_source != "All":
        query = query.filter(TimelineEvent.timestamp_source.ilike(f"%{timestamp_source}%"))
    if start_date:
        query = query.filter(TimelineEvent.timestamp >= start_date)
    if end_date:
        query = query.filter(TimelineEvent.timestamp <= end_date)
    if min_confidence is not None:
        query = query.filter(TimelineEvent.confidence >= min_confidence)
    if search:
        search_fmt = f"%{search.strip()}%"
        query = query.filter(
            or_(
                TimelineEvent.description.ilike(search_fmt),
                TimelineEvent.event_type.ilike(search_fmt),
                TimelineEvent.timestamp_source.ilike(search_fmt),
            )
        )

    if order.lower() == "asc":
        query = query.order_by(TimelineEvent.timestamp.asc())
    else:
        query = query.order_by(TimelineEvent.timestamp.desc())

    events = query.all()

    result = []
    for ev in events:
        source_evi = ev.source_evidence
        result.append(
            TimelineEventDetailResponse(
                id=ev.id,
                case_id=ev.case_id,
                evidence_id=ev.evidence_id,
                timestamp=ev.timestamp,
                timestamp_end=ev.timestamp_end,
                timestamp_source=ev.timestamp_source,
                event_type=ev.event_type,
                artifact_category=ev.artifact_category,
                description=ev.description,
                confidence=ev.confidence,
                classification=ev.classification,
                event_metadata=ev.event_metadata,
                created_at=ev.created_at,
                case_number=ev.case.case_number if ev.case else None,
                source_evidence_filename=source_evi.filename if source_evi else None,
                source_evidence_sha256=source_evi.sha256 if source_evi else None,
                source_evidence_number=source_evi.evidence_number if source_evi else None,
            )
        )
    return result


@router.get(
    "/timeline/{case_id}",
    response_model=List[TimelineEventDetailResponse],
    summary="Get timeline for a specific case",
)
def get_case_timeline(
    case_id: str,
    order: str = Query("asc", pattern="^(asc|desc)$"),
    db: Session = Depends(get_db),
):
    return get_timeline(case_id=case_id, order=order, db=db)


@router.post(
    "/cases/{case_id}/timeline/rebuild",
    status_code=status.HTTP_200_OK,
    summary="Re-sync and extract MACB timeline events for all case evidence",
)
def rebuild_case_timeline(case_id: str, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    created_count = sync_case_timeline_from_evidence(case_id, db)
    total_events = db.query(TimelineEvent).filter(TimelineEvent.case_id == case_id).count()

    return {
        "success": True,
        "message": f"Timeline re-synchronized: {created_count} new events extracted from evidence.",
        "case_id": case_id,
        "newly_indexed_events": created_count,
        "total_case_events": total_events,
    }


@router.post(
    "/timeline/events",
    response_model=TimelineEventDetailResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a custom or investigator-correlated timeline event",
)
def create_timeline_event(event_in: TimelineEventCreate, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == event_in.case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Target case not found")

    if event_in.classification not in VALID_CLASSIFICATIONS:
        event_in.classification = "CORRELATED"

    if event_in.event_type not in VALID_EVENT_TYPES:
        event_in.event_type = "Other"

    new_event = TimelineEvent(
        case_id=event_in.case_id,
        evidence_id=event_in.evidence_id,
        timestamp=event_in.timestamp,
        timestamp_end=event_in.timestamp_end,
        timestamp_source=event_in.timestamp_source,
        event_type=event_in.event_type,
        artifact_category=event_in.artifact_category,
        description=event_in.description,
        confidence=event_in.confidence,
        classification=event_in.classification,
        event_metadata=event_in.event_metadata,
    )
    db.add(new_event)
    db.commit()
    db.refresh(new_event)

    source_evi = new_event.source_evidence

    return TimelineEventDetailResponse(
        id=new_event.id,
        case_id=new_event.case_id,
        evidence_id=new_event.evidence_id,
        timestamp=new_event.timestamp,
        timestamp_end=new_event.timestamp_end,
        timestamp_source=new_event.timestamp_source,
        event_type=new_event.event_type,
        artifact_category=new_event.artifact_category,
        description=new_event.description,
        confidence=new_event.confidence,
        classification=new_event.classification,
        event_metadata=new_event.event_metadata,
        created_at=new_event.created_at,
        case_number=case.case_number,
        source_evidence_filename=source_evi.filename if source_evi else None,
        source_evidence_sha256=source_evi.sha256 if source_evi else None,
        source_evidence_number=source_evi.evidence_number if source_evi else None,
    )


@router.get(
    "/timeline/events/{event_id}",
    response_model=TimelineEventDetailResponse,
    summary="Get single timeline event with evidence drill-down",
)
def get_timeline_event(event_id: str, db: Session = Depends(get_db)):
    ev = db.query(TimelineEvent).filter(TimelineEvent.id == event_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Timeline event not found")

    source_evi = ev.source_evidence
    return TimelineEventDetailResponse(
        id=ev.id,
        case_id=ev.case_id,
        evidence_id=ev.evidence_id,
        timestamp=ev.timestamp,
        timestamp_end=ev.timestamp_end,
        timestamp_source=ev.timestamp_source,
        event_type=ev.event_type,
        artifact_category=ev.artifact_category,
        description=ev.description,
        confidence=ev.confidence,
        classification=ev.classification,
        event_metadata=ev.event_metadata,
        created_at=ev.created_at,
        case_number=ev.case.case_number if ev.case else None,
        source_evidence_filename=source_evi.filename if source_evi else None,
        source_evidence_sha256=source_evi.sha256 if source_evi else None,
        source_evidence_number=source_evi.evidence_number if source_evi else None,
    )


@router.delete(
    "/timeline/events/{event_id}",
    status_code=status.HTTP_200_OK,
    summary="Delete a timeline event",
)
def delete_timeline_event(event_id: str, db: Session = Depends(get_db)):
    ev = db.query(TimelineEvent).filter(TimelineEvent.id == event_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Timeline event not found")

    db.delete(ev)
    db.commit()

    return {"success": True, "message": "Timeline event removed successfully.", "event_id": event_id}
