from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy.orm import Session

from backend.app.models.case import Case
from backend.app.models.evidence import Evidence
from backend.app.models.event import TimelineEvent


def sync_case_timeline_from_evidence(case_id: str, db: Session) -> int:
    """
    Ensure every evidence item associated with a case has its corresponding
    MACB filesystem events registered in the timeline.
    Returns the count of newly registered timeline events.
    """
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        return 0

    evidence_items = db.query(Evidence).filter(Evidence.case_id == case_id).all()
    created_count = 0

    for evi in evidence_items:
        # Check for existing modified event
        if evi.modified_time:
            existing_mod = (
                db.query(TimelineEvent)
                .filter(
                    TimelineEvent.evidence_id == evi.id,
                    TimelineEvent.event_type == "File Modified",
                )
                .first()
            )
            if not existing_mod:
                mod_event = TimelineEvent(
                    case_id=case_id,
                    evidence_id=evi.id,
                    timestamp=evi.modified_time,
                    timestamp_source="Filesystem MACB ($FILE_MODIFY)",
                    event_type="File Modified",
                    artifact_category=evi.file_type,
                    description=f"Observed filesystem modification timestamp for {evi.filename} ({evi.sha256[:8]}...)",
                    confidence=1.0,
                    classification="OBSERVED",
                    event_metadata={"sha256": evi.sha256, "file_size": evi.file_size_bytes},
                )
                db.add(mod_event)
                created_count += 1

        # Check for existing created event
        if evi.created_time:
            existing_create = (
                db.query(TimelineEvent)
                .filter(
                    TimelineEvent.evidence_id == evi.id,
                    TimelineEvent.event_type == "File Created",
                )
                .first()
            )
            if not existing_create:
                create_event = TimelineEvent(
                    case_id=case_id,
                    evidence_id=evi.id,
                    timestamp=evi.created_time,
                    timestamp_source="Filesystem MACB ($FILE_CREATE)",
                    event_type="File Created",
                    artifact_category=evi.file_type,
                    description=f"Observed filesystem creation timestamp for {evi.filename}",
                    confidence=1.0,
                    classification="OBSERVED",
                    event_metadata={"sha256": evi.sha256},
                )
                db.add(create_event)
                created_count += 1

        # Check for existing accessed event
        if evi.accessed_time:
            existing_access = (
                db.query(TimelineEvent)
                .filter(
                    TimelineEvent.evidence_id == evi.id,
                    TimelineEvent.event_type == "File Accessed",
                )
                .first()
            )
            if not existing_access:
                access_event = TimelineEvent(
                    case_id=case_id,
                    evidence_id=evi.id,
                    timestamp=evi.accessed_time,
                    timestamp_source="Filesystem MACB ($FILE_ACCESS)",
                    event_type="File Accessed",
                    artifact_category=evi.file_type,
                    description=f"Observed filesystem access timestamp for {evi.filename}",
                    confidence=1.0,
                    classification="OBSERVED",
                    event_metadata={"sha256": evi.sha256},
                )
                db.add(access_event)
                created_count += 1

    if created_count > 0:
        db.commit()

    return created_count

