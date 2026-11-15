import os
import uuid
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    UploadFile,
    File,
    Form,
    Query,
    status,
)
from sqlalchemy.orm import Session
from sqlalchemy import or_

from backend.app.core.config import settings
from backend.app.core.database import get_db
from backend.app.core.security import sanitize_filename, calculate_sha256
from backend.app.forensics.metadata import extract_file_metadata, format_file_size
from backend.app.models.case import Case
from backend.app.models.evidence import Evidence
from backend.app.models.event import TimelineEvent
from backend.app.api.v1.schemas import (
    EvidenceResponse,
    EvidenceDetailResponse,
    EvidenceVerificationResponse,
    VALID_EVIDENCE_CATEGORIES,
)

router = APIRouter(tags=["Evidence Management & Integrity"])


@router.post(
    "/cases/{case_id}/evidence",
    response_model=EvidenceDetailResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload and ingest a forensic evidence file into a case",
)
async def upload_evidence_to_case(
    case_id: str,
    file: UploadFile = File(..., description="Target forensic evidence file"),
    file_type: str = Form("File", description="Evidence category (File, Memory Image, System Log, etc.)"),
    notes: Optional[str] = Form(None, description="Investigator acquisition notes"),
    db: Session = Depends(get_db),
):
    """
    Ingest a forensic evidence file:
    1. Validates case and filename
    2. Streams to read-only upload storage (never executed)
    3. Calculates cryptographic SHA-256 and MD5 hashes
    4. Extracts MACB filesystem timestamps and forensic metadata
    5. Tags strictly as OBSERVED EVIDENCE
    6. Automatically registers initial MACB timeline events
    """
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    if file_type not in VALID_EVIDENCE_CATEGORIES:
        file_type = "File"

    safe_filename = sanitize_filename(file.filename or "unknown_evidence")
    safe_case_num = sanitize_filename(case.case_number)
    upload_dir = settings.resolved_upload_dir().resolve()

    # Generate unique stored filename to prevent collisions while preserving original name
    unique_prefix = uuid.uuid4().hex[:8]
    stored_name = f"{safe_case_num}_{unique_prefix}_{safe_filename}"
    target_path = (upload_dir / stored_name).resolve()

    # Path traversal protection check
    if not str(target_path).startswith(str(upload_dir)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid filename or case identifier path structure.",
        )

    sha256_hasher = hashlib.sha256()
    md5_hasher = hashlib.md5()
    total_bytes = 0
    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024

    # Stream write to disk without executing
    try:
        with open(target_path, "wb") as f:
            while chunk := await file.read(65536):
                total_bytes += len(chunk)
                if total_bytes > max_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail=f"File exceeds maximum upload size of {settings.MAX_UPLOAD_SIZE_MB} MB",
                    )
                sha256_hasher.update(chunk)
                md5_hasher.update(chunk)
                f.write(chunk)
    except HTTPException:
        if target_path.exists():
            target_path.unlink()
        raise
    except Exception as e:
        if target_path.exists():
            target_path.unlink()
        raise HTTPException(status_code=500, detail=f"Failed to stream evidence file: {str(e)}")

    computed_sha256 = sha256_hasher.hexdigest()
    computed_md5 = md5_hasher.hexdigest()

    # Extract MACB timestamps and filesystem attributes
    metadata, created_dt, modified_dt, accessed_dt = extract_file_metadata(target_path)
    metadata["original_upload_filename"] = file.filename
    metadata["ingestion_method"] = "Direct Evidence Stream"
    metadata["investigator"] = case.investigator

    # Generate Evidence Number
    evi_count = db.query(Evidence).filter(Evidence.case_id == case_id).count()
    evidence_number = f"EVI-{case.case_number}-{evi_count + 1:03d}"

    # Build Evidence Record with strict OBSERVED classification
    new_evidence = Evidence(
        case_id=case_id,
        evidence_number=evidence_number,
        filename=safe_filename,
        stored_path=str(target_path),
        file_type=file_type,
        mime_type=metadata.get("mime_type", "application/octet-stream"),
        file_size_bytes=total_bytes,
        sha256=computed_sha256,
        md5=computed_md5,
        created_time=created_dt,
        modified_time=modified_dt,
        accessed_time=accessed_dt,
        classification="OBSERVED",
        status="Observed Evidence",
        metadata_json=metadata,
        notes=notes,
    )
    db.add(new_evidence)
    db.flush()  # Flush to obtain new_evidence.id

    # Automatically register initial MACB timeline events
    if modified_dt:
        mod_event = TimelineEvent(
            case_id=case_id,
            evidence_id=new_evidence.id,
            timestamp=modified_dt,
            timestamp_source="Filesystem MACB ($FILE_MODIFY)",
            event_type="File Modified",
            artifact_category=file_type,
            description=f"Observed filesystem modification timestamp for {safe_filename} ({computed_sha256[:8]}...)",
            confidence=1.0,
            classification="OBSERVED",
            event_metadata={"sha256": computed_sha256, "file_size": total_bytes},
        )
        db.add(mod_event)

    if created_dt:
        create_event = TimelineEvent(
            case_id=case_id,
            evidence_id=new_evidence.id,
            timestamp=created_dt,
            timestamp_source="Filesystem MACB ($FILE_CREATE)",
            event_type="File Created",
            artifact_category=file_type,
            description=f"Observed filesystem creation timestamp for {safe_filename}",
            confidence=1.0,
            classification="OBSERVED",
            event_metadata={"sha256": computed_sha256},
        )
        db.add(create_event)

    # Advance case status if currently New
    if case.status == "New":
        case.status = "Evidence Collected"

    db.commit()
    db.refresh(new_evidence)

    return EvidenceDetailResponse(
        id=new_evidence.id,
        case_id=new_evidence.case_id,
        evidence_number=new_evidence.evidence_number,
        filename=new_evidence.filename,
        file_type=new_evidence.file_type,
        mime_type=new_evidence.mime_type,
        file_size_bytes=new_evidence.file_size_bytes,
        readable_size=format_file_size(new_evidence.file_size_bytes),
        sha256=new_evidence.sha256,
        md5=new_evidence.md5,
        created_time=new_evidence.created_time,
        modified_time=new_evidence.modified_time,
        accessed_time=new_evidence.accessed_time,
        classification=new_evidence.classification,
        status=new_evidence.status,
        notes=new_evidence.notes,
        created_at=new_evidence.created_at,
        case_number=case.case_number,
        case_name=case.name,
        metadata_json=new_evidence.metadata_json,
    )


@router.get(
    "/evidence",
    response_model=List[EvidenceDetailResponse],
    summary="List all evidence items across cases",
)
def list_evidence(
    case_id: Optional[str] = Query(None, description="Filter by case ID"),
    file_type: Optional[str] = Query(None, description="Filter by category"),
    search: Optional[str] = Query(None, description="Search by filename or hash"),
    db: Session = Depends(get_db),
):
    query = db.query(Evidence)

    if case_id:
        query = query.filter(Evidence.case_id == case_id)
    if file_type and file_type != "All":
        query = query.filter(Evidence.file_type == file_type)
    if search:
        search_fmt = f"%{search.strip()}%"
        query = query.filter(
            or_(
                Evidence.filename.ilike(search_fmt),
                Evidence.sha256.ilike(search_fmt),
                Evidence.evidence_number.ilike(search_fmt),
            )
        )

    evidence_items = query.order_by(Evidence.created_at.desc()).all()

    result = []
    for e in evidence_items:
        result.append(
            EvidenceDetailResponse(
                id=e.id,
                case_id=e.case_id,
                evidence_number=e.evidence_number,
                filename=e.filename,
                file_type=e.file_type,
                mime_type=e.mime_type,
                file_size_bytes=e.file_size_bytes,
                readable_size=format_file_size(e.file_size_bytes),
                sha256=e.sha256,
                md5=e.md5,
                created_time=e.created_time,
                modified_time=e.modified_time,
                accessed_time=e.accessed_time,
                classification=e.classification,
                status=e.status,
                notes=e.notes,
                created_at=e.created_at,
                case_number=e.case.case_number if e.case else None,
                case_name=e.case.name if e.case else None,
                metadata_json=e.metadata_json,
            )
        )
    return result


@router.get(
    "/cases/{case_id}/evidence",
    response_model=List[EvidenceDetailResponse],
    summary="List evidence items for a specific case",
)
def list_case_evidence(case_id: str, db: Session = Depends(get_db)):
    return list_evidence(case_id=case_id, file_type=None, search=None, db=db)


@router.get(
    "/evidence/{evidence_id}",
    response_model=EvidenceDetailResponse,
    summary="Get comprehensive evidence details by ID",
)
def get_evidence_detail(evidence_id: str, db: Session = Depends(get_db)):
    e = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    if not e:
        raise HTTPException(status_code=404, detail="Evidence not found")

    return EvidenceDetailResponse(
        id=e.id,
        case_id=e.case_id,
        evidence_number=e.evidence_number,
        filename=e.filename,
        file_type=e.file_type,
        mime_type=e.mime_type,
        file_size_bytes=e.file_size_bytes,
        readable_size=format_file_size(e.file_size_bytes),
        sha256=e.sha256,
        md5=e.md5,
        created_time=e.created_time,
        modified_time=e.modified_time,
        accessed_time=e.accessed_time,
        classification=e.classification,
        status=e.status,
        notes=e.notes,
        created_at=e.created_at,
        case_number=e.case.case_number if e.case else None,
        case_name=e.case.name if e.case else None,
        metadata_json=e.metadata_json,
    )


@router.post(
    "/evidence/{evidence_id}/verify-hash",
    response_model=EvidenceVerificationResponse,
    summary="Verify cryptographic hash of evidence on disk against recorded SHA-256",
)
def verify_evidence_hash(evidence_id: str, db: Session = Depends(get_db)):
    e = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    if not e:
        raise HTTPException(status_code=404, detail="Evidence not found")

    file_path = Path(e.stored_path)
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Original evidence file is missing from storage")

    current_hash = calculate_sha256(file_path)
    is_match = (current_hash.lower() == e.sha256.lower())

    status_str = "MATCH" if is_match else "TAMPERED"
    notes_str = (
        "Cryptographic integrity confirmed: On-disk file SHA-256 matches evidence register exactly."
        if is_match
        else "CRITICAL ALERT: On-disk file hash does NOT match registered hash! Potential tampering or corruption detected."
    )

    return EvidenceVerificationResponse(
        evidence_id=e.id,
        stored_sha256=e.sha256,
        computed_sha256=current_hash,
        status=status_str,
        verified_at=datetime.now(timezone.utc),
        notes=notes_str,
    )


@router.delete(
    "/evidence/{evidence_id}",
    status_code=status.HTTP_200_OK,
    summary="Remove an evidence item from case database",
)
def delete_evidence(evidence_id: str, db: Session = Depends(get_db)):
    """
    Remove evidence record from active investigation database.
    Note: Physical file in data/uploads/ is maintained for chain of custody.
    """
    e = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    if not e:
        raise HTTPException(status_code=404, detail="Evidence not found")

    evi_name = e.filename
    db.delete(e)
    db.commit()

    return {
        "success": True,
        "message": f"Evidence {evi_name} removed from active case register.",
        "evidence_id": evidence_id,
    }
