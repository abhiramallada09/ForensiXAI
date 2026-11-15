from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models.case import Case
from backend.app.models.cloud import CloudEvidenceRecord, CloudCorrelationRecord
from backend.app.forensics.cloud_engine import (
    parse_and_ingest_cloud_records,
    correlate_cloud_with_local_evidence,
)
from backend.app.api.v1.schemas import (
    CloudEvidenceItemResponse,
    CloudCorrelationItemResponse,
    CloudIngestRequest,
    CloudIngestResponse,
    CloudSummaryResponse,
    CloudCorrelationsSummaryResponse,
)
router = APIRouter(tags=["Cloud Evidence (SaaS/IaaS)"])


@router.post(
    "/cases/{case_id}/cloud/ingest",
    response_model=CloudIngestResponse,
    summary="Ingest AWS CloudTrail or Azure Activity Log JSON audit events",
)
def ingest_cloud_logs(case_id: str, request: CloudIngestRequest, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' not found.",
        )

    records = parse_and_ingest_cloud_records(
        case_id=case_id,
        payload=request.payload,
        db=db,
        default_provider=request.provider,
    )

    anti_count = sum(1 for r in records if r.is_anti_forensic)
    prov = records[0].provider if records else (request.provider or "AWS")

    return CloudIngestResponse(
        case_id=case_id,
        records_ingested=len(records),
        anti_forensic_evasion_detected=anti_count,
        provider=prov,
        records=[CloudEvidenceItemResponse.model_validate(r) for r in records],
    )


@router.get(
    "/cases/{case_id}/cloud",
    response_model=CloudSummaryResponse,
    summary="List ingested cloud evidence records with optional filtering",
)
def get_cloud_evidence(
    case_id: str,
    provider: Optional[str] = Query(None, description="Filter by provider: AWS, Azure, GCP"),
    is_anti_forensic: Optional[bool] = Query(None, description="Filter anti-forensic events only"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    db: Session = Depends(get_db),
):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' not found.",
        )

    query = db.query(CloudEvidenceRecord).filter(CloudEvidenceRecord.case_id == case_id)

    if provider and provider != "All":
        query = query.filter(CloudEvidenceRecord.provider == provider)
    if is_anti_forensic is not None:
        query = query.filter(CloudEvidenceRecord.is_anti_forensic == is_anti_forensic)
    if severity and severity != "All":
        query = query.filter(CloudEvidenceRecord.severity == severity)

    records = query.order_by(CloudEvidenceRecord.event_time.desc()).all()

    providers = list({r.provider for r in records})
    crit_count = sum(1 for r in records if r.severity == "Critical")
    high_count = sum(1 for r in records if r.severity == "High")
    anti_count = sum(1 for r in records if r.is_anti_forensic)

    return CloudSummaryResponse(
        case_id=case_id,
        total_records=len(records),
        anti_forensic_count=anti_count,
        providers=providers,
        critical_count=crit_count,
        high_count=high_count,
        records=[CloudEvidenceItemResponse.model_validate(r) for r in records],
    )


@router.post(
    "/cases/{case_id}/cloud/correlate",
    response_model=CloudCorrelationsSummaryResponse,
    summary="Cross-correlate cloud audit events with local Volatility memory processes and network telemetry",
)
def run_cloud_correlation(
    case_id: str,
    time_window_seconds: float = Query(300.0, description="Correlation window threshold in seconds"),
    db: Session = Depends(get_db),
):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' not found.",
        )

    correlations = correlate_cloud_with_local_evidence(
        case_id=case_id,
        db=db,
        time_window_seconds=time_window_seconds,
    )

    avg_conf = float(sum(c.confidence for c in correlations) / len(correlations)) if correlations else 0.90

    return CloudCorrelationsSummaryResponse(
        case_id=case_id,
        total_correlations=len(correlations),
        average_confidence=round(avg_conf, 4),
        correlations=[CloudCorrelationItemResponse.model_validate(c) for c in correlations],
    )


@router.get(
    "/cases/{case_id}/cloud/correlations",
    response_model=CloudCorrelationsSummaryResponse,
    summary="Retrieve all cross-correlation records established between cloud and endpoint artifacts",
)
def get_cloud_correlations(case_id: str, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' not found.",
        )

    correlations = db.query(CloudCorrelationRecord).filter(
        CloudCorrelationRecord.case_id == case_id
    ).order_by(CloudCorrelationRecord.cloud_timestamp.desc()).all()

    avg_conf = float(sum(c.confidence for c in correlations) / len(correlations)) if correlations else 0.90

    return CloudCorrelationsSummaryResponse(
        case_id=case_id,
        total_correlations=len(correlations),
        average_confidence=round(avg_conf, 4),
        correlations=[CloudCorrelationItemResponse.model_validate(c) for c in correlations],
    )


@router.get(
    "/cases/{case_id}/cloud/{record_id}",
    response_model=CloudEvidenceItemResponse,
    summary="Get single cloud evidence record details including full raw payload",
)
def get_single_cloud_record(case_id: str, record_id: str, db: Session = Depends(get_db)):
    record = db.query(CloudEvidenceRecord).filter(
        CloudEvidenceRecord.case_id == case_id,
        CloudEvidenceRecord.id == record_id,
    ).first()

    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Cloud record '{record_id}' not found.",
        )

    return CloudEvidenceItemResponse.model_validate(record)


@router.delete(
    "/cases/{case_id}/cloud/{record_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a cloud evidence record",
)
def delete_cloud_record(case_id: str, record_id: str, db: Session = Depends(get_db)):
    record = db.query(CloudEvidenceRecord).filter(
        CloudEvidenceRecord.case_id == case_id,
        CloudEvidenceRecord.id == record_id,
    ).first()

    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Cloud record '{record_id}' not found.",
        )

    db.delete(record)
    db.commit()
    return None
