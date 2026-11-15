import os
import io
import re
import hashlib
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Response
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models.case import Case
from backend.app.models.evidence import Evidence
from backend.app.models.memory import MemoryAnalysisRecord
from backend.app.models.deleted_file import DeletedFileRecord
from backend.app.models.timestamp_reconstruction import TimestampReconstructionRecord
from backend.app.models.anti_forensic import AntiForensicIndicatorRecord
from backend.app.models.cloud import CloudEvidenceRecord, CloudCorrelationRecord
from backend.app.models.finding import ForensicFinding
from backend.app.reports.pdf_generator import generate_case_pdf_report

router = APIRouter(tags=["Forensic Examination Reports"])


@router.get(
    "/cases/{case_id}/reports/pdf",
    summary="Generate and stream forensic investigation PDF report",
    response_description="Binary PDF stream",
)
def download_case_pdf_report(case_id: str, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' not found.",
        )

    try:
        pdf_bytes = generate_case_pdf_report(case_id, db)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to compile forensic PDF report: {str(e)}",
        )

    safe_num = re.sub(r"[^A-Za-z0-9_\-]", "_", case.case_number)
    filename = f"ForensiX_Report_{safe_num}.pdf"

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Report-SHA256": hashlib.sha256(pdf_bytes).hexdigest(),
        },
    )


@router.get(
    "/cases/{case_id}/reports/summary",
    summary="Get report preview summary and evidentiary integrity checklist",
)
def get_case_report_summary(case_id: str, db: Session = Depends(get_db)) -> Dict[str, Any]:
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' not found.",
        )

    evidence_count = db.query(Evidence).filter(Evidence.case_id == case_id).count()
    memory_count = db.query(MemoryAnalysisRecord).filter(MemoryAnalysisRecord.case_id == case_id).count()
    deleted_count = db.query(DeletedFileRecord).filter(DeletedFileRecord.case_id == case_id).count()
    timestamp_count = db.query(TimestampReconstructionRecord).filter(TimestampReconstructionRecord.case_id == case_id).count()
    anti_forensic_count = db.query(AntiForensicIndicatorRecord).filter(AntiForensicIndicatorRecord.case_id == case_id).count()
    cloud_count = db.query(CloudEvidenceRecord).filter(CloudEvidenceRecord.case_id == case_id).count()
    cloud_corr_count = db.query(CloudCorrelationRecord).filter(CloudCorrelationRecord.case_id == case_id).count()
    findings_count = db.query(ForensicFinding).filter(ForensicFinding.case_id == case_id).count()

    return {
        "case_id": case_id,
        "case_number": case.case_number,
        "name": case.name,
        "investigator": case.investigator,
        "status": case.status,
        "evidence_count": evidence_count,
        "memory_analyses_count": memory_count,
        "deleted_files_count": deleted_count,
        "timestamp_windows_count": timestamp_count,
        "anti_forensic_indicators_count": anti_forensic_count,
        "cloud_records_count": cloud_count,
        "cloud_correlations_count": cloud_corr_count,
        "findings_count": findings_count,
        "evidentiary_standards": ["FRE 901", "FRE 902", "ISO/IEC 27037", "NIST SP 800-86"],
        "report_format": "PDF / ReportLab 5.1",
    }


@router.post(
    "/cases/{case_id}/reports/generate",
    summary="Generate and permanently store official forensic report artifact on disk",
)
def generate_and_save_report(case_id: str, db: Session = Depends(get_db)) -> Dict[str, Any]:
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' not found.",
        )

    pdf_bytes = generate_case_pdf_report(case_id, db)
    sha256_hash = hashlib.sha256(pdf_bytes).hexdigest()

    # Store in reports directory
    reports_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "data", "reports"))
    os.makedirs(reports_dir, exist_ok=True)

    safe_num = re.sub(r"[^A-Za-z0-9_\-]", "_", case.case_number)
    filename = f"ForensiX_Report_{safe_num}.pdf"
    file_path = os.path.abspath(os.path.join(reports_dir, filename))

    # Path traversal protection
    if not file_path.startswith(reports_dir):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid case number path structure.",
        )

    with open(file_path, "wb") as f:
        f.write(pdf_bytes)

    return {
        "status": "generated",
        "case_id": case_id,
        "filename": filename,
        "file_path": file_path,
        "file_size_bytes": len(pdf_bytes),
        "sha256": sha256_hash,
    }

