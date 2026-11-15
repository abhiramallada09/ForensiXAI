import uuid
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.main import app
from backend.app.core.database import SessionLocal, Base, engine
from backend.app.models.case import Case
from backend.app.models.event import TimelineEvent
from backend.app.models.finding import ForensicFinding
from backend.app.models.cloud import CloudEvidenceRecord, CloudCorrelationRecord
from backend.app.forensics.cloud_engine import (
    parse_and_ingest_cloud_records,
    correlate_cloud_with_local_evidence,
)

client = TestClient(app)


@pytest.fixture(scope="module")
def setup_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    yield db
    db.close()


def test_cloud_ingest_and_anti_forensics(setup_db: Session):
    db = setup_db
    c_num = f"CASE-CLOUD-{uuid.uuid4().hex[:6]}"
    test_case = Case(
        case_number=c_num,
        name="CloudTrail Breach & Anti-Forensics Analysis",
        investigator="A. Abhiram",
        status="Analyzing",
    )
    db.add(test_case)
    db.commit()

    base_time = datetime(2026, 11, 14, 12, 0, 0, tzinfo=timezone.utc)

    # AWS CloudTrail Sample with Anti-Forensics
    aws_payload = {
        "Records": [
            {
                "eventTime": (base_time).isoformat(),
                "eventName": "ConsoleLogin",
                "eventSource": "signin.amazonaws.com",
                "userIdentity": {
                    "type": "IAMUser",
                    "arn": "arn:aws:iam::123456789012:user/admin_attacker",
                },
                "sourceIPAddress": "198.51.100.77",
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "awsRegion": "us-east-1",
            },
            {
                "eventTime": (base_time + timedelta(seconds=45)).isoformat(),
                "eventName": "StopLogging",
                "eventSource": "cloudtrail.amazonaws.com",
                "userIdentity": {
                    "type": "IAMUser",
                    "arn": "arn:aws:iam::123456789012:user/admin_attacker",
                },
                "sourceIPAddress": "198.51.100.77",
                "awsRegion": "us-east-1",
            },
            {
                "eventTime": (base_time + timedelta(minutes=2)).isoformat(),
                "eventName": "DeleteBucket",
                "eventSource": "s3.amazonaws.com",
                "userIdentity": {
                    "type": "IAMUser",
                    "arn": "arn:aws:iam::123456789012:user/admin_attacker",
                },
                "sourceIPAddress": "198.51.100.77",
                "awsRegion": "us-east-1",
            },
        ]
    }

    # Azure Activity Log Sample
    azure_payload = {
        "value": [
            {
                "eventTimestamp": (base_time + timedelta(minutes=5)).isoformat(),
                "operationName": {"value": "Microsoft.Insights/diagnosticSettings/delete"},
                "resourceProviderName": {"value": "Microsoft.Insights"},
                "caller": "attacker@compromised.onmicrosoft.com",
                "callerIpAddress": "203.0.113.88",
                "status": {"value": "Succeeded"},
            }
        ]
    }

    # Ingest AWS
    aws_recs = parse_and_ingest_cloud_records(test_case.id, aws_payload, db, default_provider="AWS")
    assert len(aws_recs) == 3
    stop_logging_rec = next(r for r in aws_recs if r.event_name == "StopLogging")
    assert stop_logging_rec.is_anti_forensic is True
    assert stop_logging_rec.severity == "Critical"
    assert stop_logging_rec.classification == "SUSPICIOUS"

    # Ingest Azure
    azure_recs = parse_and_ingest_cloud_records(test_case.id, azure_payload, db, default_provider="Azure")
    assert len(azure_recs) == 1
    assert azure_recs[0].provider == "Azure"
    assert azure_recs[0].is_anti_forensic is True

    # Check TimelineEvents were added
    tl_events = db.query(TimelineEvent).filter(
        TimelineEvent.case_id == test_case.id,
        TimelineEvent.artifact_category == "Cloud Audit",
    ).all()
    assert len(tl_events) == 4

    # Check ForensicFindings were synthesized
    findings = db.query(ForensicFinding).filter(
        ForensicFinding.case_id == test_case.id,
        ForensicFinding.finding_type == "Cloud Anti-Forensics",
    ).all()
    assert len(findings) >= 3  # StopLogging, DeleteBucket, DiagnosticSettings/delete


def test_cloud_cross_correlation(setup_db: Session):
    db = setup_db
    c_num = f"CASE-CLOUD-{uuid.uuid4().hex[:6]}"
    test_case = Case(
        case_number=c_num,
        name="Endpoint-to-Cloud Cross-Correlation Case",
        investigator="A. Abhiram",
        status="Analyzing",
    )
    db.add(test_case)
    db.commit()

    base_time = datetime(2026, 11, 14, 13, 0, 0, tzinfo=timezone.utc)

    # Ingest CloudTrail event
    aws_event = {
        "eventTime": base_time.isoformat(),
        "eventName": "DeleteObjects",
        "eventSource": "s3.amazonaws.com",
        "userIdentity": {"arn": "arn:aws:iam::123:user/infiltrator"},
        "sourceIPAddress": "198.51.100.99",
    }
    parse_and_ingest_cloud_records(test_case.id, [aws_event], db, default_provider="AWS")

    # Stage local timeline event of CLI execution within 20 seconds
    local_ev = TimelineEvent(
        case_id=test_case.id,
        timestamp=base_time - timedelta(seconds=18),
        timestamp_source="PowerShell Console History",
        event_type="Command Executed",
        artifact_category="Command",
        description='powershell.exe -c "aws s3 rm s3://audit-vault/ --recursive"',
        confidence=0.95,
        classification="SUSPICIOUS",
    )
    db.add(local_ev)
    db.commit()

    # Correlate
    correlations = correlate_cloud_with_local_evidence(test_case.id, db, time_window_seconds=120.0)
    assert len(correlations) >= 1
    corr = correlations[0]
    assert corr.correlation_type == "Process-API Attribution"
    assert corr.time_delta_seconds == 18.0
    assert "powershell" in corr.rationale.lower() or "aws" in corr.rationale.lower()
    assert corr.confidence >= 0.85


def test_cloud_rest_api(setup_db: Session):
    db = setup_db
    c_num = f"CASE-CLOUD-{uuid.uuid4().hex[:6]}"
    test_case = Case(
        case_number=c_num,
        name="Cloud API Test Case",
        investigator="A. Abhiram",
        status="Analyzing",
    )
    db.add(test_case)
    db.commit()

    # Test POST /ingest
    res_ingest = client.post(
        f"/api/v1/cases/{test_case.id}/cloud/ingest",
        json={
            "payload": {
                "Records": [
                    {
                        "eventTime": "2026-11-14T14:00:00Z",
                        "eventName": "StopLogging",
                        "eventSource": "cloudtrail.amazonaws.com",
                        "userIdentity": {"arn": "arn:aws:iam::111:user/operator"},
                        "sourceIPAddress": "198.51.100.12",
                    }
                ]
            },
            "provider": "AWS",
        },
    )
    assert res_ingest.status_code == 200
    data = res_ingest.json()
    assert data["records_ingested"] == 1
    assert data["anti_forensic_evasion_detected"] == 1
    rec_id = data["records"][0]["id"]

    # Test GET /cloud
    res_list = client.get(f"/api/v1/cases/{test_case.id}/cloud")
    assert res_list.status_code == 200
    summary = res_list.json()
    assert summary["total_records"] == 1
    assert summary["anti_forensic_count"] == 1

    # Test POST /correlate
    res_corr = client.post(f"/api/v1/cases/{test_case.id}/cloud/correlate?time_window_seconds=300")
    assert res_corr.status_code == 200
    corr_data = res_corr.json()
    assert "total_correlations" in corr_data

    # Test GET /correlations
    res_get_corr = client.get(f"/api/v1/cases/{test_case.id}/cloud/correlations")
    assert res_get_corr.status_code == 200

    # Test GET /cloud/{record_id}
    res_single = client.get(f"/api/v1/cases/{test_case.id}/cloud/{rec_id}")
    assert res_single.status_code == 200
    assert res_single.json()["id"] == rec_id

    # Test DELETE /cloud/{record_id}
    res_del = client.delete(f"/api/v1/cases/{test_case.id}/cloud/{rec_id}")
    assert res_del.status_code == 204

    # Confirm deletion
    res_after = client.get(f"/api/v1/cases/{test_case.id}/cloud")
    assert res_after.json()["total_records"] == 0

