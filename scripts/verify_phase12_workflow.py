import os
import sys
import uuid
from datetime import datetime, timezone, timedelta

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.app.core.database import SessionLocal, Base, engine
from backend.app.models.case import Case
from backend.app.models.event import TimelineEvent
from backend.app.models.finding import ForensicFinding
from backend.app.models.cloud import CloudEvidenceRecord, CloudCorrelationRecord
from backend.app.forensics.cloud_engine import (
    parse_and_ingest_cloud_records,
    correlate_cloud_with_local_evidence,
)
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def run_phase12_verification():
    print("=" * 80)
    print("ForensiX AI - Phase 12: Cloud Evidence (SaaS/IaaS) Integration Verification")
    print("Official Academic Title:")
    print("Memory Forensics for Volatile Data Analysis via Deep Learning-based")
    print("Deleted File and Timestamp Reconstruction, Applied to Cloud Evidence")
    print("=" * 80)

    db = SessionLocal()
    try:
        # Step 1: Create Case
        c_num = f"CASE-CLOUD-{uuid.uuid4().hex[:6].upper()}"
        print(f"\n[Step 1] Creating Case: {c_num}...")
        test_case = Case(
            case_number=c_num,
            name="Operation Nimbus Shield - CloudTrail & Azure Activity Forensic Cross-Correlation",
            investigator="A. Abhiram",
            description="Forensic recovery and cross-correlation of cloud anti-forensics with volatile endpoint memory",
            status="Analyzing",
        )
        db.add(test_case)
        db.commit()

        # Step 2: Ingest AWS CloudTrail Logs
        print("\n[Step 2] Ingesting AWS CloudTrail Logs with Anti-Forensics...")
        base_t = datetime(2026, 11, 14, 15, 0, 0, tzinfo=timezone.utc)

        aws_trail_payload = {
            "Records": [
                {
                    "eventTime": base_t.isoformat(),
                    "eventName": "ConsoleLogin",
                    "eventSource": "signin.amazonaws.com",
                    "userIdentity": {
                        "type": "IAMUser",
                        "arn": "arn:aws:iam::123456789012:user/compromised_dev",
                    },
                    "sourceIPAddress": "198.51.100.55",
                    "userAgent": "AWS-CLI/2.15.0 Python/3.11.2",
                    "awsRegion": "us-east-1",
                },
                {
                    "eventTime": (base_t + timedelta(seconds=24)).isoformat(),
                    "eventName": "StopLogging",
                    "eventSource": "cloudtrail.amazonaws.com",
                    "userIdentity": {
                        "type": "IAMUser",
                        "arn": "arn:aws:iam::123456789012:user/compromised_dev",
                    },
                    "sourceIPAddress": "198.51.100.55",
                    "awsRegion": "us-east-1",
                },
                {
                    "eventTime": (base_t + timedelta(seconds=70)).isoformat(),
                    "eventName": "DeleteBucket",
                    "eventSource": "s3.amazonaws.com",
                    "userIdentity": {
                        "type": "IAMUser",
                        "arn": "arn:aws:iam::123456789012:user/compromised_dev",
                    },
                    "sourceIPAddress": "198.51.100.55",
                    "awsRegion": "us-east-1",
                },
            ]
        }

        aws_records = parse_and_ingest_cloud_records(test_case.id, aws_trail_payload, db, default_provider="AWS")
        print(f"  -> Ingested {len(aws_records)} AWS CloudTrail records.")
        for r in aws_records:
            print(f"     * [{r.provider}] {r.event_name} (Severity: {r.severity}, Anti-Forensic: {r.is_anti_forensic})")

        # Step 3: Ingest Azure Activity Logs
        print("\n[Step 3] Ingesting Azure Activity Logs with Diagnostic Evasion...")
        azure_payload = {
            "value": [
                {
                    "eventTimestamp": (base_t + timedelta(minutes=4)).isoformat(),
                    "operationName": {"value": "Microsoft.Insights/diagnosticSettings/delete"},
                    "resourceProviderName": {"value": "Microsoft.Insights"},
                    "caller": "bad_actor@cloudorg.onmicrosoft.com",
                    "callerIpAddress": "203.0.113.99",
                    "status": {"value": "Succeeded"},
                }
            ]
        }
        azure_records = parse_and_ingest_cloud_records(test_case.id, azure_payload, db, default_provider="Azure")
        print(f"  -> Ingested {len(azure_records)} Azure Activity record(s).")

        # Step 4: Verify Timeline Injection & Forensic Findings
        print("\n[Step 4] Verifying Automatic Timeline Injection & Forensic Findings...")
        tl_events = db.query(TimelineEvent).filter(
            TimelineEvent.case_id == test_case.id,
            TimelineEvent.artifact_category == "Cloud Audit",
        ).all()
        print(f"  -> Found {len(tl_events)} Cloud Audit events injected into case timeline.")
        assert len(tl_events) == 4

        cloud_findings = db.query(ForensicFinding).filter(
            ForensicFinding.case_id == test_case.id,
            ForensicFinding.finding_type == "Cloud Anti-Forensics",
        ).all()
        print(f"  -> Synthesized {len(cloud_findings)} Forensic Finding(s) for cloud anti-forensics:")
        for f in cloud_findings:
            print(f"     * [{f.severity}] {f.title}: {f.reason}")
        assert len(cloud_findings) >= 3

        # Step 5: Stage Endpoint Local Timeline Action for Cross-Correlation
        print("\n[Step 5] Staging Local Endpoint Evidence for Cross-Correlation...")
        local_cli_event = TimelineEvent(
            case_id=test_case.id,
            timestamp=base_t + timedelta(seconds=20),  # 4 seconds before StopLogging!
            timestamp_source="Command Line History",
            event_type="Command Executed",
            artifact_category="Command",
            description='cmd.exe /c "aws cloudtrail stop-logging --name production-trail"',
            confidence=0.98,
            classification="SUSPICIOUS",
        )
        db.add(local_cli_event)
        db.commit()

        # Step 6: Execute Cloud-to-Endpoint Cross-Correlation Engine
        print("\n[Step 6] Running Cloud Cross-Correlation Engine...")
        correlations = correlate_cloud_with_local_evidence(test_case.id, db, time_window_seconds=120.0)
        print(f"  -> Established {len(correlations)} Cloud Correlation(s):")
        for c in correlations:
            print(f"     * [{c.correlation_type}] Delta: {c.time_delta_seconds}s, Conf: {c.confidence*100:.0f}%")
            print(f"       Local: {c.local_artifact_desc}")
            print(f"       Rationale: {c.rationale}")
        assert len(correlations) >= 1

        # Step 7: Test REST APIs via TestClient
        print("\n[Step 7] Testing Cloud REST API Endpoints...")

        # 7a: GET /cloud
        res_list = client.get(f"/api/v1/cases/{test_case.id}/cloud")
        assert res_list.status_code == 200
        summary = res_list.json()
        print(f"  -> GET /cloud: Total={summary['total_records']}, Anti-Forensic={summary['anti_forensic_count']}, Providers={summary['providers']}")
        assert summary["total_records"] == 4
        assert summary["anti_forensic_count"] >= 3

        # 7b: GET /cloud/correlations
        res_corr = client.get(f"/api/v1/cases/{test_case.id}/cloud/correlations")
        assert res_corr.status_code == 200
        corr_summary = res_corr.json()
        print(f"  -> GET /cloud/correlations: Total Correlations={corr_summary['total_correlations']}")
        assert corr_summary["total_correlations"] >= 1

        # 7c: GET /cloud/{record_id}
        first_rec_id = summary["records"][0]["id"]
        res_single = client.get(f"/api/v1/cases/{test_case.id}/cloud/{first_rec_id}")
        assert res_single.status_code == 200
        assert res_single.json()["id"] == first_rec_id
        print(f"  -> GET single cloud record verified: {res_single.json()['event_name']}")

        # 7d: DELETE /cloud/{record_id}
        res_del = client.delete(f"/api/v1/cases/{test_case.id}/cloud/{first_rec_id}")
        assert res_del.status_code == 204
        print(f"  -> DELETE record {first_rec_id} succeeded with Status 204.")

        res_check = client.get(f"/api/v1/cases/{test_case.id}/cloud")
        assert res_check.json()["total_records"] == 3

        print("\n" + "=" * 80)
        print(">>> SUCCESS: Phase 12 Cloud Evidence Integration is 100% verified!")
        print("=" * 80)

    finally:
        db.close()


if __name__ == "__main__":
    run_phase12_verification()

