import os
import sys
import uuid
import hashlib
from datetime import datetime, timezone, timedelta

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.app.core.database import SessionLocal, Base, engine
from backend.app.models.case import Case
from backend.app.models.evidence import Evidence
from backend.app.models.memory import MemoryAnalysisRecord
from backend.app.models.event import TimelineEvent
from backend.app.models.deleted_file import DeletedFileRecord
from backend.app.models.timestamp_reconstruction import TimestampReconstructionRecord
from backend.app.models.anti_forensic import AntiForensicIndicatorRecord
from backend.app.models.cloud import CloudEvidenceRecord, CloudCorrelationRecord
from backend.app.models.finding import ForensicFinding
from backend.app.reports.pdf_generator import generate_case_pdf_report
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def run_phase13_verification():
    print("=" * 80)
    print("ForensiX AI - Phase 13: Court-Admissible Forensic PDF Reports Verification")
    print("Official Academic Title:")
    print("Memory Forensics for Volatile Data Analysis via Deep Learning-based")
    print("Deleted File and Timestamp Reconstruction, Applied to Cloud Evidence")
    print("=" * 80)

    db = SessionLocal()
    try:
        # Step 1: Create Case
        c_num = f"CASE-REPORT-{uuid.uuid4().hex[:6].upper()}"
        print(f"\n[Step 1] Creating Case: {c_num}...")
        test_case = Case(
            case_number=c_num,
            name="Operation Judex - Multi-Artifact Court-Admissible Forensic Examination",
            investigator="A. Abhiram (Lead Forensic Examiner)",
            description="Complete evidentiary reconstruction report synthesizing Volatility 3, DeepNet DL, Deleted Files, Timestamps, Anti-Forensics, and Cloud logs",
            status="Analysis Complete",
        )
        db.add(test_case)
        db.commit()

        base_t = datetime(2026, 11, 14, 17, 0, 0, tzinfo=timezone.utc)

        # Step 2: Stage Comprehensive Multi-Phase Evidence
        print("\n[Step 2] Staging Complete Multi-Phase Evidence...")

        # 2a: Evidence Items (Physical disk & memory images)
        ev1_id = str(uuid.uuid4())
        ev2_id = str(uuid.uuid4())
        ev1 = Evidence(
            id=ev1_id,
            case_id=test_case.id,
            evidence_number="EVD-001",
            filename="primary_memory_dump.raw",
            stored_path="/evidence/primary_memory_dump.raw",
            file_type="Raw Memory Image",
            file_size_bytes=4294967296,
            sha256="c7e1" * 16,
            classification="OBSERVED",
            status="Verified",
        )
        ev2 = Evidence(
            id=ev2_id,
            case_id=test_case.id,
            evidence_number="EVD-002",
            filename="ntfs_system_volume.vhd",
            stored_path="/evidence/ntfs_system_volume.vhd",
            file_type="Virtual Hard Disk",
            file_size_bytes=10737418240,
            sha256="88fa" * 16,
            classification="OBSERVED",
            status="Verified",
        )
        db.add_all([ev1, ev2])
        db.commit()

        # 2b: Memory Analysis Record
        mem = MemoryAnalysisRecord(
            case_id=test_case.id,
            evidence_id=ev1_id,
            plugins_run=["windows.pslist", "windows.netscan", "windows.malfind"],
            processes=[
                {"PID": 4, "PPID": 0, "ImageFileName": "System", "Threads": 142},
                {"PID": 620, "PPID": 580, "ImageFileName": "lsass.exe", "Threads": 18},
                {"PID": 2844, "PPID": 620, "ImageFileName": "svchost.exe", "Threads": 6},
                {"PID": 3912, "PPID": 2844, "ImageFileName": "powershell.exe", "Threads": 12},
            ],
            network_connections=[
                {"PID": 3912, "ForeignAddress": "198.51.100.55:443", "State": "ESTABLISHED"},
            ],
            injected_regions=[
                {"PID": 620, "Process": "lsass.exe", "Protection": "PAGE_EXECUTE_READWRITE", "Injected": True},
            ],
        )
        db.add(mem)

        # 2c: Deleted Files Remnants
        df = DeletedFileRecord(
            case_id=test_case.id,
            evidence_id=ev2.id,
            filename="payload_dropper.exe",
            original_path="C:\\Users\\Victim\\Downloads\\payload_dropper.exe",
            carved_header_signature="4D 5A 90 00",
            file_type="PE Executable",
            estimated_size_bytes=65536,
            deletion_timestamp=base_t + timedelta(minutes=5),
            confidence=0.94,
            classification="RECONSTRUCTED",
            status="Probable deleted artifact",
            corroborating_sources=["MFT $STANDARD_INFO", "Sysmon Event ID 23", "Closed Memory Handle"],
            reconstruction_reason="Correlated MFT USN deletion entry with closed Volatility handle",
            carved_hex_preview="4D5A90000300000004000000FFFF0000",
        )
        db.add(df)

        # 2d: Timestamp Reconstruction Window
        tw = TimestampReconstructionRecord(
            case_id=test_case.id,
            event_title="Malware Execution & Lateral Beaconing",
            observed_timestamp=base_t + timedelta(minutes=10),
            probable_window_start=base_t + timedelta(minutes=9, seconds=45),
            probable_window_end=base_t + timedelta(minutes=10, seconds=30),
            probable_event_time=base_t + timedelta(minutes=10),
            window_duration_seconds=45.0,
            consistency_status="CONSISTENT",
            classification="RECONSTRUCTED",
            confidence=0.96,
            sources_compared=[
                {"source": "Volatility pslist (CreateTime)"},
                {"source": "NTFS $MFT $FILE_NAME"},
                {"source": "Security Event ID 4688"},
            ],
            related_event_ids=[],
            reconstruction_reason="Observed execution aligns with MACB modification within 45s window",
        )
        db.add(tw)

        # 2e: Anti-Forensic Tampering Anomaly
        af = AntiForensicIndicatorRecord(
            case_id=test_case.id,
            indicator_type="Audit Log Cleared",
            title="Deliberate Event Log Cleansing Detected",
            severity="Critical",
            confidence=0.98,
            classification="SUSPICIOUS",
            supporting_evidence_ids=[ev2.id],
            supporting_artifacts=["Windows Event ID 1102", "wevtutil cl Security"],
            reason="Possible manipulation detected: Security audit log was intentionally purged.",
            recommendation="Inspect unallocated disk clusters and Volume Shadow Copies for carved EVTX log fragments.",
        )
        db.add(af)

        # 2f: Cloud Audit Evidence & Cross-Correlation
        cr = CloudEvidenceRecord(
            case_id=test_case.id,
            provider="AWS",
            event_time=base_t + timedelta(minutes=12),
            event_name="StopLogging",
            service_name="cloudtrail.amazonaws.com",
            identity_arn="arn:aws:iam::123456789012:user/admin_infiltrator",
            source_ip="198.51.100.55",
            aws_region="us-east-1",
            classification="SUSPICIOUS",
            severity="Critical",
            is_anti_forensic=True,
            raw_payload={"eventName": "StopLogging", "eventSource": "cloudtrail.amazonaws.com"},
            notes="Possible anti-forensic manipulation: CloudTrail logging halted.",
        )
        db.add(cr)
        db.commit()

        cc = CloudCorrelationRecord(
            case_id=test_case.id,
            cloud_event_id=cr.id,
            local_artifact_type="Process",
            local_artifact_desc="Local execution of 'aws' (PID 3912)",
            local_timestamp=base_t + timedelta(minutes=11, seconds=50),
            cloud_timestamp=base_t + timedelta(minutes=12),
            time_delta_seconds=10.0,
            correlation_type="Process-API Attribution",
            confidence=0.95,
            classification="CORRELATED",
            rationale="Local memory execution of aws CLI tool preceded remote StopLogging call by 10.0s.",
        )
        db.add(cc)
        db.commit()

        print("  -> Staged 2 Evidence items, 1 Volatility memory record, 1 Deleted File,")
        print("     1 Timestamp Window, 1 Anti-Forensic Indicator, and 1 Cloud Correlation.")

        # Step 3: Run PDF Generation Engine
        print("\n[Step 3] Executing Court-Admissible ReportLab PDF Generation Engine...")
        pdf_bytes = generate_case_pdf_report(test_case.id, db)
        pdf_size = len(pdf_bytes)
        sha256_hash = hashlib.sha256(pdf_bytes).hexdigest()

        print(f"  -> Generated PDF size: {pdf_size:,} bytes")
        print(f"  -> SHA-256 Digest: {sha256_hash}")
        assert pdf_bytes.startswith(b"%PDF-"), "Output must have valid %PDF- magic header"
        assert pdf_size > 8000, f"Expected comprehensive PDF > 8KB, got {pdf_size} bytes"

        # Step 4: Test REST API Endpoints via TestClient
        print("\n[Step 4] Testing Reports REST API Endpoints...")

        # 4a: GET /reports/summary
        res_sum = client.get(f"/api/v1/cases/{test_case.id}/reports/summary")
        assert res_sum.status_code == 200
        summary_info = res_sum.json()
        print(f"  -> GET /reports/summary: Case={summary_info['case_number']}, Evidence={summary_info['evidence_count']}, Deleted={summary_info['deleted_files_count']}, Cloud={summary_info['cloud_records_count']}")
        assert summary_info["evidence_count"] == 2
        assert summary_info["deleted_files_count"] == 1
        assert summary_info["cloud_records_count"] == 1

        # 4b: GET /reports/pdf (Streaming binary response)
        res_stream = client.get(f"/api/v1/cases/{test_case.id}/reports/pdf")
        assert res_stream.status_code == 200
        assert res_stream.headers["content-type"] == "application/pdf"
        assert "attachment; filename=" in res_stream.headers["content-disposition"]
        assert "X-Report-SHA256" in res_stream.headers
        print(f"  -> GET /reports/pdf: Content-Disposition='{res_stream.headers['content-disposition']}'")
        print(f"  -> Verified Header X-Report-SHA256: {res_stream.headers['X-Report-SHA256']}")

        # 4c: POST /reports/generate (Disk persistence)
        res_gen = client.post(f"/api/v1/cases/{test_case.id}/reports/generate")
        assert res_gen.status_code == 200
        gen_info = res_gen.json()
        print(f"  -> POST /reports/generate: Saved report to '{gen_info['file_path']}'")
        assert os.path.exists(gen_info["file_path"])
        assert gen_info["file_size_bytes"] == pdf_size

        print("\n" + "=" * 80)
        print(">>> SUCCESS: Phase 13 Court-Admissible Forensic PDF Reports is 100% verified!")
        print("=" * 80)

    finally:
        db.close()


if __name__ == "__main__":
    run_phase13_verification()
