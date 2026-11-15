import os
import sys
import uuid
from datetime import datetime, timezone

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.app.core.database import SessionLocal, Base, engine
from backend.app.models.case import Case
from backend.app.models.evidence import Evidence
from backend.app.models.event import TimelineEvent
from backend.app.models.finding import ForensicFinding
from backend.app.models.memory import MemoryAnalysisRecord
from backend.app.models.deleted_file import DeletedFileRecord
from backend.app.forensics.deleted_analysis import analyze_deleted_file_traces
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def run_phase9_verification():
    print("=" * 80)
    print("ForensiX AI - Phase 9: Deleted-File Trace Analysis Verification")
    print("Official Academic Title:")
    print("Memory Forensics for Volatile Data Analysis via Deep Learning-based")
    print("Deleted File and Timestamp Reconstruction, Applied to Cloud Evidence")
    print("=" * 80)

    db = SessionLocal()
    try:
        # Step 1: Create Case
        c_num = f"CASE-DEL-{uuid.uuid4().hex[:6].upper()}"
        print(f"\n[Step 1] Creating Case: {c_num}...")
        test_case = Case(
            case_number=c_num,
            name="Operation Mirage - Deleted Malware & MFT Remnants Recovery",
            investigator="A. Abhiram",
            description="Forensic investigation into wiped memory payloads and unallocated file traces",
            status="Analyzing",
        )
        db.add(test_case)
        db.commit()

        # Step 2: Add Staged Evidence (Memory Image & Carved Slack bytes)
        print("\n[Step 2] Staging Volatile Memory & Carved Disk Residue Evidence...")
        mem_evidence = Evidence(
            case_id=test_case.id,
            evidence_number=f"EVI-MEM-{uuid.uuid4().hex[:4].upper()}",
            filename="physical_memory.raw",
            stored_path="physical_memory.raw",
            file_size_bytes=4194304,
            sha256="e" * 64,
            file_type="Memory Image",
        )
        disk_slack_evidence = Evidence(
            case_id=test_case.id,
            evidence_number=f"EVI-SLACK-{uuid.uuid4().hex[:4].upper()}",
            filename="unallocated_cluster_slack.bin",
            stored_path="unallocated_cluster_slack.bin",
            file_size_bytes=65536,
            sha256="f" * 64,
            file_type="File",
            metadata_json={
                "deleted_indicator": True,
                "unallocated_slack": True,
                "entropy": 7.42,
                "original_path": r"C:\Windows\Temp\malware_test.exe",
            },
        )
        db.add_all([mem_evidence, disk_slack_evidence])
        db.commit()

        # Step 3: Add Memory Analysis Record with Closed Handles & Deletion Command
        print("\n[Step 3] Injecting Volatility 3 Kernel Memory Traces...")
        mem_rec = MemoryAnalysisRecord(
            case_id=test_case.id,
            evidence_id=mem_evidence.id,
            plugins_run=["windows.handles", "windows.cmdline"],
            processes=[{"PID": 2844, "PPID": 1024, "ImageFileName": "cmd.exe"}],
            handles=[
                {
                    "PID": 2844,
                    "Process": "cmd.exe",
                    "HandleValue": "0x2e0",
                    "Type": "File",
                    "Name": r"C:\Windows\Temp\malware_test.exe",
                }
            ],
            cmdlines=[
                {
                    "PID": 2844,
                    "Process": "cmd.exe",
                    "CommandLine": r'cmd.exe /c del /f /q C:\Windows\Temp\malware_test.exe',
                }
            ],
        )
        db.add(mem_rec)
        db.commit()

        # Step 4: Add Chronological Audit Log Deletion Event (Event ID 4660)
        print("\n[Step 4] Adding Security Audit Log Deletion Event...")
        del_event = TimelineEvent(
            case_id=test_case.id,
            evidence_id=disk_slack_evidence.id,
            timestamp=datetime(2026, 11, 14, 10, 6, 18, tzinfo=timezone.utc),
            timestamp_source="Security Audit Log (Event ID 4660)",
            event_type="File Deleted",
            artifact_category="File",
            description=r"File Deleted: C:\Windows\Temp\malware_test.exe",
            confidence=0.92,
            classification="SUSPICIOUS",
        )
        db.add(del_event)
        db.commit()

        # Step 5: Execute Deleted-File Trace Analysis Engine
        print("\n[Step 5] Executing Deleted File Analysis Engine...")
        records = analyze_deleted_file_traces(test_case.id, db)
        print(f"  -> Discovered {len(records)} Probable Deleted Artifact(s)")

        assert len(records) >= 1, "Should identify at least one deleted file candidate!"
        del_item = next((r for r in records if "malware_test.exe" in r.filename.lower()), records[0])

        print(f"  -> Filename:              {del_item.filename}")
        print(f"  -> Original Path:          {del_item.original_path}")
        print(f"  -> Forensic Status:        {del_item.status}")
        print(f"  -> Classification:         {del_item.classification}")
        print(f"  -> Confidence:             {del_item.confidence * 100:.1f}%")
        print(f"  -> Carved Signature:       {del_item.carved_header_signature}")
        print(f"  -> Corroborating Sources:  ({len(del_item.corroborating_sources)})")
        for s in del_item.corroborating_sources:
            print(f"       * {s}")

        assert del_item.status == "Probable deleted artifact", "Must adhere to careful forensic phrasing!"
        assert del_item.classification in {"RECONSTRUCTED", "SUSPICIOUS"}, "Must be RECONSTRUCTED or SUSPICIOUS!"
        assert del_item.confidence >= 0.80, "Multi-source evidence must achieve >= 80% confidence!"
        assert len(del_item.corroborating_sources) >= 2, "Must be corroborated by multiple independent traces!"

        # Step 6: Verify Linked Forensic Finding
        findings = db.query(ForensicFinding).filter(
            ForensicFinding.case_id == test_case.id,
            ForensicFinding.finding_type == "Deleted File Trace",
        ).all()
        print(f"\n[Step 6] Verifying Automatically Synthesized Findings: {len(findings)} found")
        assert len(findings) >= 1, "Should automatically create high-confidence ForensicFinding!"
        print(f"  -> Finding Title:   {findings[0].title}")
        print(f"  -> Classification:  {findings[0].classification}")
        print(f"  -> Confidence:      {findings[0].confidence * 100:.1f}%")

        # Step 7: Verify REST API Endpoints
        print("\n[Step 7] Testing FastAPI REST Endpoints...")
        api_res = client.get(f"/api/v1/cases/{test_case.id}/deleted-files")
        assert api_res.status_code == 200
        summary_data = api_res.json()
        print(f"  -> API Total Deleted Artifacts: {summary_data['total_deleted_artifacts']}")
        print(f"  -> API Memory Corroborated:     {summary_data['memory_corroborated_count']}")
        print(f"  -> API Log Corroborated:        {summary_data['log_corroborated_count']}")
        print(f"  -> API Average Confidence:      {summary_data['average_confidence'] * 100:.1f}%")

        print("\n" + "=" * 80)
        print("PHASE 9 DELETED-FILE TRACE ANALYSIS: ALL CHECKS PASSED [SUCCESS]")
        print("=" * 80)

    finally:
        db.close()


if __name__ == "__main__":
    run_phase9_verification()

