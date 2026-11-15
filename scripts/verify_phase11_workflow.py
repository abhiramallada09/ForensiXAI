import os
import sys
import uuid
from datetime import datetime, timezone, timedelta

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.app.core.database import SessionLocal, Base, engine
from backend.app.models.case import Case
from backend.app.models.evidence import Evidence
from backend.app.models.event import TimelineEvent
from backend.app.models.finding import ForensicFinding
from backend.app.models.anti_forensic import AntiForensicIndicatorRecord
from backend.app.forensics.anti_forensics import detect_anti_forensic_anomalies
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def run_phase11_verification():
    print("=" * 80)
    print("ForensiX AI - Phase 11: Anti-Forensic Anomaly Detection Verification")
    print("Official Academic Title:")
    print("Memory Forensics for Volatile Data Analysis via Deep Learning-based")
    print("Deleted File and Timestamp Reconstruction, Applied to Cloud Evidence")
    print("=" * 80)

    db = SessionLocal()
    try:
        # Step 1: Create Case
        c_num = f"CASE-ANTI-{uuid.uuid4().hex[:6].upper()}"
        print(f"\n[Step 1] Creating Case: {c_num}...")
        test_case = Case(
            case_number=c_num,
            name="Operation Shadow Sweep - Anti-Forensic Tampering Investigation",
            investigator="A. Abhiram",
            description="Investigation into anti-forensic timestomping, audit log wiping, and sdelete artifacts",
            status="Analyzing",
        )
        db.add(test_case)
        db.commit()

        # Step 2: Stage Anti-Forensic Artifacts
        print("\n[Step 2] Staging Multi-Source Anti-Forensic Artifacts...")
        base_t = datetime(2026, 11, 14, 11, 0, 0, tzinfo=timezone.utc)

        # 2a: Timestomping Artifact (modified before created & subseconds zeroed)
        timestomped_ev = Evidence(
            case_id=test_case.id,
            evidence_number=f"EVD-TIME-{uuid.uuid4().hex[:4].upper()}",
            filename="suspicious_driver.sys",
            stored_path="/uploads/evidence/suspicious_driver.sys",
            file_type="System Driver",
            file_size_bytes=102400,
            sha256="aa" * 32,
            created_time=base_t,
            modified_time=base_t - timedelta(days=600),  # Modified way before created!
            classification="SUSPICIOUS",
            status="Uploaded",
            metadata_json={"subsecond_nanoseconds": 0},
        )
        db.add(timestomped_ev)

        # 2b: Extension Spoofing Artifact (MZ PE header inside a .pdf document)
        spoofed_ev = Evidence(
            case_id=test_case.id,
            evidence_number=f"EVD-SPOOF-{uuid.uuid4().hex[:4].upper()}",
            filename="confidential_memo.pdf",
            stored_path="/uploads/evidence/confidential_memo.pdf",
            file_type="PDF Document",
            file_size_bytes=204800,
            sha256="bb" * 32,
            classification="SUSPICIOUS",
            status="Uploaded",
            metadata_json={"header_hex": "4d5a900003000000"},  # MZ header!
        )
        db.add(spoofed_ev)

        # 2c: Audit Log Cleared Event (Event ID 1102)
        log_clear_event = TimelineEvent(
            case_id=test_case.id,
            timestamp=base_t + timedelta(minutes=10),
            timestamp_source="Security.evtx",
            event_type="Log Cleared",
            artifact_category="Event Log",
            description="Audit log was cleared. Event ID 1102 logged by System.",
            confidence=0.98,
            classification="SUSPICIOUS",
        )
        db.add(log_clear_event)

        # 2d: Secure Wiping Execution Event (sdelete -p 3)
        wiping_event = TimelineEvent(
            case_id=test_case.id,
            timestamp=base_t + timedelta(minutes=15),
            timestamp_source="CommandLine History / Sysmon",
            event_type="Command Executed",
            artifact_category="Command",
            description='cmd.exe /c "sdelete -p 3 -z D:\\Data\\Confidential"',
            confidence=0.95,
            classification="SUSPICIOUS",
        )
        db.add(wiping_event)

        # 2e: Injected Code / Memory Injection Event
        injection_event = TimelineEvent(
            case_id=test_case.id,
            timestamp=base_t + timedelta(minutes=20),
            timestamp_source="Volatility 3 windows.malfind",
            event_type="Code Injection",
            artifact_category="Memory Image",
            description="Process lsass.exe (PID 620) contains unbacked executable PAGE_EXECUTE_READWRITE memory",
            confidence=0.94,
            classification="SUSPICIOUS",
        )
        db.add(injection_event)

        db.commit()
        print("  -> Injected 2 Evidence items and 3 Timeline events covering 5 anti-forensic heuristics.")

        # Step 3: Run Anti-Forensics Engine
        print("\n[Step 3] Running Multi-Heuristic Anti-Forensics Engine...")
        detected = detect_anti_forensic_anomalies(test_case.id, db)
        print(f"  -> Detected {len(detected)} Anti-Forensic Indicator(s):")

        for ind in detected:
            print(f"     * [{ind.severity}] {ind.indicator_type}: '{ind.title}'")
            print(f"       Reason: {ind.reason}")
            print(f"       Artifacts: {ind.supporting_artifacts}")
            print(f"       Recommendation: {ind.recommendation}")
            assert "possible manipulation detected" in ind.reason.lower() or "observed" in ind.reason.lower(), (
                "Forensic Safety Rule violation: must use non-accusatory terminology"
            )
            assert ind.classification == "SUSPICIOUS", "Classification must be SUSPICIOUS"

        assert len(detected) >= 4, f"Expected at least 4 indicators, got {len(detected)}"

        # Step 4: Verify Findings Were Automatically Synthesized
        print("\n[Step 4] Checking Synthesized Forensic Findings...")
        findings = db.query(ForensicFinding).filter(
            ForensicFinding.case_id == test_case.id,
            ForensicFinding.finding_type == "Anti-Forensic Anomaly",
        ).all()
        print(f"  -> Found {len(findings)} Forensic Finding(s) recorded in database.")
        assert len(findings) >= 1, "Should record at least 1 finding in ForensicFinding table"

        # Step 5: Test REST API Endpoints via TestClient
        print("\n[Step 5] Testing Anti-Forensic REST API Endpoints...")

        # 5a: POST /analyze
        res_post = client.post(f"/api/v1/cases/{test_case.id}/anti-forensics/analyze")
        assert res_post.status_code == 200, f"Analyze failed: {res_post.status_code} {res_post.text}"
        data_post = res_post.json()
        print(f"  -> POST /analyze: total={data_post['total_indicators']}, critical={data_post['critical_severity_count']}, high={data_post['high_severity_count']}")
        assert data_post["total_indicators"] >= 4

        # 5b: GET /anti-forensics
        res_get = client.get(f"/api/v1/cases/{test_case.id}/anti-forensics")
        assert res_get.status_code == 200, f"Get indicators failed: {res_get.text}"
        data_get = res_get.json()
        assert len(data_get["indicators"]) >= 4

        # 5c: GET /anti-forensics/{indicator_id}
        first_id = data_get["indicators"][0]["id"]
        res_single = client.get(f"/api/v1/cases/{test_case.id}/anti-forensics/{first_id}")
        assert res_single.status_code == 200, f"Get single indicator failed: {res_single.text}"
        single_data = res_single.json()
        assert single_data["id"] == first_id
        print(f"  -> Single Indicator Verified: {single_data['title']}")

        # 5d: DELETE /anti-forensics/{indicator_id}
        res_del = client.delete(f"/api/v1/cases/{test_case.id}/anti-forensics/{first_id}")
        assert res_del.status_code == 204, f"Delete indicator failed: {res_del.status_code} {res_del.text}"
        print(f"  -> Deleted Indicator {first_id} successfully (Status 204).")

        # Re-query
        res_after = client.get(f"/api/v1/cases/{test_case.id}/anti-forensics")
        assert len(res_after.json()["indicators"]) == len(data_get["indicators"]) - 1

        print("\n" + "=" * 80)
        print(">>> SUCCESS: Phase 11 Anti-Forensic Anomaly Detection is 100% verified!")
        print("=" * 80)

    finally:
        db.close()


if __name__ == "__main__":
    run_phase11_verification()
