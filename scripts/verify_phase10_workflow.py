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
from backend.app.models.timestamp_reconstruction import TimestampReconstructionRecord
from backend.app.forensics.timestamp_reconstruction import reconstruct_timestamp_windows
from backend.app.ml.features import to_utc
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def run_phase10_verification():
    print("=" * 80)
    print("ForensiX AI - Phase 10: Timestamp Reconstruction & Event Windows Verification")
    print("Official Academic Title:")
    print("Memory Forensics for Volatile Data Analysis via Deep Learning-based")
    print("Deleted File and Timestamp Reconstruction, Applied to Cloud Evidence")
    print("=" * 80)

    db = SessionLocal()
    try:
        # Step 1: Create Case
        c_num = f"CASE-TIME-{uuid.uuid4().hex[:6].upper()}"
        print(f"\n[Step 1] Creating Case: {c_num}...")
        test_case = Case(
            case_number=c_num,
            name="Operation Chronos - Multi-Source Timestamp Reconstruction",
            investigator="A. Abhiram",
            description="Reconstruction of probable event time windows across Volatility memory, MFT, and audit logs",
            status="Analyzing",
        )
        db.add(test_case)
        db.commit()

        # Step 2: Inject Multi-Source Events Matching Specification Example:
        # Observed event: 10:03:22
        # Related events: 10:03:18, 10:03:25, 10:03:27
        base_t = datetime(2026, 11, 14, 10, 3, 18, tzinfo=timezone.utc)
        print("\n[Step 2] Staging Correlated Multi-Source Events (File, Process, Network, Log)...")

        events = [
            TimelineEvent(
                case_id=test_case.id,
                timestamp=base_t,  # 10:03:18
                timestamp_source="Filesystem MACB ($FILE_MODIFY)",
                event_type="File Modified",
                artifact_category="File",
                description="Observed modification of payload file",
                confidence=1.0,
                classification="OBSERVED",
            ),
            TimelineEvent(
                case_id=test_case.id,
                timestamp=base_t + timedelta(seconds=4),  # 10:03:22 (Observed Anchor)
                timestamp_source="Volatility 3 windows.pslist",
                event_type="Process Started",
                artifact_category="Memory Image",
                description="Process execution: svchost.exe (PID 2844)",
                confidence=0.95,
                classification="OBSERVED",
            ),
            TimelineEvent(
                case_id=test_case.id,
                timestamp=base_t + timedelta(seconds=7),  # 10:03:25
                timestamp_source="Volatility 3 windows.netscan",
                event_type="Network Activity",
                artifact_category="Network Evidence",
                description="Outbound socket connection to C2 IP 198.51.100.44",
                confidence=0.90,
                classification="CORRELATED",
            ),
            TimelineEvent(
                case_id=test_case.id,
                timestamp=base_t + timedelta(seconds=9),  # 10:03:27
                timestamp_source="Security Audit Log (Event ID 4660)",
                event_type="File Deleted",
                artifact_category="File",
                description="File Deleted event logged by audit policy",
                confidence=0.92,
                classification="SUSPICIOUS",
            ),
        ]
        db.add_all(events)
        db.commit()

        # Step 3: Run Engine
        print("\n[Step 3] Running Timestamp Reconstruction Engine (30s window threshold)...")
        records = reconstruct_timestamp_windows(test_case.id, db, window_threshold_seconds=30.0)
        print(f"  -> Generated {len(records)} Timestamp Window(s)")
        assert len(records) >= 1, "Should reconstruct at least 1 window!"

        w = records[0]
        print(f"  -> Event Title:           {w.event_title}")
        print(f"  -> Observed Anchor Time:  {to_utc(w.observed_timestamp).strftime('%H:%M:%S UTC')}")
        print(f"  -> Probable Window Start: {to_utc(w.probable_window_start).strftime('%H:%M:%S UTC')}")
        print(f"  -> Probable Window End:   {to_utc(w.probable_window_end).strftime('%H:%M:%S UTC')}")
        print(f"  -> Window Duration Span:  {w.window_duration_seconds}s")
        print(f"  -> Consistency Status:    {w.consistency_status}")
        print(f"  -> Classification:        {w.classification}")
        print(f"  -> Confidence:            {w.confidence * 100:.0f}%")
        print(f"  -> Sources Compared:      ({len(w.sources_compared)})")
        for s in w.sources_compared:
            print(f"       * {s['source']}: {s.get('formatted_time')} ({s['event_type']})")

        assert w.window_duration_seconds == 9.0, f"Expected 9.0s duration span, got {w.window_duration_seconds}"
        assert to_utc(w.probable_window_start) <= base_t, "Window start must encompass earliest event"
        assert to_utc(w.probable_window_end) >= (base_t + timedelta(seconds=9)), "Window end must encompass latest event"
        assert w.confidence >= 0.80, "Confidence should be >= 80%"

        # Step 4: Test Inconsistent / Timestomped Sequence Detection
        print("\n[Step 4] Staging Inconsistent/Inverted Timestamp Events...")
        # File Deleted occurs before Process Started
        inconsistent_events = [
            TimelineEvent(
                case_id=test_case.id,
                timestamp=base_t + timedelta(minutes=10),
                timestamp_source="Security Audit Log (Event ID 4660)",
                event_type="File Deleted",
                artifact_category="File",
                description="File Deleted before execution trace",
                confidence=0.90,
                classification="SUSPICIOUS",
            ),
            TimelineEvent(
                case_id=test_case.id,
                timestamp=base_t + timedelta(minutes=10, seconds=15),
                timestamp_source="Filesystem MACB ($FILE_CREATE)",
                event_type="File Created",
                artifact_category="File",
                description="Inverted creation after deletion (timestomping indicator)",
                confidence=0.88,
                classification="SUSPICIOUS",
            ),
        ]
        db.add_all(inconsistent_events)
        db.commit()

        inconsistent_records = reconstruct_timestamp_windows(test_case.id, db, window_threshold_seconds=60.0)
        inconsistent_win = next((r for r in inconsistent_records if r.consistency_status == "INCONSISTENT"), None)
        assert inconsistent_win is not None, "Engine must detect INCONSISTENT timestamp sequence!"
        print(f"  -> Detected Inconsistency: {inconsistent_win.event_title}")
        print(f"  -> Consistency Status:     {inconsistent_win.consistency_status}")
        print(f"  -> Classification:         {inconsistent_win.classification}")
        assert inconsistent_win.classification == "SUSPICIOUS", "Inconsistent timestamp sequence must be SUSPICIOUS!"

        # Step 5: Test REST API Endpoints
        print("\n[Step 5] Testing FastAPI REST Endpoints...")
        api_res = client.get(f"/api/v1/cases/{test_case.id}/timestamps")
        assert api_res.status_code == 200
        summary_data = api_res.json()
        print(f"  -> Total Windows Evaluated: {summary_data['total_windows_evaluated']}")
        print(f"  -> Consistent Sequences:    {summary_data['consistent_count']}")
        print(f"  -> Inconsistent Sequences:  {summary_data['inconsistent_count']}")
        print(f"  -> Average Confidence:      {summary_data['average_confidence'] * 100:.1f}%")

        print("\n" + "=" * 80)
        print("PHASE 10 TIMESTAMP RECONSTRUCTION: ALL CHECKS PASSED [SUCCESS]")
        print("=" * 80)

    finally:
        db.close()


if __name__ == "__main__":
    run_phase10_verification()

