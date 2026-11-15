import uuid
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.core.database import SessionLocal
from backend.app.models.case import Case
from backend.app.models.event import TimelineEvent
from backend.app.models.timestamp_reconstruction import TimestampReconstructionRecord
from backend.app.forensics.timestamp_reconstruction import reconstruct_timestamp_windows
from backend.app.ml.features import to_utc

client = TestClient(app)


def test_timestamp_reconstruction_engine():
    """Verify multi-source timestamp window calculation, consistency checking, and padding."""
    db = SessionLocal()
    try:
        case = Case(
            case_number=f"CASE-TIME-{uuid.uuid4().hex[:6]}",
            name="Timestamp Reconstruction Investigation",
            investigator="A. Abhiram",
            status="Analyzing",
        )
        db.add(case)
        db.commit()

        base_time = datetime(2026, 11, 14, 10, 3, 18, tzinfo=timezone.utc)

        # 4 Multi-Source Events matching specification example: 10:03:18, 10:03:22, 10:03:25, 10:03:27
        events = [
            TimelineEvent(
                case_id=case.id,
                timestamp=base_time,  # 10:03:18
                timestamp_source="Filesystem MACB ($FILE_MODIFY)",
                event_type="File Modified",
                artifact_category="File",
                description="Observed modification of payload file",
                confidence=1.0,
                classification="OBSERVED",
            ),
            TimelineEvent(
                case_id=case.id,
                timestamp=base_time + timedelta(seconds=4),  # 10:03:22 (Observed Anchor)
                timestamp_source="Volatility 3 windows.pslist",
                event_type="Process Started",
                artifact_category="Memory Image",
                description="Process execution: svchost.exe (PID 2844)",
                confidence=0.95,
                classification="OBSERVED",
            ),
            TimelineEvent(
                case_id=case.id,
                timestamp=base_time + timedelta(seconds=7),  # 10:03:25
                timestamp_source="Volatility 3 windows.netscan",
                event_type="Network Activity",
                artifact_category="Network Evidence",
                description="Outbound socket connection to C2 IP 198.51.100.44",
                confidence=0.90,
                classification="CORRELATED",
            ),
            TimelineEvent(
                case_id=case.id,
                timestamp=base_time + timedelta(seconds=9),  # 10:03:27
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

        # Run reconstruction with 30s clustering
        records = reconstruct_timestamp_windows(case.id, db, window_threshold_seconds=30.0)
        assert len(records) >= 1

        rec = records[0]
        assert rec.case_id == case.id
        assert to_utc(rec.probable_window_start) <= to_utc(base_time)
        assert to_utc(rec.probable_window_end) >= to_utc(base_time + timedelta(seconds=9))
        assert rec.window_duration_seconds == 9.0
        assert rec.confidence >= 0.80
        assert rec.classification in {"RECONSTRUCTED", "SUSPICIOUS"}
        assert len(rec.sources_compared) == 4
        assert "Probable event window" in rec.reconstruction_reason
    finally:
        db.close()


def test_timestamp_rest_api():
    """Verify REST endpoints for timestamp reconstruction, retrieval, and deletion."""
    # Create test case
    case_res = client.post("/api/v1/cases/", json={
        "name": "Timestamp REST API Test Case",
        "investigator": "A. Abhiram",
        "description": "Validation of Module 8 endpoints",
    })
    assert case_res.status_code == 201
    case_id = case_res.json()["id"]

    # 1. POST /api/v1/cases/{case_id}/timestamps/reconstruct
    reconstruct_res = client.post(f"/api/v1/cases/{case_id}/timestamps/reconstruct?window_threshold_seconds=120.0")
    assert reconstruct_res.status_code == 200
    summary = reconstruct_res.json()
    assert summary["case_id"] == case_id
    assert summary["total_windows_evaluated"] >= 1
    assert summary["average_confidence"] >= 0.75

    first_window = summary["reconstructed_windows"][0]
    rec_id = first_window["id"]
    assert "probable_window_start" in first_window
    assert "probable_window_end" in first_window
    assert first_window["classification"] in {"RECONSTRUCTED", "SUSPICIOUS"}

    # 2. GET /api/v1/cases/{case_id}/timestamps
    list_res = client.get(f"/api/v1/cases/{case_id}/timestamps")
    assert list_res.status_code == 200
    assert len(list_res.json()["reconstructed_windows"]) >= 1

    # 3. GET /api/v1/cases/{case_id}/timestamps/{record_id}
    single_res = client.get(f"/api/v1/cases/{case_id}/timestamps/{rec_id}")
    assert single_res.status_code == 200
    assert single_res.json()["id"] == rec_id

    # 4. DELETE /api/v1/cases/{case_id}/timestamps/{record_id}
    del_res = client.delete(f"/api/v1/cases/{case_id}/timestamps/{rec_id}")
    assert del_res.status_code == 204
