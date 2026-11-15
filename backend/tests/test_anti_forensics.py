import uuid
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.core.database import SessionLocal
from backend.app.models.case import Case
from backend.app.models.evidence import Evidence
from backend.app.models.event import TimelineEvent
from backend.app.models.anti_forensic import AntiForensicIndicatorRecord
from backend.app.forensics.anti_forensics import detect_anti_forensic_anomalies

client = TestClient(app)


def test_anti_forensics_engine():
    """Verify detection of timestomping and event log clearing indicators."""
    db = SessionLocal()
    try:
        case = Case(
            case_number=f"CASE-AF-{uuid.uuid4().hex[:6]}",
            name="Anti-Forensic Anomaly Detection Case",
            investigator="A. Abhiram",
            status="Analyzing",
        )
        db.add(case)
        db.commit()

        # 1. Evidence with timestomped inverted timestamps (modified 30m before creation)
        evi = Evidence(
            case_id=case.id,
            evidence_number=f"EVI-AF-{uuid.uuid4().hex[:4]}",
            filename="timestomped_agent.exe",
            stored_path="timestomped_agent.exe",
            file_size_bytes=524288,
            sha256="1" * 64,
            file_type="File",
            created_time=datetime(2026, 11, 14, 10, 30, 0, tzinfo=timezone.utc),
            modified_time=datetime(2026, 11, 14, 10, 0, 0, tzinfo=timezone.utc),  # Inverted -30m
            metadata_json={"timestomped": True},
        )
        db.add(evi)

        # 2. Event log indicating log was cleared (Event ID 1102)
        ev = TimelineEvent(
            case_id=case.id,
            timestamp=datetime(2026, 11, 14, 10, 35, 0, tzinfo=timezone.utc),
            timestamp_source="Security Audit Log (Event ID 1102)",
            event_type="Other",
            artifact_category="System Log",
            description="The audit log was cleared by user NT AUTHORITY\\SYSTEM",
            confidence=1.0,
            classification="SUSPICIOUS",
        )
        db.add(ev)
        db.commit()

        # Run anti-forensic scan
        indicators = detect_anti_forensic_anomalies(case.id, db)
        assert len(indicators) >= 2

        # Check Timestomping indicator
        ts_ind = next((i for i in indicators if "Timestamp" in i.indicator_type), None)
        assert ts_ind is not None
        assert ts_ind.classification == "SUSPICIOUS"
        assert ts_ind.severity in {"High", "Critical"}
        assert ts_ind.confidence >= 0.85
        assert "Possible manipulation" in ts_ind.reason
        assert "Manual forensic verification required" in ts_ind.recommendation

        # Check Log Cleared indicator
        log_ind = next((i for i in indicators if "Log Cleared" in i.indicator_type), None)
        assert log_ind is not None
        assert log_ind.severity == "Critical"
        assert log_ind.confidence >= 0.90
        assert "cleared" in log_ind.reason.lower()
    finally:
        db.close()


def test_anti_forensics_rest_api():
    """Verify REST endpoints for scanning, retrieving, and managing anti-forensic anomalies."""
    # Create test case
    case_res = client.post("/api/v1/cases/", json={
        "name": "Anti-Forensics REST API Test Case",
        "investigator": "A. Abhiram",
        "description": "Validation of Module 9 anti-forensics endpoints",
    })
    assert case_res.status_code == 201
    case_id = case_res.json()["id"]

    # 1. POST /api/v1/cases/{case_id}/anti-forensics/analyze
    scan_res = client.post(f"/api/v1/cases/{case_id}/anti-forensics/analyze")
    assert scan_res.status_code == 200
    summary = scan_res.json()
    assert summary["case_id"] == case_id
    assert summary["total_indicators"] >= 1
    assert summary["average_confidence"] >= 0.80

    first_ind = summary["indicators"][0]
    ind_id = first_ind["id"]
    assert first_ind["classification"] == "SUSPICIOUS"
    assert "Possible manipulation" in first_ind["reason"]

    # 2. GET /api/v1/cases/{case_id}/anti-forensics
    list_res = client.get(f"/api/v1/cases/{case_id}/anti-forensics")
    assert list_res.status_code == 200
    assert len(list_res.json()["indicators"]) >= 1

    # 3. GET /api/v1/cases/{case_id}/anti-forensics/{indicator_id}
    single_res = client.get(f"/api/v1/cases/{case_id}/anti-forensics/{ind_id}")
    assert single_res.status_code == 200
    assert single_res.json()["id"] == ind_id

    # 4. DELETE /api/v1/cases/{case_id}/anti-forensics/{indicator_id}
    del_res = client.delete(f"/api/v1/cases/{case_id}/anti-forensics/{ind_id}")
    assert del_res.status_code == 204

