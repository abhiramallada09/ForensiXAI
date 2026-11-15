import uuid
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.core.database import SessionLocal
from backend.app.models.case import Case
from backend.app.models.evidence import Evidence
from backend.app.models.event import TimelineEvent
from backend.app.models.memory import MemoryAnalysisRecord
from backend.app.models.deleted_file import DeletedFileRecord
from backend.app.forensics.deleted_analysis import analyze_deleted_file_traces

client = TestClient(app)


def test_deleted_analysis_engine():
    """Verify deleted file trace extraction across memory handles and timeline events."""
    db = SessionLocal()
    try:
        case = Case(
            case_number=f"CASE-DEL-{uuid.uuid4().hex[:6]}",
            name="Deleted File Remnant Investigation",
            investigator="A. Abhiram",
            status="Analyzing",
        )
        db.add(case)
        db.commit()

        # Add Evidence row for the memory dump
        evi = Evidence(
            case_id=case.id,
            evidence_number=f"EVI-MEM-{uuid.uuid4().hex[:4]}",
            filename="memory.raw",
            stored_path="memory.raw",
            file_size_bytes=1048576,
            sha256="d" * 64,
            file_type="Memory Image",
        )
        db.add(evi)
        db.commit()

        # Add Memory record with a closed handle pointing to a deleted temporary executable
        mem_rec = MemoryAnalysisRecord(
            case_id=case.id,
            evidence_id=evi.id,
            plugins_run=["windows.handles", "windows.cmdline"],
            processes=[{"PID": 2844, "PPID": 1024, "ImageFileName": "explorer.exe"}],
            handles=[
                {
                    "PID": 2844,
                    "Process": "explorer.exe",
                    "HandleValue": "0x1b4",
                    "Type": "File",
                    "Name": r"C:\Windows\Temp\malware_test.exe",
                }
            ],
            cmdlines=[
                {
                    "PID": 1024,
                    "Process": "cmd.exe",
                    "CommandLine": r'cmd.exe /c del /f /q C:\Windows\Temp\malware_test.exe',
                }
            ],
        )
        db.add(mem_rec)
        db.add(mem_rec)

        # Add a corresponding timeline deletion event
        del_event = TimelineEvent(
            case_id=case.id,
            timestamp=datetime(2026, 11, 14, 10, 6, 18, tzinfo=timezone.utc),
            timestamp_source="Security Audit Log (Event ID 4660)",
            event_type="File Deleted",
            artifact_category="File",
            description="File Deleted: C:\\Windows\\Temp\\malware_test.exe",
            confidence=0.90,
            classification="SUSPICIOUS",
        )
        db.add(del_event)
        db.commit()

        # Execute analysis
        records = analyze_deleted_file_traces(case.id, db)
        assert len(records) >= 1

        del_record = next((r for r in records if "malware_test.exe" in r.filename.lower()), records[0])
        assert del_record.filename == "malware_test.exe"
        assert del_record.status == "Probable deleted artifact"
        assert del_record.classification in {"RECONSTRUCTED", "SUSPICIOUS"}
        assert del_record.confidence >= 0.80
        assert del_record.carved_header_signature == "4D 5A 90 00"

        # Check corroboration
        assert len(del_record.corroborating_sources) >= 2
        assert any("memory handle" in s.lower() for s in del_record.corroborating_sources)
        assert any("timeline" in s.lower() or "cmd" in s.lower() for s in del_record.corroborating_sources)
    finally:
        db.close()


def test_deleted_rest_api():
    """Verify REST endpoints for running and managing deleted file traces."""
    # Create test case
    case_res = client.post("/api/v1/cases/", json={
        "name": "Deleted File API Test",
        "investigator": "A. Abhiram",
        "description": "API verification of Module 7",
    })
    assert case_res.status_code == 201
    case_id = case_res.json()["id"]

    # 1. POST /api/v1/cases/{case_id}/deleted-files/analyze
    analyze_res = client.post(f"/api/v1/cases/{case_id}/deleted-files/analyze")
    assert analyze_res.status_code == 200
    data = analyze_res.json()
    assert data["case_id"] == case_id
    assert data["total_deleted_artifacts"] >= 1
    assert data["average_confidence"] >= 0.70

    first_artifact = data["artifacts"][0]
    record_id = first_artifact["id"]
    assert first_artifact["status"] == "Probable deleted artifact"
    assert first_artifact["classification"] in {"RECONSTRUCTED", "SUSPICIOUS"}

    # 2. GET /api/v1/cases/{case_id}/deleted-files
    list_res = client.get(f"/api/v1/cases/{case_id}/deleted-files")
    assert list_res.status_code == 200
    assert len(list_res.json()["artifacts"]) >= 1

    # 3. GET /api/v1/cases/{case_id}/deleted-files/{record_id}
    single_res = client.get(f"/api/v1/cases/{case_id}/deleted-files/{record_id}")
    assert single_res.status_code == 200
    assert single_res.json()["id"] == record_id

    # 4. DELETE /api/v1/cases/{case_id}/deleted-files/{record_id}
    del_res = client.delete(f"/api/v1/cases/{case_id}/deleted-files/{record_id}")
    assert del_res.status_code == 204
