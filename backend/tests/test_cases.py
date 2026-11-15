import pytest
from fastapi.testclient import TestClient
from backend.app.main import app


def test_case_lifecycle():
    with TestClient(app) as client:
        # 1. Create a case with custom case number
        create_payload = {
            "case_number": "CAS-TEST-999",
            "name": "Phase 2 Forensic Lifecycle Case",
            "description": "Initial investigation into unauthorized volatile process injections.",
            "investigator": "A. Abhiram",
            "status": "New"
        }
        res = client.post("/api/v1/cases", json=create_payload)
        assert res.status_code == 201
        case = res.json()
        case_id = case["id"]
        assert case["case_number"] == "CAS-TEST-999"
        assert case["name"] == "Phase 2 Forensic Lifecycle Case"
        assert case["status"] == "New"
        assert case["evidence_count"] == 0

        # 2. Duplicate case number rejection
        dup_res = client.post("/api/v1/cases", json=create_payload)
        assert dup_res.status_code == 409

        # 3. Retrieve by ID
        get_res = client.get(f"/api/v1/cases/{case_id}")
        assert get_res.status_code == 200
        assert get_res.json()["id"] == case_id

        # 4. Filter by status
        list_res = client.get("/api/v1/cases?status=New")
        assert list_res.status_code == 200
        cases_list = list_res.json()
        assert any(c["id"] == case_id for c in cases_list)

        # 5. Search cases
        search_res = client.get("/api/v1/cases?search=Lifecycle")
        assert search_res.status_code == 200
        assert any(c["id"] == case_id for c in search_res.json())

        # 6. Update / Rename Case
        update_payload = {
            "name": "Renamed Incident 999",
            "description": "Updated description with new indicators.",
            "status": "Analyzing"
        }
        update_res = client.patch(f"/api/v1/cases/{case_id}", json=update_payload)
        assert update_res.status_code == 200
        updated = update_res.json()
        assert updated["name"] == "Renamed Incident 999"
        assert updated["status"] == "Analyzing"

        # 7. Archive Case
        archive_res = client.post(f"/api/v1/cases/{case_id}/archive")
        assert archive_res.status_code == 200
        assert archive_res.json()["status"] == "Archived"

        # 8. Export Case Dossier as JSON
        export_res = client.get(f"/api/v1/cases/{case_id}/export")
        assert export_res.status_code == 200
        export_data = export_res.json()
        assert export_data["case"]["id"] == case_id
        assert "evidence" in export_data
        assert "timeline_events" in export_data
        assert "findings" in export_data

        # 9. Delete Case
        del_res = client.delete(f"/api/v1/cases/{case_id}")
        assert del_res.status_code == 200
        assert del_res.json()["success"] is True

        # Verify 404 after deletion
        not_found_res = client.get(f"/api/v1/cases/{case_id}")
        assert not_found_res.status_code == 404


def test_invalid_case_status():
    with TestClient(app) as client:
        payload = {
            "name": "Invalid Status Case",
            "status": "NonExistentStatus"
        }
        res = client.post("/api/v1/cases", json=payload)
        assert res.status_code == 400

