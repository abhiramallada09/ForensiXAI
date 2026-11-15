from fastapi.testclient import TestClient
from backend.app.main import app


def test_root_endpoint():
    with TestClient(app) as client:
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["product"] == "ForensiX AI"
        assert "Memory Forensics for Volatile Data Analysis" in data["academic_title"]


def test_health_check_endpoint():
    with TestClient(app) as client:
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["app"] == "ForensiX AI"


def test_system_status_endpoint():
    with TestClient(app) as client:
        response = client.get("/api/v1/status")
        assert response.status_code == 200
        data = response.json()
        assert data["app_name"] == "ForensiX AI"
        assert data["database_connected"] is True
        assert data["status"] == "ONLINE"


def test_create_and_list_cases():
    with TestClient(app) as client:
        # Test creating a case
        create_payload = {
            "name": "Phase 1 Baseline Case",
            "description": "Validation test case for ForensiX AI Phase 1 setup",
            "investigator": "A. Abhiram",
            "status": "New"
        }
        create_res = client.post("/api/v1/cases", json=create_payload)
        assert create_res.status_code == 201
        created_case = create_res.json()
        assert created_case["name"] == "Phase 1 Baseline Case"
        assert created_case["investigator"] == "A. Abhiram"
        assert "id" in created_case

        # Test listing cases
        list_res = client.get("/api/v1/cases")
        assert list_res.status_code == 200
        cases_list = list_res.json()
        assert len(cases_list) >= 1
        assert any(c["id"] == created_case["id"] for c in cases_list)
