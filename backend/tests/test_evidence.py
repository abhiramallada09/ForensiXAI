import io
import hashlib
from fastapi.testclient import TestClient
from backend.app.main import app


def test_evidence_upload_and_integrity_verification():
    with TestClient(app) as client:
        # 1. Create a parent investigation case
        case_res = client.post(
            "/api/v1/cases",
            json={
                "name": "Phase 3 Evidence Test Case",
                "description": "Validation of forensic evidence upload and hashing.",
                "investigator": "A. Abhiram",
                "status": "New",
            },
        )
        assert case_res.status_code == 201
        case_id = case_res.json()["id"]

        # 2. Prepare test file bytes and compute expected SHA-256
        test_content = b"FORENSIX_AI_EVIDENCE_SAMPLE_CONTENT_2026_TEST_STRING_VERIFICATION\n"
        expected_sha256 = hashlib.sha256(test_content).hexdigest()

        # 3. Upload evidence file
        upload_res = client.post(
            f"/api/v1/cases/{case_id}/evidence",
            files={"file": ("incident_log.txt", io.BytesIO(test_content), "text/plain")},
            data={"file_type": "System Log", "notes": "Extracted from host during preliminary triage"},
        )
        assert upload_res.status_code == 201
        evidence = upload_res.json()

        # Verify Core Forensic Properties
        evidence_id = evidence["id"]
        assert evidence["filename"] == "incident_log.txt"
        assert evidence["sha256"] == expected_sha256
        assert evidence["file_type"] == "System Log"
        assert evidence["file_size_bytes"] == len(test_content)
        assert evidence["classification"] == "OBSERVED"
        assert evidence["status"] == "Observed Evidence"
        assert evidence["created_time"] is not None
        assert evidence["modified_time"] is not None
        assert evidence["accessed_time"] is not None
        assert evidence["evidence_number"].startswith("EVI-")

        # 4. Verify Case status was updated to "Evidence Collected"
        updated_case_res = client.get(f"/api/v1/cases/{case_id}")
        assert updated_case_res.status_code == 200
        assert updated_case_res.json()["status"] == "Evidence Collected"
        assert updated_case_res.json()["evidence_count"] >= 1

        # 5. Verify Hash Integrity Endpoint (Live Disk Check)
        verify_res = client.post(f"/api/v1/evidence/{evidence_id}/verify-hash")
        assert verify_res.status_code == 200
        verify_data = verify_res.json()
        assert verify_data["status"] == "MATCH"
        assert verify_data["stored_sha256"] == expected_sha256
        assert verify_data["computed_sha256"] == expected_sha256
        assert "Cryptographic integrity confirmed" in verify_data["notes"]

        # 6. Test Listing Evidence
        list_res = client.get(f"/api/v1/evidence?case_id={case_id}")
        assert list_res.status_code == 200
        evidence_list = list_res.json()
        assert len(evidence_list) >= 1
        assert any(e["id"] == evidence_id for e in evidence_list)

        # 7. Test Get Evidence Detail
        detail_res = client.get(f"/api/v1/evidence/{evidence_id}")
        assert detail_res.status_code == 200
        detail = detail_res.json()
        assert detail["id"] == evidence_id
        assert "metadata_json" in detail
        assert detail["metadata_json"]["readable_size"] is not None

        # 8. Test Deleting Evidence
        del_res = client.delete(f"/api/v1/evidence/{evidence_id}")
        assert del_res.status_code == 200
        assert del_res.json()["success"] is True

        # Verify not found after deletion
        not_found_res = client.get(f"/api/v1/evidence/{evidence_id}")
        assert not_found_res.status_code == 404

