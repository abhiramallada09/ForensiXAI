import io
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from backend.app.main import app


def test_timeline_engine():
    with TestClient(app) as client:
        # 1. Create parent case
        case_res = client.post(
            "/api/v1/cases",
            json={
                "name": "Phase 4 Timeline Engine Case",
                "description": "Testing chronological event extraction and correlation.",
                "investigator": "A. Abhiram",
                "status": "New",
            },
        )
        assert case_res.status_code == 201
        case_id = case_res.json()["id"]

        # 2. Upload file to trigger automatic MACB timeline event generation
        file_bytes = b"TIMELINE_TEST_LOG_ENTRY_2026\n"
        upload_res = client.post(
            f"/api/v1/cases/{case_id}/evidence",
            files={"file": ("auth_audit.log", io.BytesIO(file_bytes), "text/plain")},
            data={"file_type": "System Log"},
        )
        assert upload_res.status_code == 201
        evidence_id = upload_res.json()["id"]

        # 3. Verify automatic timeline events exist for the case
        tl_res = client.get(f"/api/v1/timeline?case_id={case_id}")
        assert tl_res.status_code == 200
        events = tl_res.json()
        assert len(events) >= 1
        event_types = [e["event_type"] for e in events]
        assert "File Modified" in event_types or "File Created" in event_types

        # 4. Add a Correlated Event
        now = datetime.now(timezone.utc)
        corr_payload = {
            "case_id": case_id,
            "evidence_id": evidence_id,
            "timestamp": (now - timedelta(minutes=5)).isoformat(),
            "timestamp_source": "Volatility 3 (windows.pslist)",
            "event_type": "Process Started",
            "artifact_category": "Memory Image",
            "description": "Suspicious process powershell.exe (PID 5844) spawned by explorer.exe",
            "confidence": 0.95,
            "classification": "CORRELATED",
        }
        create_corr = client.post("/api/v1/timeline/events", json=corr_payload)
        assert create_corr.status_code == 201
        corr_event = create_corr.json()
        assert corr_event["classification"] == "CORRELATED"
        assert corr_event["event_type"] == "Process Started"
        assert corr_event["source_evidence_filename"] == "auth_audit.log"

        # 5. Add a Reconstructed Event with an Event Window
        recon_payload = {
            "case_id": case_id,
            "timestamp": (now - timedelta(minutes=10)).isoformat(),
            "timestamp_end": (now - timedelta(minutes=8)).isoformat(),
            "timestamp_source": "Deep Learning Deleted File Remnant Model",
            "event_type": "File Deleted",
            "artifact_category": "File",
            "description": "Probable deleted artifact invoice_2026_receipt.pdf in unallocated memory block",
            "confidence": 0.84,
            "classification": "RECONSTRUCTED",
        }
        create_recon = client.post("/api/v1/timeline/events", json=recon_payload)
        assert create_recon.status_code == 201
        recon_event = create_recon.json()
        assert recon_event["classification"] == "RECONSTRUCTED"
        assert recon_event["timestamp_end"] is not None

        # 6. Test Filtering by classification
        recon_filter = client.get(f"/api/v1/timeline?case_id={case_id}&classification=RECONSTRUCTED")
        assert recon_filter.status_code == 200
        recon_items = recon_filter.json()
        assert len(recon_items) == 1
        assert recon_items[0]["classification"] == "RECONSTRUCTED"

        # 7. Test Filtering by event_type
        proc_filter = client.get(f"/api/v1/timeline?case_id={case_id}&event_type=Process Started")
        assert proc_filter.status_code == 200
        assert len(proc_filter.json()) == 1

        # 8. Test Chronological Ordering (ASC vs DESC)
        asc_res = client.get(f"/api/v1/timeline?case_id={case_id}&order=asc")
        assert asc_res.status_code == 200
        asc_events = asc_res.json()
        assert len(asc_events) >= 2
        # Earliest event should be first in ASC
        assert asc_events[0]["timestamp"] <= asc_events[-1]["timestamp"]

        # 9. Test Rebuild/Sync Endpoint
        rebuild_res = client.post(f"/api/v1/cases/{case_id}/timeline/rebuild")
        assert rebuild_res.status_code == 200
        assert rebuild_res.json()["success"] is True

        # 10. Test Event Drill-Down
        get_single = client.get(f"/api/v1/timeline/events/{corr_event['id']}")
        assert get_single.status_code == 200
        assert get_single.json()["id"] == corr_event["id"]

        # 11. Test Event Deletion
        del_res = client.delete(f"/api/v1/timeline/events/{recon_event['id']}")
        assert del_res.status_code == 200
        assert del_res.json()["success"] is True

        # Verify deleted
        assert client.get(f"/api/v1/timeline/events/{recon_event['id']}").status_code == 404

