import io
from fastapi.testclient import TestClient
from backend.app.main import app


def test_volatility_memory_analysis():
    with TestClient(app) as client:
        # 1. Create a forensic investigation case
        case_res = client.post(
            "/api/v1/cases",
            json={
                "name": "Phase 6 Volatility Memory Forensics Case",
                "description": "Extracting kernel memory processes, network sockets, and shellcode injections.",
                "investigator": "A. Abhiram",
                "status": "Analyzing",
            },
        )
        assert case_res.status_code == 201
        case_id = case_res.json()["id"]

        # 2. Upload a memory image file
        mem_bytes = b"\x00" * 1024 * 64  # 64 KB memory test header
        upload_res = client.post(
            f"/api/v1/cases/{case_id}/evidence",
            files={"file": ("endpoint_mem.raw", io.BytesIO(mem_bytes), "application/octet-stream")},
            data={"file_type": "Memory Image"},
        )
        assert upload_res.status_code == 201
        evidence_id = upload_res.json()["id"]

        # 3. Trigger Memory Analysis with all 5 core plugins
        analyze_res = client.post(
            f"/api/v1/cases/{case_id}/memory/analyze",
            json={
                "evidence_id": evidence_id,
                "plugins": [
                    "windows.pslist",
                    "windows.netscan",
                    "windows.malfind",
                    "windows.cmdline",
                    "windows.handles",
                ],
                "sync_timeline": True,
            },
        )
        if analyze_res.status_code != 200:
            print("ERROR IN ANALYZE:", analyze_res.text)
        assert analyze_res.status_code == 200
        mem_data = analyze_res.json()

        assert mem_data["case_id"] == case_id
        assert mem_data["evidence_id"] == evidence_id
        assert len(mem_data["processes"]) >= 5
        assert len(mem_data["network_connections"]) >= 2
        assert len(mem_data["injected_regions"]) >= 1
        assert len(mem_data["cmdlines"]) >= 1
        assert len(mem_data["handles"]) >= 1
        assert "Volatility 3 Framework" in mem_data["raw_output"]
        assert mem_data["timeline_events_created"] >= 5
        assert mem_data["findings_created"] >= 1

        # Check process details
        proc_names = [p["image_name"] for p in mem_data["processes"]]
        assert "System" in proc_names
        assert "powershell.exe" in proc_names

        # Check injection details
        inj = mem_data["injected_regions"][0]
        assert inj["protection"] == "PAGE_EXECUTE_READWRITE"
        assert inj["process_name"] == "powershell.exe"

        # 4. Query latest analysis endpoint
        latest_res = client.get(f"/api/v1/cases/{case_id}/memory/latest")
        assert latest_res.status_code == 200
        latest_data = latest_res.json()
        assert latest_data["id"] == mem_data["id"]

        # 5. Query sub-endpoints
        proc_res = client.get(f"/api/v1/cases/{case_id}/memory/processes")
        assert proc_res.status_code == 200
        assert len(proc_res.json()) >= 5

        net_res = client.get(f"/api/v1/cases/{case_id}/memory/network")
        assert net_res.status_code == 200
        assert len(net_res.json()) >= 2

        inj_res = client.get(f"/api/v1/cases/{case_id}/memory/injections")
        assert inj_res.status_code == 200
        assert len(inj_res.json()) >= 1

        # 6. Verify Timeline has integrated the memory events
        tl_res = client.get(f"/api/v1/timeline?case_id={case_id}&event_type=Process Started")
        assert tl_res.status_code == 200
        tl_events = tl_res.json()
        assert len(tl_events) >= 5
        assert any("Volatility 3" in e["timestamp_source"] for e in tl_events)

        # 7. Verify Findings has integrated the critical injection finding
        findings_res = client.get(f"/api/v1/cases/{case_id}/findings")
        assert findings_res.status_code == 200
        findings = findings_res.json()
        assert any("Memory Injection" in f["title"] for f in findings)
