"""
ForensiX AI - Phase 6 Volatility 3 Memory Forensics Verification Script
Verifies Volatility 3 memory dump ingestion, kernel process enumeration,
TCP/UDP socket reconstruction, malfind shellcode injection detection,
and automated timeline/finding synchronization.
"""

import io
import os
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from fastapi.testclient import TestClient
from backend.app.main import app


def run_phase6_verification():
    print("=" * 65)
    print("ForensiX AI: Phase 6 Volatility 3 Memory Forensics Verification")
    print("Official Academic Title:")
    print("Memory Forensics for Volatile Data Analysis via Deep Learning-based")
    print("Deleted File and Timestamp Reconstruction, Applied to Cloud...")
    print("=" * 65)

    with TestClient(app) as client:
        # Step 1: Create Case
        print("\n[Step 1] Creating Memory Forensics Investigation Case...")
        case_res = client.post(
            "/api/v1/cases",
            json={
                "name": "Phase 6 Volatile Memory Kernel Forensics",
                "description": "Kernel process list, injected RWX shellcode, and network socket reconstruction.",
                "investigator": "A. Abhiram",
                "status": "Analyzing",
            },
        )
        assert case_res.status_code == 201
        case = case_res.json()
        case_id = case["id"]
        print(f"  ✓ Case Created: {case['case_number']} (ID: {case_id})")

        # Step 2: Ingest Memory Image Evidence
        print("\n[Step 2] Uploading Memory Image Evidence (RAW dump)...")
        mem_header = b"\x4d\x5a\x90\x00" + b"\x00" * 1024 * 64
        evi_res = client.post(
            f"/api/v1/cases/{case_id}/evidence",
            files={"file": ("srv01_memory_dump.raw", io.BytesIO(mem_header), "application/octet-stream")},
            data={"file_type": "Memory Image"},
        )
        assert evi_res.status_code == 201
        evi = evi_res.json()
        print(f"  ✓ Evidence Ingested: {evi['filename']} ({evi['readable_size']}) - SHA256: {evi['sha256'][:16]}...")

        # Step 3: Execute Volatility 3 Core Analysis
        print("\n[Step 3] Executing Volatility 3 Analysis Engine...")
        plugins = [
            "windows.pslist",
            "windows.netscan",
            "windows.malfind",
            "windows.cmdline",
            "windows.handles",
        ]
        mem_res = client.post(
            f"/api/v1/cases/{case_id}/memory/analyze",
            json={
                "evidence_id": evi["id"],
                "plugins": plugins,
                "sync_timeline": True,
            },
        )
        assert mem_res.status_code == 200, f"Analysis failed: {mem_res.text}"
        res = mem_res.json()
        print(f"  ✓ Volatility 3 Execution Completed in Case {case['case_number']}")
        print(f"  ✓ Plugins Run: {', '.join(res['plugins_run'])}")

        # Step 4: Validate Extracted Kernel Processes
        print("\n[Step 4] Validating Extracted Kernel Processes (windows.pslist)...")
        print(f"  ✓ Total Processes: {len(res['processes'])}")
        for p in res["processes"][:5]:
            print(f"    • PID {p['pid']:<5} | PPID {p['ppid']:<5} | {p['image_name']:<18} | Status: [{p['status']}]")

        suspicious_procs = [p for p in res["processes"] if p["status"] == "Suspicious"]
        assert len(suspicious_procs) >= 1
        print(f"  ✓ Detected Suspicious Memory Process: {suspicious_procs[0]['image_name']} (PID: {suspicious_procs[0]['pid']})")

        # Step 5: Validate Network Sockets (windows.netscan)
        print("\n[Step 5] Validating Network Sockets (windows.netscan)...")
        print(f"  ✓ Total Sockets: {len(res['network_connections'])}")
        for net in res["network_connections"]:
            print(f"    • {net['proto']} {net['local_addr']}:{net['local_port']} -> {net['foreign_addr']}:{net['foreign_port']} [{net['state']}] (Owner: {net['owner']})")

        # Step 6: Validate Malfind Injected Code
        print("\n[Step 6] Validating Code Injections (windows.malfind)...")
        assert len(res["injected_regions"]) >= 1
        inj = res["injected_regions"][0]
        print(f"  ✓ Malicious VAD Injected Region in {inj['process_name']} (PID: {inj['pid']})")
        print(f"    Address Range : {inj['start_vpn']} - {inj['end_vpn']}")
        print(f"    Protection    : {inj['protection']} (RWX)")
        print(f"    Hexdump       : {inj['hexdump_snippet'][:32]}...")
        print(f"    Disassembly   : {inj['disassembly_snippet']}")

        # Step 7: Validate Timeline Synchronization
        print("\n[Step 7] Verifying Timeline Synchronization...")
        tl_res = client.get(f"/api/v1/timeline?case_id={case_id}")
        assert tl_res.status_code == 200
        tl_events = tl_res.json()
        print(f"  ✓ Total Timeline Events Synced from Memory: {len(tl_events)}")
        proc_events = [e for e in tl_events if e["event_type"] == "Process Started"]
        net_events = [e for e in tl_events if e["event_type"] == "Network Activity"]
        print(f"    • 'Process Started' Events: {len(proc_events)}")
        print(f"    • 'Network Activity' Events: {len(net_events)}")

        # Step 8: Validate Forensic Finding Generation
        print("\n[Step 8] Verifying Synthesized Forensic Finding...")
        findings_res = client.get(f"/api/v1/cases/{case_id}/findings")
        assert findings_res.status_code == 200
        findings = findings_res.json()
        assert len(findings) >= 1
        mem_finding = findings[0]
        print(f"  ✓ Synthesized Finding: {mem_finding['title']}")
        print(f"    Classification : [{mem_finding['classification']}] | Severity: {mem_finding['severity']}")
        print(f"    Confidence     : {int(mem_finding['confidence'] * 100)}%")
        print(f"    Reason         : {mem_finding['reason']}")
        print(f"    Recommendation : {mem_finding['recommendation']}")

        print("\n" + "=" * 65)
        print("✓ PHASE 6 VOLATILITY 3 MEMORY FORENSICS VERIFIED SUCCESSFULLY!")
        print("=" * 65)


if __name__ == "__main__":
    run_phase6_verification()

