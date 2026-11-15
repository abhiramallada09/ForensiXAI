import time
import subprocess
import sys
import httpx
from pathlib import Path

def test_phase3_workflow():
    print("=" * 60)
    print("  FORENSIX AI — PHASE 3 EVIDENCE PIPELINE DEMO")
    print("=" * 60)

    print("\n[1/5] Launching FastAPI backend server...")
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "backend.app.main:app", "--port", "8000", "--host", "127.0.0.1"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    client = httpx.Client(base_url="http://127.0.0.1:8000", timeout=10.0)

    try:
        # Wait for server
        for attempt in range(15):
            time.sleep(1)
            try:
                r = client.get("/api/v1/health")
                if r.status_code == 200:
                    print(f"Backend connected on attempt {attempt + 1}!")
                    break
            except Exception:
                pass

        # 2. Create Case
        print("\n[2/5] Creating Investigation Case...")
        case_res = client.post(
            "/api/v1/cases",
            json={
                "name": "Acquisition Incident - Host 104",
                "description": "Triage of suspicious file activity and volatile memory.",
                "investigator": "A. Abhiram",
                "status": "New"
            }
        )
        case_data = case_res.json()
        case_id = case_data["id"]
        case_num = case_data["case_number"]
        print(f"-> Case Created: {case_data['name']} (ID: {case_num})")

        # 3. Create Sample Evidence File
        print("\n[3/5] Generating Forensic Evidence Sample...")
        sample_path = Path("./data/working/evidence_sample_report.txt")
        sample_content = (
            b"FORENSIC EVIDENCE ACQUISITION RECORD\n"
            b"Case: " + case_num.encode() + b"\n"
            b"Investigator: A. Abhiram\n"
            b"Source: C:\\Windows\\System32\\drivers\\etc\\hosts\n"
            b"Acquisition Timestamp: 2026-11-14T15:40:00Z\n"
        )
        sample_path.write_bytes(sample_content)
        print(f"-> Sample written to: {sample_path} ({len(sample_content)} bytes)")

        # 4. Ingest Evidence File
        print("\n[4/5] Uploading & Ingesting Evidence into Vault...")
        with open(sample_path, "rb") as f:
            upload_res = client.post(
                f"/api/v1/cases/{case_id}/evidence",
                files={"file": ("evidence_sample_report.txt", f, "text/plain")},
                data={"file_type": "System Log", "notes": "Captured directly from endpoint hosts file"}
            )
        assert upload_res.status_code == 201
        evidence = upload_res.json()
        print("-> Ingestion SUCCESSFUL!")
        print(f"   Evidence Identifier : {evidence['evidence_number']}")
        print(f"   Filename            : {evidence['filename']}")
        print(f"   Classification      : {evidence['classification']}")
        print(f"   Status              : {evidence['status']}")
        print(f"   SHA-256 Hash        : {evidence['sha256']}")
        print(f"   Size                : {evidence['readable_size']}")
        print(f"   Created Time (UTC)  : {evidence['created_time']}")
        print(f"   Modified Time (UTC) : {evidence['modified_time']}")
        print(f"   Accessed Time (UTC) : {evidence['accessed_time']}")

        # 5. Verify Disk Cryptographic Integrity
        print("\n[5/5] Executing Live On-Disk Cryptographic Hash Verification...")
        verify_res = client.post(f"/api/v1/evidence/{evidence['id']}/verify-hash")
        assert verify_res.status_code == 200
        vdata = verify_res.json()
        print(f"-> Hash Status         : {vdata['status']}")
        print(f"-> Stored SHA-256      : {vdata['stored_sha256']}")
        print(f"-> On-Disk SHA-256     : {vdata['computed_sha256']}")
        print(f"-> Integrity Analysis  : {vdata['notes']}")
        assert vdata['status'] == "MATCH"

        print("\n" + "=" * 60)
        print("  PHASE 3 END-TO-END DEMONSTRATION VERIFIED SUCCESSFULLY!")
        print("=" * 60)

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()

if __name__ == "__main__":
    test_phase3_workflow()

