import time
import subprocess
import sys
import httpx

def verify():
    print("[1/3] Launching FastAPI backend server on port 8000...")
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "backend.app.main:app", "--port", "8000", "--host", "127.0.0.1"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    client = httpx.Client(base_url="http://127.0.0.1:8000", timeout=5.0)

    try:
        # Retry connection for up to 15 seconds
        connected = False
        print("[2/3] Waiting for server to become responsive...")
        for attempt in range(15):
            time.sleep(1)
            try:
                r_root = client.get("/")
                if r_root.status_code == 200:
                    connected = True
                    print(f"Connected on attempt {attempt + 1}!")
                    print("Root response:", r_root.status_code, r_root.json())
                    break
            except Exception:
                pass

        if not connected:
            stderr_out = proc.stderr.read().decode(errors="ignore") if proc.stderr else ""
            raise RuntimeError(f"Server failed to start within 15 seconds. Stderr: {stderr_out}")

        print("[3/3] Probing GET /api/v1/status ...")
        r_status = client.get("/api/v1/status")
        print("Status response:", r_status.status_code, r_status.json())
        assert r_status.status_code == 200
        assert r_status.json()["status"] == "ONLINE"
        assert r_status.json()["database_connected"] is True

        print(">>> Backend verification SUCCESSFUL! <<<")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()

if __name__ == "__main__":
    verify()
