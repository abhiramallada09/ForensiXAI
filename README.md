# ForensiX AI

> **Official Academic Project Title:**
> *Memory Forensics for Volatile Data Analysis via Deep Learning-based Deleted File and Timestamp Reconstruction, Applied to Cloud Service Provider (SaaS/IaaS) Evidence Recovery*

ForensiX AI is an AI-assisted digital forensics and evidence reconstruction web application. Designed for digital forensic investigators, DFIR analysts, cybersecurity students, and academic researchers, it enables controlled investigation case management, evidence integrity verification, volatile memory analysis (via Volatility 3), chronological timeline reconstruction, and anti-forensic anomaly detection.

---

## Forensic Integrity & Safety Principles
1. **Never Execute Evidence:** The system functions strictly as an analytical pipeline; uploaded evidence files are stored read-only and never executed.
2. **Cryptographic Provenance:** Automatic SHA-256 calculation upon ingestion with immutable evidence registers.
3. **Probabilistic Transparency:** Clearly distinguishes between directly observed evidence and inferred or reconstructed events using five strict classifications:
   - `OBSERVED`: Directly present in the evidence.
   - `CORRELATED`: Supported by multiple independent artifacts.
   - `RECONSTRUCTED`: Inferred from available evidence.
   - `SUSPICIOUS`: Evidence contains an anomaly or inconsistency.
   - `UNKNOWN`: Insufficient evidence to make a conclusion.
4. **Research Prototype Notice:** Reconstruction results are probabilistic unless directly supported by evidence. AI findings require investigator verification.

---

## Technology Stack
- **Frontend:** React 18, TypeScript, Vite, Tailwind CSS, Lucide Icons, TanStack Query, React Router.
- **Backend:** Python 3.10+, FastAPI, Uvicorn, SQLAlchemy, Pydantic v2.
- **Database:** SQLite (local-first; migration-ready for PostgreSQL).
- **Forensic & ML Engines (Phases 3–14):** Volatility 3, Scikit-learn, PyTorch, ReportLab.

---

## Directory Structure
```
forensix-ai/
├── .skills/                          # Project specialized agent skills
├── backend/
│   ├── app/
│   │   ├── api/                      # REST API endpoints (v1)
│   │   ├── core/                     # Config, DB session, security
│   │   ├── models/                   # SQLAlchemy relational models
│   │   ├── services/                 # Business logic services
│   │   ├── forensics/                # Forensic extraction modules
│   │   ├── ai/                       # ML & DL models
│   │   ├── reconstruction/           # Timeline and trace reconstruction
│   │   ├── anti_forensics/           # Anti-forensics & anomaly checks
│   │   └── reports/                  # Report generators
│   └── tests/                        # Automated backend tests
├── frontend/                         # React + TypeScript + Tailwind UI
├── data/
│   ├── uploads/                      # Read-only original evidence storage
│   ├── working/                      # Analysis working copies
│   └── reports/                      # Exported forensic reports
├── models/                           # Serialized ML model weights
├── docs/                             # Academic & architectural documentation
├── scripts/                          # Automation and dataset scripts
├── .env.example
├── .gitignore
└── requirements.txt
```

---

## Quickstart & How to Run

You can run ForensiX AI either via the convenient one-click launch scripts or manually from terminal windows.

### Method 1: One-Click Launch Scripts (Windows)

1. **Start Backend Server:**
   Double-click `run_backend.bat` (or run `.\run_backend.bat` in PowerShell).
   - Starts the FastAPI backend at `http://127.0.0.1:8000`.
   - Swagger API documentation is available at `http://127.0.0.1:8000/docs`.

2. **Start Frontend Web Application:**
   Double-click `run_frontend.bat` (or run `.\run_frontend.bat` in PowerShell).
   - Starts Vite React development server at `http://localhost:5173`.

---

### Method 2: Manual Command-Line Startup

#### Terminal 1 — Backend (FastAPI):
```powershell
# From project root:
py -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
*(Alternatively, if using `.venv`: `.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload`)*

#### Terminal 2 — Frontend (React + Vite):
```powershell
cd frontend
npm install
npm run dev
```

Open your browser to:
- **Web Application UI:** [http://localhost:5173](http://localhost:5173)
- **Interactive REST API Docs:** [http://localhost:8000/docs](http://localhost:8000/docs)
- **API Health Check:** [http://localhost:8000/api/v1/health](http://localhost:8000/api/v1/health)

---

### Authentication & User Credentials

ForensiX AI includes complete user authentication and account registration storing investigator credentials in `database.db`:

- **Sign In & Sign Up:** Navigate to `http://localhost:5173/login`.
- **Pre-Seeded Default Accounts:**
  - **Lead Examiner:** `abhiram` (or `investigator@forensix.ai`) | Password: `Password123!`
  - **DFIR Analyst:** `analyst` (or `analyst@forensix.ai`) | Password: `Password123!`
- **Sign Up / Custom Accounts:** You can register custom or temporary investigator accounts via the **Sign Up** tab.
- **Account Database Reference:** A database accounts reference drawer is accessible on the login page to view registered accounts stored in `database.db`.

---

### Running Automated Verification & Tests

To execute the full test suite and workflow validation scripts:

```powershell
# Run all 31 automated test cases (using isolated test database)
py -m pytest -v backend/tests

# Verify Phase 13 (ReportLab PDF Generation & Sealing)
py scripts/verify_phase13_workflow.py

# Verify Phase 14 (Research Evaluation Benchmark & Demo Scenario Loader)
py scripts/verify_phase14_workflow.py

# Check frontend TypeScript compilation & production build
cd frontend
npm run build
```

---

### Real-Time Live Investigation Workflow

Once logged in at `http://localhost:5173`:
1. **Create Case:** Navigate to **Cases** and register a new case (e.g., `CAS-2026-LIVE`).
2. **Ingest Evidence:** Upload memory dumps (`.raw`), disk images (`.vhd`), or cloud audit logs (`.json`) into the cryptographically sealed evidence vault.
3. **Volatility Kernel Forensics:** Run process tree extraction, network socket scans, and unbacked executable RWX VAD detection.
4. **Deleted File & Carving Analysis:** Detect MFT remnants, closed handles, and carve header signatures (`4D 5A`, `50 4B`).
5. **Timestamp Reconstruction:** Correlate conflicting MACB timestamps and bound probable event windows $[T_{\text{start}}, T_{\text{end}}]$.
6. **Anti-Forensic Analysis:** Automatically detect timestomping, audit log wiping (Event 1102), and secure deletion commands.
7. **Cloud Correlation:** Cross-correlate AWS CloudTrail and Azure Activity records with endpoint memory processes.
8. **Forensic Examination Reports:** Compile and export standardized evidentiary PDF reports.

