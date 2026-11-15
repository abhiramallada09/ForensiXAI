import os
import sys
import uuid
from datetime import datetime, timezone

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.app.core.database import SessionLocal, Base, engine
from backend.app.models.case import Case
from backend.app.models.evidence import Evidence
from backend.app.models.finding import ForensicFinding
from backend.app.models.ml import MLModelRecord
from backend.app.ml.deep_model import ForensiXDeepNet
from backend.app.ml.deep_trainer import (
    train_and_register_deep_model,
    MODELS_DIR,
    DEEP_FEATURE_COLUMNS,
)
from backend.app.ml.deep_predictor import (
    predict_evidence_deep,
    evaluate_case_deep_summary,
    get_deep_model_and_norm,
)


def run_phase8_verification():
    print("=" * 80)
    print("ForensiX AI - Phase 8: PyTorch Deep Learning Engine Verification")
    print("Official Academic Title:")
    print("Memory Forensics for Volatile Data Analysis via Deep Learning-based")
    print("Deleted File and Timestamp Reconstruction, Applied to Cloud Evidence")
    print("=" * 80)

    db = SessionLocal()
    try:
        # Step 1: Train & Register ForensiXDeepNet
        print("\n[Step 1] Training & Checkpointing ForensiXDeepNet (PyTorch 2.15+)...")
        train_res = train_and_register_deep_model(db, epochs=15)
        print(f"  -> Model Name: {train_res['model_name']}")
        print(f"  -> Total Trainable Parameters: {train_res['architecture_summary']['trainable_parameters']}")
        print(f"  -> Deleted Task Accuracy: {train_res['metrics']['deleted_task_accuracy'] * 100:.1f}%")
        print(f"  -> Manipulation Task Accuracy: {train_res['metrics']['manipulation_task_accuracy'] * 100:.1f}%")
        print(f"  -> Malware Task Accuracy: {train_res['metrics']['malware_task_accuracy'] * 100:.1f}%")
        print(f"  -> Final Epoch Loss: {train_res['metrics']['final_epoch_loss']:.4f}")
        assert os.path.exists(os.path.join(MODELS_DIR, "forensix_dl_v1.pt")), "Deep model weights file missing!"
        assert os.path.exists(os.path.join(MODELS_DIR, "forensix_dl_norm_v1.json")), "Normalization config missing!"

        # Step 2: Create Test Investigation Case
        c_num = f"CASE-DL-{uuid.uuid4().hex[:6].upper()}"
        print(f"\n[Step 2] Creating Case: {c_num}...")
        test_case = Case(
            case_number=c_num,
            name="Operation Cobalt Volatile Artifact & Remnant Deep Analysis",
            investigator="A. Abhiram",
            description="Deep learning multi-task forensic reconstruction of volatile memory and unallocated disk slack space",
            status="Analyzing",
        )
        db.add(test_case)
        db.commit()

        # Step 3: Add Memory Finding (RWX VAD injection)
        vad_finding = ForensicFinding(
            case_id=test_case.id,
            title="Kernel RWX Memory Page Shellcode Injection (PID 2844)",
            finding_type="Malware Activity",
            reason="Volatility 3 windows.malfind detected PAGE_EXECUTE_READWRITE protection with MZ header in unmapped VAD",
            confidence=0.96,
            classification="SUSPICIOUS",
            severity="Critical",
        )
        db.add(vad_finding)
        db.commit()

        # Step 4: Add Sample Evidence Artifacts
        print("\n[Step 3] Staging Multi-Source Forensic Artifacts for Deep Inference...")
        evi1 = Evidence(
            case_id=test_case.id,
            evidence_number=f"EVI-{uuid.uuid4().hex[:4].upper()}",
            filename="svchost_injected.exe",
            stored_path="svchost_injected.exe",
            file_size_bytes=524288,
            sha256="a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
            file_type="File",
            created_time=datetime(2026, 11, 14, 10, 0, 0, tzinfo=timezone.utc),
            modified_time=datetime(2026, 11, 14, 9, 30, 0, tzinfo=timezone.utc),  # -30m timestomp
            accessed_time=datetime(2026, 11, 14, 10, 5, 0, tzinfo=timezone.utc),
            metadata_json={"entropy": 7.91, "timestomped": True, "deleted_indicator": True},
        )
        evi2 = Evidence(
            case_id=test_case.id,
            evidence_number=f"EVI-{uuid.uuid4().hex[:4].upper()}",
            filename="legitimate_report.pdf",
            stored_path="legitimate_report.pdf",
            file_size_bytes=104857,
            sha256="b2c3d4e5f6a10718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
            file_type="File",
            created_time=datetime(2026, 11, 14, 8, 0, 0, tzinfo=timezone.utc),
            modified_time=datetime(2026, 11, 14, 8, 15, 0, tzinfo=timezone.utc),
            accessed_time=datetime(2026, 11, 14, 8, 20, 0, tzinfo=timezone.utc),
            metadata_json={"entropy": 4.35},
        )
        db.add_all([evi1, evi2])
        db.commit()

        # Step 5: Run Deep Neural Network Inference on Evidence
        print("\n[Step 4] Running Forward Pass Through ForensiXDeepNet...")
        pred1 = predict_evidence_deep(evi1, db)
        pred2 = predict_evidence_deep(evi2, db)

        print("\n--- Evidence 1: svchost_injected.exe (Anomalous Remnant) ---")
        print(f"  -> Deleted File Probability: {pred1['deleted_file_probability'] * 100:.1f}%")
        print(f"  -> Manipulation Likelihood: {pred1['manipulation_likelihood'] * 100:.1f}%")
        print(f"  -> Malware Indicator:       {pred1['malware_indicator'] * 100:.1f}%")
        print(f"  -> Calibrated Confidence:   {pred1['confidence'] * 100:.0f}%")
        print(f"  -> Safety Classification:   {pred1['classification']} ({pred1['severity']} Severity)")
        print(f"  -> Explainable AI Factors:  {'; '.join(pred1['key_factors'])}")
        assert pred1["classification"] in {"SUSPICIOUS", "RECONSTRUCTED"}, "Expected high-risk classification!"

        print("\n--- Evidence 2: legitimate_report.pdf (Benign Document) ---")
        print(f"  -> Deleted File Probability: {pred2['deleted_file_probability'] * 100:.1f}%")
        print(f"  -> Manipulation Likelihood: {pred2['manipulation_likelihood'] * 100:.1f}%")
        print(f"  -> Malware Indicator:       {pred2['malware_indicator'] * 100:.1f}%")
        print(f"  -> Safety Classification:   {pred2['classification']}")
        assert pred2["classification"] == "OBSERVED", "Expected OBSERVED for benign file!"

        # Step 6: Case Summary Multi-Task Aggregation
        print("\n[Step 5] Evaluating Aggregated Case Deep Summary (UI Alignment)...")
        case_summary = evaluate_case_deep_summary(test_case.id, db)
        print(f"  -> Deleted File Probability: {case_summary['deleted_file_probability']}%")
        print(f"  -> Manipulation Likelihood:  {case_summary['manipulation_likelihood']}%")
        print(f"  -> Malware Indicator:        {case_summary['malware_indicator']}%")
        print(f"  -> Overall Confidence Score: {case_summary['confidence_score']}% ({case_summary['confidence_label']})")
        print(f"  -> Active Model:             {case_summary['model_name']} (v{case_summary['model_version']})")
        assert case_summary["deep_learning_active"] is True, "Deep learning should be marked active!"
        assert case_summary["confidence_score"] >= 80, "Expected high confidence score!"

        print("\n" + "=" * 80)
        print("PHASE 8 DEEP LEARNING VERIFICATION: ALL CHECKS PASSED [SUCCESS]")
        print("=" * 80)

    finally:
        db.close()


if __name__ == "__main__":
    run_phase8_verification()
