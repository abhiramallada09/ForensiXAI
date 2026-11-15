import os
import sys

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.app.core.database import SessionLocal
from backend.app.models.case import Case
from backend.app.models.evidence import Evidence
from backend.app.models.deleted_file import DeletedFileRecord
from backend.app.models.timestamp_reconstruction import TimestampReconstructionRecord
from backend.app.models.anti_forensic import AntiForensicIndicatorRecord
from backend.app.models.cloud import CloudEvidenceRecord, CloudCorrelationRecord
from backend.app.evaluation.benchmark import run_comparative_benchmark
from backend.app.evaluation.demo_loader import load_complete_demo_scenario
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def run_phase14_verification():
    print("=" * 80)
    print("ForensiX AI - Phase 14: Research Evaluation, Demo Mode & Final Verification")
    print("Official Academic Title:")
    print("Memory Forensics for Volatile Data Analysis via Deep Learning-based")
    print("Deleted File and Timestamp Reconstruction, Applied to Cloud Evidence")
    print("=" * 80)

    db = SessionLocal()
    try:
        # Step 1: Run Scientific Comparative Benchmark
        print("\n[Step 1] Running Scientific Model Benchmark (DeepNet vs Classical Baselines)...")
        b_res = run_comparative_benchmark(db, n_eval_samples=400)
        print(f"  -> Evaluated on {b_res['eval_dataset_size']} synthetic forensic feature tensors across {b_res['features_evaluated']} dimensions.")
        print(f"  -> ForensiXDeepNet Overall Accuracy: {b_res['overall_deep_accuracy']}%")
        print(f"  -> ForensiXDeepNet Overall F1-Score: {b_res['overall_deep_f1']}%")
        print(f"  -> Inference Latency per 100 samples: {b_res['deep_latency_ms']} ms")

        print("\n  [Model Performance Comparison Matrix]:")
        for row in b_res["comparison_table"]:
            print(f"   * {row['model_name']:<35} | Acc: {row['accuracy']:>5.1f}% | Prec: {row['precision']:>5.1f}% | Rec: {row['recall']:>5.1f}% | F1: {row['f1_score']:>5.1f}% | Latency: {row['latency_per_100_ms']:>5.2f}ms")

        print("\n  [Multi-Task Breakdown]:")
        for t in b_res["task_breakdown"]:
            print(f"   * [{t['task_id']}] {t['task_name']:<35} -> Acc: {t['accuracy']:>5.1f}%, F1: {t['f1_score']:>5.1f}%")

        assert b_res["overall_deep_accuracy"] >= 80.0
        assert len(b_res["comparison_table"]) == 4

        # Step 2: Load One-Click Demonstration Scenario
        print("\n[Step 2] Ingesting Complete Demonstration Incident Scenario (DEMO-NIMBUS-2026)...")
        demo_case = load_complete_demo_scenario(db)
        print(f"  -> Successfully Loaded Case: {demo_case.case_number} - {demo_case.name}")

        # Check all modules
        ev_count = db.query(Evidence).filter(Evidence.case_id == demo_case.id).count()
        del_count = db.query(DeletedFileRecord).filter(DeletedFileRecord.case_id == demo_case.id).count()
        time_count = db.query(TimestampReconstructionRecord).filter(TimestampReconstructionRecord.case_id == demo_case.id).count()
        anti_count = db.query(AntiForensicIndicatorRecord).filter(AntiForensicIndicatorRecord.case_id == demo_case.id).count()
        cloud_count = db.query(CloudEvidenceRecord).filter(CloudEvidenceRecord.case_id == demo_case.id).count()
        cloud_corr_count = db.query(CloudCorrelationRecord).filter(CloudCorrelationRecord.case_id == demo_case.id).count()

        print(f"  -> Evidence Files: {ev_count} (Raw memory image, NTFS VHD, CloudTrail JSON)")
        print(f"  -> Reconstructed Deleted Remnants: {del_count} (PE header 4D 5A, ZIP header 50 4B)")
        print(f"  -> Probable Event Windows: {time_count}")
        print(f"  -> Anti-Forensic Flags: {anti_count} (Log wiping 1102, sdelete CLI, RWX VAD injection)")
        print(f"  -> Cloud Audit Records: {cloud_count} (AWS StopLogging, DeleteBucket, Azure diagnostic delete)")
        print(f"  -> Endpoint-to-Cloud Correlations: {cloud_corr_count}")

        assert ev_count == 3
        assert del_count == 2
        assert time_count == 2
        assert anti_count == 3
        assert cloud_count == 3
        assert cloud_corr_count == 2

        # Step 3: Test REST APIs
        print("\n[Step 3] Testing Evaluation & Demo REST API Endpoints...")

        # 3a: GET /api/v1/evaluation/benchmark
        res_bench = client.get("/api/v1/evaluation/benchmark")
        assert res_bench.status_code == 200
        bench_json = res_bench.json()
        print(f"  -> GET /evaluation/benchmark returned {len(bench_json['comparison_table'])} models and conclusion.")

        # 3b: POST /api/v1/demo/load-scenario
        res_demo = client.post("/api/v1/demo/load-scenario")
        assert res_demo.status_code == 200
        demo_json = res_demo.json()
        print(f"  -> POST /demo/load-scenario returned case ID: {demo_json['id']} ({demo_json['case_number']})")
        assert demo_json["case_number"] == "DEMO-NIMBUS-2026"

        print("\n" + "=" * 80)
        print(">>> SUCCESS: Phase 14 Research Evaluation & Demo Mode is 100% verified!")
        print("=" * 80)

    finally:
        db.close()


if __name__ == "__main__":
    run_phase14_verification()

