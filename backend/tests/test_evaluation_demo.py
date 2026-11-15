import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.main import app
from backend.app.core.database import SessionLocal, Base, engine
from backend.app.models.case import Case
from backend.app.models.evidence import Evidence
from backend.app.models.memory import MemoryAnalysisRecord
from backend.app.models.deleted_file import DeletedFileRecord
from backend.app.models.timestamp_reconstruction import TimestampReconstructionRecord
from backend.app.models.anti_forensic import AntiForensicIndicatorRecord
from backend.app.models.cloud import CloudEvidenceRecord
from backend.app.evaluation.benchmark import run_comparative_benchmark
from backend.app.evaluation.demo_loader import load_complete_demo_scenario

client = TestClient(app)


@pytest.fixture(scope="module")
def setup_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    yield db
    db.close()


def test_comparative_benchmark_engine(setup_db: Session):
    db = setup_db
    benchmark_data = run_comparative_benchmark(db, n_eval_samples=200)

    assert benchmark_data is not None
    assert benchmark_data["overall_deep_accuracy"] >= 80.0
    assert len(benchmark_data["comparison_table"]) == 4
    assert len(benchmark_data["task_breakdown"]) == 3
    assert "ForensiXDeepNet" in benchmark_data["comparison_table"][0]["model_name"]


def test_demo_scenario_loader(setup_db: Session):
    db = setup_db
    demo_case = load_complete_demo_scenario(db)

    assert demo_case is not None
    assert demo_case.case_number == "DEMO-NIMBUS-2026"
    assert "Nimbus" in demo_case.name

    # Check that all 8 modules are populated
    ev_count = db.query(Evidence).filter(Evidence.case_id == demo_case.id).count()
    assert ev_count == 3

    mem_count = db.query(MemoryAnalysisRecord).filter(MemoryAnalysisRecord.case_id == demo_case.id).count()
    assert mem_count == 1

    del_count = db.query(DeletedFileRecord).filter(DeletedFileRecord.case_id == demo_case.id).count()
    assert del_count == 2

    time_count = db.query(TimestampReconstructionRecord).filter(TimestampReconstructionRecord.case_id == demo_case.id).count()
    assert time_count == 2

    anti_count = db.query(AntiForensicIndicatorRecord).filter(AntiForensicIndicatorRecord.case_id == demo_case.id).count()
    assert anti_count == 3

    cloud_count = db.query(CloudEvidenceRecord).filter(CloudEvidenceRecord.case_id == demo_case.id).count()
    assert cloud_count == 3


def test_evaluation_and_demo_rest_api(setup_db: Session):
    # Test GET /api/v1/evaluation/benchmark
    res_bench = client.get("/api/v1/evaluation/benchmark")
    assert res_bench.status_code == 200
    b_data = res_bench.json()
    assert "comparison_table" in b_data
    assert "task_breakdown" in b_data

    # Test POST /api/v1/demo/load-scenario
    res_demo = client.post("/api/v1/demo/load-scenario")
    assert res_demo.status_code == 200
    demo_data = res_demo.json()
    assert demo_data["case_number"] == "DEMO-NIMBUS-2026"
    assert "id" in demo_data

