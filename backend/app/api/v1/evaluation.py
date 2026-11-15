from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.evaluation.benchmark import run_comparative_benchmark
from backend.app.evaluation.demo_loader import load_complete_demo_scenario
from backend.app.api.v1.schemas import CaseResponse

router = APIRouter(tags=["Research Benchmark & Evaluation"])


@router.get(
    "/evaluation/benchmark",
    summary="Execute comparative research benchmark: PyTorch DeepNet vs Classical ML Baselines",
)
def get_research_benchmark(db: Session = Depends(get_db)) -> Dict[str, Any]:
    try:
        results = run_comparative_benchmark(db, n_eval_samples=500)
        return results
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Benchmark execution failed: {str(e)}",
        )


@router.post(
    "/demo/load-scenario",
    response_model=CaseResponse,
    summary="Instantly populate complete end-to-end forensic demonstration scenario",
)
def load_demo_case(db: Session = Depends(get_db)):
    try:
        case = load_complete_demo_scenario(db)
        return CaseResponse.model_validate(case)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to load demo scenario: {str(e)}",
        )

