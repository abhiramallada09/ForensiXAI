from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models.case import Case
from backend.app.models.evidence import Evidence
from backend.app.models.ml import MLModelRecord
from backend.app.ml.baseline import train_and_register_baseline_models
from backend.app.ml.predictor import (
    predict_evidence_item,
    detect_timeline_anomalies,
    get_case_ml_summary,
    ensure_models_loaded,
)
from backend.app.ml.deep_trainer import train_and_register_deep_model
from backend.app.ml.deep_predictor import (
    predict_evidence_deep,
    evaluate_case_deep_summary,
    get_deep_model_and_norm,
)
from backend.app.api.v1.schemas import (
    MLModelResponse,
    EvidencePredictionResponse,
    TimelineAnomalyResponse,
    MLCaseSummaryResponse,
    DeepPredictionResponse,
    DeepTrainResponse,
)

router = APIRouter(tags=["AI Machine Learning Baseline & Deep Learning"])


@router.get(
    "/ml/models",
    response_model=List[MLModelResponse],
    summary="List all registered machine learning baseline & PyTorch deep models and metrics",
)
def get_registered_models(db: Session = Depends(get_db)):
    ensure_models_loaded(db)
    get_deep_model_and_norm(db)
    models = db.query(MLModelRecord).order_by(MLModelRecord.name.asc()).all()
    return models


@router.post(
    "/ml/train-baseline",
    summary="Train or retrain baseline forensic machine learning models (Random Forest, Isolation Forest, Logistic Regression)",
)
def train_baseline(db: Session = Depends(get_db)):
    try:
        result = train_and_register_baseline_models(db)
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Model training failed: {str(e)}",
        )


@router.post(
    "/cases/{case_id}/ml/predict-evidence",
    response_model=List[EvidencePredictionResponse],
    summary="Run machine learning prediction and explainability analysis across case evidence",
)
def predict_case_evidence(case_id: str, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' not found.",
        )

    evidence_items = db.query(Evidence).filter(Evidence.case_id == case_id).all()
    if not evidence_items:
        return []

    predictions = []
    for evi in evidence_items:
        pred = predict_evidence_item(evi, db)
        predictions.append(EvidencePredictionResponse(**pred))

    return predictions


@router.post(
    "/cases/{case_id}/ml/detect-anomalies",
    response_model=List[TimelineAnomalyResponse],
    summary="Run Isolation Forest anomaly detection across timeline events",
)
def detect_case_anomalies(case_id: str, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' not found.",
        )

    anomalies = detect_timeline_anomalies(case_id, db)
    return [TimelineAnomalyResponse(**a) for a in anomalies]


@router.get(
    "/cases/{case_id}/ml/summary",
    response_model=MLCaseSummaryResponse,
    summary="Retrieve aggregated forensic AI probability bars matching UI design reference",
)
def get_case_summary(case_id: str, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' not found.",
        )

    summary_data = get_case_ml_summary(case_id, db)
    return MLCaseSummaryResponse(**summary_data)


# ----------------- Phase 8: PyTorch Deep Learning Endpoints -----------------

@router.post(
    "/ml/train-deep",
    response_model=DeepTrainResponse,
    summary="Train or retrain the ForensiX PyTorch Deep Multi-Task ResNet model",
)
def train_deep_network(epochs: int = Query(25, ge=5, le=100), db: Session = Depends(get_db)):
    try:
        result = train_and_register_deep_model(db, epochs=epochs)
        return DeepTrainResponse(**result)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Deep learning training failed: {str(e)}",
        )


@router.post(
    "/cases/{case_id}/ml/deep-evaluate",
    response_model=List[DeepPredictionResponse],
    summary="Run PyTorch deep neural network inference and feature attribution across case evidence",
)
def deep_evaluate_evidence(case_id: str, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' not found.",
        )

    evidence_items = db.query(Evidence).filter(Evidence.case_id == case_id).all()
    if not evidence_items:
        return []

    results = []
    for evi in evidence_items:
        pred = predict_evidence_deep(evi, db)
        results.append(DeepPredictionResponse(**pred))

    return results


@router.get(
    "/cases/{case_id}/ml/deep-summary",
    summary="Retrieve calibrated multi-task deep learning probabilities for UI dashboard cards",
)
def get_case_deep_summary_endpoint(case_id: str, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' not found.",
        )

    return evaluate_case_deep_summary(case_id, db)

