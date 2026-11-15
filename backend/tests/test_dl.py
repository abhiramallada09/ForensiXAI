import os
import uuid
import torch
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.core.database import get_db, Base, engine, SessionLocal
from backend.app.models.case import Case
from backend.app.models.evidence import Evidence
from backend.app.ml.deep_model import ForensiXDeepNet
from backend.app.ml.deep_trainer import (
    train_and_register_deep_model,
    DEEP_FEATURE_COLUMNS,
    MODELS_DIR,
)
from backend.app.ml.deep_predictor import (
    predict_evidence_deep,
    evaluate_case_deep_summary,
    extract_evidence_deep_features,
)

client = TestClient(app)


def test_deep_model_architecture_and_forward():
    """Verify PyTorch model structure, parameter counting, and forward multi-task shapes."""
    model = ForensiXDeepNet(input_dim=12, hidden_dim=64)
    model.eval()

    summary = model.get_layer_summary()
    assert summary["model_name"] == "ForensiXDeepNet"
    assert summary["input_dimension"] == 12
    assert summary["total_parameters"] > 1000

    batch_x = torch.randn(4, 12)
    with torch.no_grad():
        out = model(batch_x)

    assert "deleted_probability" in out
    assert "manipulation_likelihood" in out
    assert "malware_indicator" in out
    assert "confidence_score" in out
    assert "latent_representation" in out

    assert out["deleted_probability"].shape == (4,)
    assert (out["deleted_probability"] >= 0.0).all() and (out["deleted_probability"] <= 1.0).all()
    assert (out["confidence_score"] >= 0.0).all() and (out["confidence_score"] <= 1.0).all()


def test_train_and_register_deep_model():
    """Test training and database registration of ForensiX DeepNet."""
    db = SessionLocal()
    try:
        res = train_and_register_deep_model(db, epochs=5)
        assert res["status"] == "success"
        assert res["model_name"] == "ForensiX-DeepNet-v1"
        assert "metrics" in res
        assert res["metrics"]["accuracy"] >= 0.70
        assert os.path.exists(os.path.join(MODELS_DIR, "forensix_dl_v1.pt"))
        assert os.path.exists(os.path.join(MODELS_DIR, "forensix_dl_norm_v1.json"))
    finally:
        db.close()


def test_deep_evaluate_and_explainability():
    """Verify inference, safety classification, and explainable key factors on evidence."""
    db = SessionLocal()
    try:
        c_num = f"CASE-DL-{uuid.uuid4().hex[:6]}"
        case = Case(
            case_number=c_num,
            name="Deep Learning Forensics Test Case",
            investigator="Investigator Deep",
            status="Analyzing",
        )
        db.add(case)
        db.commit()

        # Anomalous payload with negative delta (timestomped) and packed entropy
        evidence = Evidence(
            case_id=case.id,
            evidence_number=f"EVI-DL-{uuid.uuid4().hex[:6]}",
            filename="trojan_payload.exe",
            stored_path="trojan_payload.exe",
            file_size_bytes=1048576,
            sha256="c"*64,
            file_type="File",
            created_time=datetime(2026, 11, 14, 10, 30, 0, tzinfo=timezone.utc),
            modified_time=datetime(2026, 11, 14, 10, 10, 0, tzinfo=timezone.utc),  # -20min timestomp
            metadata_json={"entropy": 7.82, "timestomped": True},
        )
        db.add(evidence)
        db.commit()

        pred = predict_evidence_deep(evidence, db)
        assert pred["evidence_id"] == evidence.id
        assert pred["filename"] == "trojan_payload.exe"
        assert pred["deleted_file_probability"] >= 0.40
        assert pred["confidence"] >= 0.60
        assert pred["classification"] in {"SUSPICIOUS", "RECONSTRUCTED"}
        assert any("entropy" in factor.lower() or "timestomp" in factor.lower() for factor in pred["key_factors"])

        # Test case deep summary aggregation
        summary = evaluate_case_deep_summary(case.id, db)
        assert summary["case_id"] == case.id
        assert summary["confidence_score"] >= 80
        assert summary["deep_learning_active"] is True
    finally:
        db.close()


def test_deep_rest_endpoints():
    """Verify FastAPI endpoints for deep learning training, inference, and summary."""
    # Create case
    case_res = client.post("/api/v1/cases/", json={
        "name": "DL API Test Case",
        "investigator": "Dr. Investigator",
        "description": "Validation of Deep Learning Endpoints",
    })
    assert case_res.status_code == 201
    case_id = case_res.json()["id"]

    # Upload or attach evidence
    evidence_res = client.post(f"/api/v1/cases/{case_id}/evidence", files={
        "file": ("malicious_beacon.exe", b"MZ\x90\x00" + os.urandom(2048), "application/octet-stream")
    })
    assert evidence_res.status_code == 201

    # Test /cases/{id}/ml/deep-evaluate
    eval_res = client.post(f"/api/v1/cases/{case_id}/ml/deep-evaluate")
    assert eval_res.status_code == 200
    eval_data = eval_res.json()
    assert len(eval_data) >= 1
    assert "deleted_file_probability" in eval_data[0]
    assert "malware_indicator" in eval_data[0]
    assert "reason" in eval_data[0]

    # Test /cases/{id}/ml/deep-summary
    summary_res = client.get(f"/api/v1/cases/{case_id}/ml/deep-summary")
    assert summary_res.status_code == 200
    summary_data = summary_res.json()
    assert summary_data["deep_learning_active"] is True
    assert summary_data["model_name"] == "ForensiX-DeepNet-v1"
    assert summary_data["evaluated_evidence_count"] >= 1
