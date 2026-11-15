import io
from fastapi.testclient import TestClient
from backend.app.main import app


def test_ml_baseline_pipeline():
    with TestClient(app) as client:
        # 1. Verify ML models listing and automated initialization
        models_res = client.get("/api/v1/ml/models")
        assert models_res.status_code == 200
        models = models_res.json()
        assert len(models) >= 3

        model_names = [m["name"] for m in models]
        assert "ForensiX-RF-FileDetector" in model_names
        assert "ForensiX-IF-TimestampAnomaly" in model_names
        assert "ForensiX-LR-Baseline" in model_names

        # Verify metrics structure
        rf_meta = next(m for m in models if m["name"] == "ForensiX-RF-FileDetector")
        assert rf_meta["version"] == "1.0.0"
        assert "accuracy" in rf_meta["metrics"]
        assert "f1" in rf_meta["metrics"]
        assert len(rf_meta["feature_names"]) >= 6

        # 2. Test explicit retraining endpoint
        train_res = client.post("/api/v1/ml/train-baseline")
        assert train_res.status_code == 200
        train_data = train_res.json()
        assert train_data["status"] == "success"
        assert train_data["models_trained"] >= 3
        assert "feature_importances" in train_data

        # 3. Create a Case and upload evidence to evaluate
        case_res = client.post(
            "/api/v1/cases",
            json={
                "name": "Phase 7 AI Baseline Test Case",
                "description": "Evaluating ML Random Forest and Isolation Forest classifiers.",
                "investigator": "A. Abhiram",
                "status": "Analyzing",
            },
        )
        assert case_res.status_code == 201
        case_id = case_res.json()["id"]

        # Upload suspicious packed executable payload
        import os
        payload_bytes = b"MZ\x90\x00\x03\x00\x00\x00" + os.urandom(2048)
        upload_res = client.post(
            f"/api/v1/cases/{case_id}/evidence",
            files={"file": ("malware_beacon.exe", io.BytesIO(payload_bytes), "application/x-dosexec")},
            data={"file_type": "File"},
        )
        assert upload_res.status_code == 201
        evi_id = upload_res.json()["id"]

        # 4. Run Evidence Prediction with explainable AI
        pred_res = client.post(f"/api/v1/cases/{case_id}/ml/predict-evidence")
        assert pred_res.status_code == 200
        predictions = pred_res.json()
        assert len(predictions) >= 1

        pred = predictions[0]
        assert pred["evidence_id"] == evi_id
        assert pred["probability"] >= 0.50
        assert pred["is_anomaly"] is True
        assert pred["classification"] in ("SUSPICIOUS", "RECONSTRUCTED")
        assert len(pred["key_factors"]) >= 1
        assert "Random Forest" in pred["reason"]

        # 5. Add timeline events and test anomaly detection
        client.post(
            "/api/v1/timeline/events",
            json={
                "case_id": case_id,
                "evidence_id": evi_id,
                "timestamp": "2026-11-14T10:03:40Z",
                "timestamp_source": "Volatility 3 (windows.pslist)",
                "event_type": "Process Started",
                "artifact_category": "Memory Image",
                "description": "powershell.exe spawned with suspicious encoded arguments",
                "confidence": 0.95,
                "classification": "SUSPICIOUS",
            },
        )

        anom_res = client.post(f"/api/v1/cases/{case_id}/ml/detect-anomalies")
        assert anom_res.status_code == 200
        anomalies = anom_res.json()
        assert len(anomalies) >= 1
        assert "Isolation Forest" in anomalies[0]["reason"]

        # 6. Verify Case AI Summary endpoint matching UI Reference Card
        summary_res = client.get(f"/api/v1/cases/{case_id}/ml/summary")
        assert summary_res.status_code == 200
        summary = summary_res.json()
        assert summary["case_id"] == case_id
        assert 0 <= summary["deleted_file_probability"] <= 100
        assert 0 <= summary["manipulation_likelihood"] <= 100
        assert 0 <= summary["malware_indicator"] <= 100
        assert summary["confidence_score"] > 50
        assert summary["confidence_level"] in ("Very High", "High", "Moderate")
