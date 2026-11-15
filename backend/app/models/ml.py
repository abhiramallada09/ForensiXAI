import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, JSON
from backend.app.core.database import Base


def utc_now():
    return datetime.now(timezone.utc)


class MLModelRecord(Base):
    """
    Stores registered ML baseline & deep-learning model metadata,
    versioning, training benchmarks, and explainability feature weights.
    """
    __tablename__ = "ml_models"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(128), nullable=False, index=True)
    version = Column(String(32), nullable=False, default="1.0.0")
    algorithm = Column(String(64), nullable=False)  # RandomForest, IsolationForest, LogisticRegression, PyTorch
    task_type = Column(String(64), nullable=False)  # deleted_file_detection, timestamp_anomaly_detection
    training_dataset = Column(String(255), nullable=False)
    
    # Performance metrics
    metrics = Column(JSON, nullable=False)  # {"accuracy": 0.94, "precision": 0.92, "recall": 0.96, "f1": 0.94}
    feature_names = Column(JSON, nullable=False)  # List of feature names
    feature_importances = Column(JSON, nullable=True)  # Map or list of importance values
    
    model_path = Column(String(512), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)

