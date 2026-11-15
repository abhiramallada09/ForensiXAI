import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Float, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from backend.app.core.database import Base


def utc_now():
    return datetime.now(timezone.utc)


class TimelineEvent(Base):
    """
    Unified chronological event model.
    Represents actions like: File Created, File Modified, File Accessed, File Deleted,
    Process Started, Network Activity, Login, Cloud Activity.
    """
    __tablename__ = "timeline_events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String(36), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id = Column(String(36), ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True)
    
    timestamp = Column(DateTime, nullable=False, index=True)
    timestamp_end = Column(DateTime, nullable=True)  # For reconstructed event windows
    timestamp_source = Column(String(64), nullable=False)  # File MACB, Process, Volatility, EventLog, CloudTrail
    
    event_type = Column(String(64), nullable=False)  # File Created, Process Started, Network Activity, etc.
    artifact_category = Column(String(64), nullable=True)
    description = Column(Text, nullable=False)
    
    confidence = Column(Float, default=1.0, nullable=False)  # 0.0 to 1.0
    classification = Column(String(32), default="OBSERVED", nullable=False)  # OBSERVED, CORRELATED, RECONSTRUCTED, SUSPICIOUS, UNKNOWN
    
    event_metadata = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationships
    case = relationship("Case", back_populates="timeline_events")
    source_evidence = relationship("Evidence", back_populates="timeline_events")
