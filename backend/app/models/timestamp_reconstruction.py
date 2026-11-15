import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Float, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship

from backend.app.core.database import Base


def utc_now():
    return datetime.now(timezone.utc)


class TimestampReconstructionRecord(Base):
    """
    Forensic model for multi-source timestamp comparison, consistency status
    (CONSISTENT, INCONSISTENT, MISSING), and probable event time window calculation.
    """
    __tablename__ = "timestamp_reconstructions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String(36), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    anchor_event_id = Column(String(36), ForeignKey("timeline_events.id", ondelete="SET NULL"), nullable=True, index=True)

    event_title = Column(String(255), nullable=False)
    observed_timestamp = Column(DateTime, nullable=False)
    probable_window_start = Column(DateTime, nullable=False)
    probable_window_end = Column(DateTime, nullable=False)
    probable_event_time = Column(DateTime, nullable=False)
    window_duration_seconds = Column(Float, default=0.0, nullable=False)

    consistency_status = Column(String(32), default="CONSISTENT", nullable=False)  # CONSISTENT, INCONSISTENT, MISSING
    classification = Column(String(32), default="RECONSTRUCTED", nullable=False)  # RECONSTRUCTED, SUSPICIOUS
    confidence = Column(Float, nullable=False)  # 0.70 to 0.98

    sources_compared = Column(JSON, default=list, nullable=False)  # List of source dicts {source, timestamp, event_type}
    related_event_ids = Column(JSON, default=list, nullable=False)
    reconstruction_reason = Column(Text, nullable=False)

    created_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationships
    case = relationship("Case", back_populates="timestamp_reconstructions")
    anchor_event = relationship("TimelineEvent")

