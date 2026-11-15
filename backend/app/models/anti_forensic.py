import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Float, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship

from backend.app.core.database import Base


def utc_now():
    return datetime.now(timezone.utc)


class AntiForensicIndicatorRecord(Base):
    """
    Forensic record for detected anti-forensic anomalies, timestomping,
    log tampering, secure deletion wiping, and artifact inconsistencies.
    Adheres strictly to the Forensic Safety Rule: Classification SUSPICIOUS.
    """
    __tablename__ = "anti_forensic_indicators"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String(36), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)

    indicator_type = Column(String(64), nullable=False)  # Timestomping, Log Tampering, Secure Deletion, Extension Spoofing, Volatile Disruption
    title = Column(String(255), nullable=False)
    severity = Column(String(32), default="High", nullable=False)  # Critical, High, Medium, Low
    confidence = Column(Float, nullable=False)  # 0.75 to 0.98
    classification = Column(String(32), default="SUSPICIOUS", nullable=False)  # Always SUSPICIOUS

    supporting_evidence_ids = Column(JSON, default=list, nullable=False)
    supporting_artifacts = Column(JSON, default=list, nullable=False)  # List of string artifact names/sources

    reason = Column(Text, nullable=False)
    recommendation = Column(Text, nullable=False)  # Actionable DFIR examiner recommendation

    created_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationships
    case = relationship("Case", back_populates="anti_forensic_indicators")

