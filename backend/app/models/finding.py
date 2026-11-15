import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Float, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from backend.app.core.database import Base


def utc_now():
    return datetime.now(timezone.utc)


class ForensicFinding(Base):
    """
    Forensic or AI finding model with explicit provenance, classification, and explanation.
    """
    __tablename__ = "forensic_findings"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String(36), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    
    title = Column(String(255), nullable=False)
    finding_type = Column(String(64), nullable=False)  # Deleted File Trace, Timestamp Manipulation, Malware, Anti-Forensic
    classification = Column(String(32), default="SUSPICIOUS", nullable=False)  # OBSERVED, CORRELATED, RECONSTRUCTED, SUSPICIOUS, UNKNOWN
    severity = Column(String(32), default="Medium", nullable=False)  # Low, Medium, High, Critical
    
    confidence = Column(Float, nullable=False)
    reason = Column(Text, nullable=False)
    explanation = Column(Text, nullable=True)  # Explainable AI details
    
    supporting_artifacts = Column(JSON, nullable=True)
    recommendation = Column(Text, nullable=True)
    
    created_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationships
    case = relationship("Case", back_populates="findings")
