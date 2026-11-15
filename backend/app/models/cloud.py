import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Float, ForeignKey, JSON, Text, Boolean
from sqlalchemy.orm import relationship

from backend.app.core.database import Base


class CloudEvidenceRecord(Base):
    """
    Stores ingested Cloud Service Provider (SaaS/IaaS) audit logs and evidence,
    such as AWS CloudTrail, Azure Activity Logs, and Microsoft Entra ID events.
    """
    __tablename__ = "cloud_evidence"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String(36), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    provider = Column(String(32), default="AWS", nullable=False)  # "AWS", "Azure", "GCP", "Generic Cloud"
    event_time = Column(DateTime, nullable=False, index=True)
    event_name = Column(String(128), nullable=False, index=True)  # e.g. StopLogging, DeleteBucket, ConsoleLogin
    service_name = Column(String(128), nullable=True)  # cloudtrail.amazonaws.com, s3.amazonaws.com, etc.
    identity_arn = Column(String(256), nullable=True)  # arn:aws:iam::..., user principal
    identity_type = Column(String(64), nullable=True)  # IAMUser, AssumedRole, Root, ServicePrincipal
    source_ip = Column(String(64), nullable=True)
    user_agent = Column(String(256), nullable=True)
    aws_region = Column(String(32), nullable=True)
    error_code = Column(String(64), nullable=True)  # AccessDenied, UnauthorizedOperation, etc.
    classification = Column(String(32), default="OBSERVED", nullable=False)  # OBSERVED, SUSPICIOUS, CORRELATED
    severity = Column(String(32), default="Informational", nullable=False)  # Critical, High, Medium, Low, Informational
    is_anti_forensic = Column(Boolean, default=False, nullable=False)
    raw_payload = Column(JSON, default=dict)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    case = relationship("Case", back_populates="cloud_evidence")
    correlations = relationship("CloudCorrelationRecord", back_populates="cloud_event", cascade="all, delete-orphan")


class CloudCorrelationRecord(Base):
    """
    Represents an established cross-correlation between a local endpoint/memory artifact
    (e.g., Volatility process execution, local socket, command history) and a remote cloud audit event.
    """
    __tablename__ = "cloud_correlations"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String(36), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    cloud_event_id = Column(String(36), ForeignKey("cloud_evidence.id", ondelete="CASCADE"), nullable=True)
    local_artifact_type = Column(String(64), nullable=False)  # "Process", "Network Socket", "Command History", "Timeline Event"
    local_artifact_desc = Column(String(256), nullable=False)
    local_timestamp = Column(DateTime, nullable=True)
    cloud_timestamp = Column(DateTime, nullable=False)
    time_delta_seconds = Column(Float, default=0.0)
    correlation_type = Column(String(64), nullable=False)  # "IP Match", "Temporal Proximity", "Process-API Attribution"
    confidence = Column(Float, default=0.90)
    classification = Column(String(32), default="CORRELATED", nullable=False)
    rationale = Column(Text, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    cloud_event = relationship("CloudEvidenceRecord", back_populates="correlations")

