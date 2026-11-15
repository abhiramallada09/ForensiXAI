import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, BigInteger, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from backend.app.core.database import Base


def utc_now():
    return datetime.now(timezone.utc)


class Evidence(Base):
    """
    Forensic Evidence model.
    Maintains cryptographic hash, original file metadata, and classification:
    OBSERVED, CORRELATED, RECONSTRUCTED, SUSPICIOUS, UNKNOWN.
    """
    __tablename__ = "evidence"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String(36), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_number = Column(String(64), nullable=True)
    filename = Column(String(255), nullable=False)
    stored_path = Column(String(512), nullable=False)
    file_type = Column(String(64), nullable=False, default="File")  # File, Memory Image, System Log, etc.
    mime_type = Column(String(128), nullable=True)
    file_size_bytes = Column(BigInteger, nullable=False, default=0)
    
    # Hashes for forensic integrity
    sha256 = Column(String(64), nullable=False, index=True)
    md5 = Column(String(32), nullable=True)
    
    # Forensic Timestamps
    created_time = Column(DateTime, nullable=True)
    modified_time = Column(DateTime, nullable=True)
    accessed_time = Column(DateTime, nullable=True)
    
    # Classification & Verification status
    classification = Column(String(32), default="OBSERVED", nullable=False)
    status = Column(String(64), default="Ingested", nullable=False)  # Ingested, Analyzed, Flagged
    
    # Detailed extracted metadata JSON
    metadata_json = Column(JSON, nullable=True)
    notes = Column(Text, nullable=True)
    
    created_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationships
    case = relationship("Case", back_populates="evidence_items")
    timeline_events = relationship("TimelineEvent", back_populates="source_evidence")
