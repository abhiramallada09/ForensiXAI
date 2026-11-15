import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, DateTime
from sqlalchemy.orm import relationship
from backend.app.core.database import Base


def utc_now():
    return datetime.now(timezone.utc)


class Case(Base):
    """
    Forensic Case model storing metadata and investigation tracking details.
    Statuses: New, Evidence Collected, Analyzing, Analysis Complete, Review Required, Archived
    """
    __tablename__ = "cases"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_number = Column(String(64), unique=True, index=True, nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    investigator = Column(String(128), default="A. Abhiram", nullable=False)
    status = Column(String(64), default="New", nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    # Relationships
    evidence_items = relationship("Evidence", back_populates="case", cascade="all, delete-orphan")
    timeline_events = relationship("TimelineEvent", back_populates="case", cascade="all, delete-orphan")
    findings = relationship("ForensicFinding", back_populates="case", cascade="all, delete-orphan")
    memory_analyses = relationship("MemoryAnalysisRecord", back_populates="case", cascade="all, delete-orphan")
    deleted_files = relationship("DeletedFileRecord", back_populates="case", cascade="all, delete-orphan")
    timestamp_reconstructions = relationship("TimestampReconstructionRecord", back_populates="case", cascade="all, delete-orphan")
    anti_forensic_indicators = relationship("AntiForensicIndicatorRecord", back_populates="case", cascade="all, delete-orphan")
    cloud_evidence = relationship("CloudEvidenceRecord", back_populates="case", cascade="all, delete-orphan")



