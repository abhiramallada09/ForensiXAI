import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship

from backend.app.core.database import Base


def utc_now():
    return datetime.now(timezone.utc)


class DeletedFileRecord(Base):
    """
    Forensic record for probable deleted file remnants, MFT residue,
    unallocated memory references, and carved headers.
    Adheres strictly to the Forensic Safety Rule: Classification RECONSTRUCTED or SUSPICIOUS.
    """
    __tablename__ = "deleted_file_records"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String(36), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id = Column(String(36), ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True, index=True)

    filename = Column(String(255), nullable=False)
    original_path = Column(String(512), nullable=True)
    file_type = Column(String(64), default="Executable", nullable=False)
    estimated_size_bytes = Column(Integer, default=0, nullable=False)
    carved_header_signature = Column(String(64), nullable=True)  # e.g., "4D 5A 90 00"

    deletion_timestamp = Column(DateTime, nullable=True)
    confidence = Column(Float, nullable=False)  # 0.70 to 0.98
    classification = Column(String(32), default="RECONSTRUCTED", nullable=False)  # RECONSTRUCTED or SUSPICIOUS
    status = Column(String(64), default="Probable deleted artifact", nullable=False)

    corroborating_sources = Column(JSON, default=list, nullable=False)  # e.g. ["Memory Handle", "Event ID 4660"]
    reconstruction_reason = Column(Text, nullable=False)
    carved_hex_preview = Column(Text, nullable=True)  # Up to 64 bytes of carved hex preview

    created_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationships
    case = relationship("Case", back_populates="deleted_files")
    evidence = relationship("Evidence")

