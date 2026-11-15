import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from backend.app.core.database import Base


def utc_now():
    return datetime.now(timezone.utc)


class MemoryAnalysisRecord(Base):
    """
    Stores Volatility 3 execution results, extracted process lists,
    network sockets, malfind injected code regions, and raw output logs.
    """
    __tablename__ = "memory_analysis_records"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String(36), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id = Column(String(36), ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False, index=True)

    plugins_run = Column(JSON, nullable=False)  # List of plugin strings
    processes = Column(JSON, nullable=True)  # List of normalized process dicts
    network_connections = Column(JSON, nullable=True)  # List of normalized network dicts
    injected_regions = Column(JSON, nullable=True)  # List of malfind alerts
    handles = Column(JSON, nullable=True)  # List of handles
    cmdlines = Column(JSON, nullable=True)  # List of cmdline records
    raw_output = Column(Text, nullable=True)  # Raw stdout logs

    created_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationships
    case = relationship("Case", back_populates="memory_analyses")
    evidence = relationship("Evidence")

