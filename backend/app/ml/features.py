import math
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

SUSPICIOUS_EXTENSIONS = {".exe", ".dll", ".sys", ".scr", ".ps1", ".bat", ".vbs", ".sh", ".cmd"}
SUSPICIOUS_KEYWORDS = {"payload", "beacon", "dropper", "malware", "inject", "exploit", "shell", "temp", "mimikatz", "backdoor", "c2"}

EVENT_TYPE_MAPPING = {
    "File Created": 1,
    "File Modified": 2,
    "File Accessed": 3,
    "File Deleted": 4,
    "Process Started": 5,
    "Network Activity": 6,
    "Login": 7,
    "Cloud Activity": 8,
    "Other": 9,
}


def to_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def extract_file_features(evidence_item) -> Dict[str, float]:
    """
    Extracts normalized numerical features from an evidence item for ML models.
    """
    filename = (evidence_item.filename or "").lower()
    ext = ("." + filename.split(".")[-1]) if "." in filename else ""
    size_bytes = evidence_item.file_size_bytes or 0

    # Read Shannon entropy from metadata_json if present
    meta = evidence_item.metadata_json or {}
    entropy = float(meta.get("entropy", 4.0))

    # Timestamp deltas
    c_time = to_utc(evidence_item.created_time)
    m_time = to_utc(evidence_item.modified_time)
    a_time = to_utc(evidence_item.accessed_time)

    delta_mc = 0.0
    delta_am = 0.0

    if c_time and m_time:
        delta_mc = (m_time - c_time).total_seconds()
    if m_time and a_time:
        delta_am = (a_time - m_time).total_seconds()

    is_exec = 1.0 if ext in {".exe", ".dll", ".sys", ".scr"} else 0.0
    is_script = 1.0 if ext in {".ps1", ".bat", ".vbs", ".sh", ".cmd"} else 0.0
    is_mem = 1.0 if evidence_item.file_type == "Memory Image" or ext in {".raw", ".mem", ".dmp"} else 0.0
    has_keyword = 1.0 if any(kw in filename for kw in SUSPICIOUS_KEYWORDS) else 0.0

    return {
        "log_size": round(math.log10(max(1, size_bytes)), 4),
        "entropy": round(entropy, 4),
        "delta_modified_created": round(delta_mc, 2),
        "delta_accessed_modified": round(delta_am, 2),
        "is_executable": is_exec,
        "is_script": is_script,
        "is_memory_image": is_mem,
        "filename_length": float(len(filename)),
        "has_suspicious_keywords": has_keyword,
    }


def extract_timeline_features(events: List[Any]) -> List[Dict[str, Any]]:
    """
    Extracts temporal and sequence features for anomaly detection (Isolation Forest).
    """
    if not events:
        return []

    # Ensure events are sorted chronologically
    sorted_events = sorted(events, key=lambda e: to_utc(e.timestamp) or datetime.min.replace(tzinfo=timezone.utc))
    extracted: List[Dict[str, Any]] = []

    for idx, ev in enumerate(sorted_events):
        curr_time = to_utc(ev.timestamp)

        # Gap to previous event
        if idx > 0:
            prev_time = to_utc(sorted_events[idx - 1].timestamp)
            gap_prev = max(0.0, (curr_time - prev_time).total_seconds()) if (curr_time and prev_time) else 0.0
        else:
            gap_prev = 0.0

        # Gap to next event
        if idx < len(sorted_events) - 1:
            next_time = to_utc(sorted_events[idx + 1].timestamp)
            gap_next = max(0.0, (next_time - curr_time).total_seconds()) if (curr_time and next_time) else 0.0
        else:
            gap_next = 0.0

        # Events density in +/- 60s
        density_60s = sum(
            1
            for other in sorted_events
            if curr_time and to_utc(other.timestamp) and abs((to_utc(other.timestamp) - curr_time).total_seconds()) <= 60.0
        )

        # Unique sources in +/- 60s
        sources_60s = len(
            {
                other.evidence_id
                for other in sorted_events
                if curr_time and to_utc(other.timestamp) and abs((to_utc(other.timestamp) - curr_time).total_seconds()) <= 60.0 and other.evidence_id
            }
        )

        type_code = float(EVENT_TYPE_MAPPING.get(ev.event_type, 9))

        extracted.append({
            "event_id": ev.id,
            "event_type": ev.event_type,
            "timestamp": curr_time.isoformat() if curr_time else "",
            "features": {
                "gap_prev_seconds": round(gap_prev, 2),
                "gap_next_seconds": round(gap_next, 2),
                "density_60s": float(density_60s),
                "sources_60s": float(sources_60s),
                "event_type_code": type_code,
                "confidence": float(ev.confidence),
            },
        })

    return extracted

