import os
import math
import mimetypes
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Tuple


def calculate_entropy(filepath: Path) -> float:
    """Calculate Shannon entropy (0.0 to 8.0) of a file to detect packed/encrypted data."""
    try:
        with open(filepath, "rb") as f:
            data = f.read(1024 * 1024)  # Read up to 1MB for speed
            if not data:
                return 0.0
            occurences = [0] * 256
            for byte in data:
                occurences[byte] += 1
            entropy = 0.0
            total = len(data)
            for count in occurences:
                if count > 0:
                    p = count / total
                    entropy -= p * math.log2(p)
            return round(entropy, 3)
    except Exception:
        return 0.0


def format_file_size(size_bytes: int) -> str:
    """Format bytes into human-readable string (KB, MB, GB)."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def extract_file_metadata(filepath: Path) -> Tuple[Dict[str, Any], datetime, datetime, datetime]:
    """
    Extract comprehensive forensic metadata and MACB timestamps from a local file.
    Does NOT execute the file.
    Returns: (json_safe_metadata_dict, created_dt, modified_dt, accessed_dt)
    """
    stat = filepath.stat()
    size_bytes = stat.st_size

    # Datetimes in UTC
    created_dt = datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc)
    modified_dt = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
    accessed_dt = datetime.fromtimestamp(stat.st_atime, tz=timezone.utc)

    ext = filepath.suffix.lower()
    guessed_mime, _ = mimetypes.guess_type(str(filepath))
    mime_type = guessed_mime or "application/octet-stream"

    # Read first 16 bytes as hex magic header
    magic_hex = ""
    try:
        with open(filepath, "rb") as f:
            header_bytes = f.read(16)
            magic_hex = header_bytes.hex().upper()
    except Exception:
        magic_hex = "UNAVAILABLE"

    # Determine file category suggestion
    category = "File"
    if ext in [".raw", ".mem", ".dmp", ".vmem"]:
        category = "Memory Image"
    elif ext in [".evtx", ".log"]:
        category = "System Log"
    elif ext in [".json", ".csv"] and ("cloudtrail" in filepath.name.lower() or "azure" in filepath.name.lower()):
        category = "Cloud Log"
    elif ext in [".pcap", ".pcapng"]:
        category = "Network Evidence"

    entropy_val = calculate_entropy(filepath)

    json_metadata = {
        "filename": filepath.name,
        "extension": ext,
        "file_size_bytes": size_bytes,
        "readable_size": format_file_size(size_bytes),
        "mime_type": mime_type,
        "magic_header_hex": magic_hex,
        "entropy": entropy_val,
        "suggested_category": category,
        "created_time_iso": created_dt.isoformat(),
        "modified_time_iso": modified_dt.isoformat(),
        "accessed_time_iso": accessed_dt.isoformat(),
        "attributes": {
            "is_symlink": filepath.is_symlink(),
            "readonly": not os.access(filepath, os.W_OK),
            "device": stat.st_dev,
            "inode": stat.st_ino,
        }
    }

    return json_metadata, created_dt, modified_dt, accessed_dt
