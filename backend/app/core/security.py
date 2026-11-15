import hashlib
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Union, Optional, Dict, Any
import jwt

from backend.app.core.config import settings


def calculate_sha256(filepath: Union[str, Path]) -> str:
    """Calculate SHA-256 hash of a file efficiently using chunk streaming."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
    return sha256.hexdigest()


def sanitize_filename(filename: str) -> str:
    """
    Sanitize input filename to avoid directory traversal or dangerous characters.
    Preserves valid basename and extension.
    """
    filename = os.path.basename(filename)
    # Remove any characters other than alphanumeric, dots, underscores, and hyphens
    sanitized = re.sub(r"[^\w\.\-]", "_", filename)
    return sanitized or "unnamed_evidence"


def hash_password(password: str) -> str:
    """Hash password securely using PBKDF2 with SHA-256 and unique 16-byte salt."""
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000)
    return f"{salt}:{key.hex()}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify plain password against PBKDF2 hash using constant-time comparison."""
    try:
        salt, key_hex = hashed_password.split(":")
        check_key = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt.encode("utf-8"), 100000)
        return secrets.compare_digest(check_key.hex(), key_hex)
    except Exception:
        return False


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Generate signed JWT access token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(hours=24))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode and validate signed JWT access token."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        return payload
    except Exception:
        return None
