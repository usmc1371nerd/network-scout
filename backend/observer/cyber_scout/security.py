"""Owner-private dashboard session material and HTTP boundary checks."""

from __future__ import annotations

import hmac
import os
from pathlib import Path
import secrets
import stat


DEFAULT_SESSION_FILE = Path.home() / ".local" / "state" / "cyber-scout" / "dashboard-session"


def load_or_create_session_secret(path: Path | str = DEFAULT_SESSION_FILE) -> str:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    target.parent.chmod(0o700)
    if target.exists():
        metadata = target.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
            raise PermissionError("Dashboard session file must be a private owner-only regular file")
        value = target.read_text().strip()
        if len(value) < 43:
            raise ValueError("Dashboard session secret is invalid")
        return value
    value = secrets.token_urlsafe(32)
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(value + "\n")
    return value


def token_matches(provided: str | None, expected: str) -> bool:
    return bool(provided) and hmac.compare_digest(provided, expected)


def allowed_authority(host: str | None, port: int) -> bool:
    return (host or "").lower() in {f"127.0.0.1:{port}", f"[::1]:{port}"}


def allowed_origin(origin: str | None, port: int) -> bool:
    return origin in {f"http://127.0.0.1:{port}", f"http://[::1]:{port}"}
