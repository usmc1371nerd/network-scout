"""Bounded JSON-lines runtime logging for long-lived Cyber Scout processes."""

from __future__ import annotations

import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import time

DEFAULT_LOG_DIRECTORY = Path.home() / ".local" / "state" / "cyber-scout"


class PrivateRotatingFileHandler(RotatingFileHandler):
    def _apply_private_mode(self) -> None:
        try:
            Path(self.baseFilename).chmod(0o600)
        except OSError:
            pass

    def _open(self):
        stream = super()._open()
        self._apply_private_mode()
        return stream

    def doRollover(self) -> None:
        super().doRollover()
        self._apply_private_mode()


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": int(time.time()),
            "level": record.levelname.lower(),
            "component": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)[-4096:]
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


def runtime_logger(
    component: str,
    directory: Path | str = DEFAULT_LOG_DIRECTORY,
    *,
    max_bytes: int = 1_048_576,
    backup_count: int = 3,
) -> logging.Logger:
    logger = logging.getLogger(f"cyber_scout.{component}")
    if logger.handlers:
        return logger
    log_directory = Path(directory)
    log_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        log_directory.chmod(0o700)
    except OSError:
        pass
    handler = PrivateRotatingFileHandler(
        log_directory / f"{component}.jsonl",
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger
