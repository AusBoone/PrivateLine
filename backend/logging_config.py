"""Logging utilities for the PrivateLine backend.

This module configures Python's :mod:`logging` subsystem with a
:class:`~logging.handlers.TimedRotatingFileHandler` so log files rotate at
midnight. The number of retained backups is controlled by the
``LOG_RETENTION_DAYS`` environment variable. A small filter removes common
PII such as bearer tokens and email addresses before messages are written.

Example usage::

    from backend.logging_config import init_logging
    init_logging()
"""

from __future__ import annotations

import logging
import os
import re
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path


class SensitiveDataFilter(logging.Filter):
    """Sanitize log messages to avoid leaking tokens or email addresses."""

    _token_re = re.compile(r"Bearer\s+[A-Za-z0-9._-]+")
    _email_re = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        sanitized = self._token_re.sub("Bearer [REDACTED]", message)
        sanitized = self._email_re.sub("[REDACTED_EMAIL]", sanitized)
        if sanitized != message:
            record.msg = sanitized
            record.args = ()
        return True


def init_logging() -> None:
    """Initialize the root logger with a rotating file handler."""

    log_path = Path(os.environ.get("LOG_PATH", "/tmp/private_line.log"))
    log_path.parent.mkdir(parents=True, exist_ok=True)
    retention = int(os.environ.get("LOG_RETENTION_DAYS", "7"))
    level_name = os.environ.get("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    handler = TimedRotatingFileHandler(
        filename=str(log_path), when="midnight", backupCount=retention
    )
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s - %(message)s")
    )
    handler.addFilter(SensitiveDataFilter())

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()
    root.addHandler(handler)
