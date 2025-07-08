"""Logging utilities for the PrivateLine backend.

This module configures Python's :mod:`logging` subsystem so logs are rotated
at midnight and persisted entries remain encrypted at rest. The AES-256 key
used for encryption is provided via the ``ENCRYPTED_LOG_KEY`` environment
variable. ``LOG_RETENTION_DAYS`` controls how many rotated files are kept.
Common PII such as bearer tokens and email addresses are removed before each
record is written.

Example usage::

    from backend.logging_config import init_logging
    init_logging()
"""

from __future__ import annotations

import logging
import os
import re
from base64 import b64decode, b64encode
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


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


class EncryptedFileHandler(TimedRotatingFileHandler):
    """Rotate log files while encrypting each record with AES-GCM."""

    def __init__(self, *, key: bytes, **kwargs) -> None:
        """Create the handler.

        Parameters
        ----------
        key:
            Raw 32 byte AES key used to encrypt log lines.
        **kwargs:
            Additional parameters forwarded to
            :class:`~logging.handlers.TimedRotatingFileHandler` such as
            ``filename`` and ``backupCount``.
        """

        if not key or len(key) != 32:
            raise ValueError("A 32 byte AES key is required for encrypted logs")

        super().__init__(**kwargs)
        self._aesgcm = AESGCM(key)

    def emit(self, record: logging.LogRecord) -> None:
        """Encrypt and write the formatted log record to disk."""

        try:
            msg = self.format(record)
            nonce = os.urandom(12)
            ct = self._aesgcm.encrypt(nonce, msg.encode("utf-8"), None)
            data = b64encode(nonce + ct).decode("ascii")
            self.acquire()
            try:
                self.stream.write(data + self.terminator)
                self.flush()
            finally:
                self.release()
        except Exception:
            self.handleError(record)


def init_logging() -> None:
    """Initialize the root logger with an encrypted rotating file handler."""

    log_path = Path(os.environ.get("LOG_PATH", "/tmp/private_line.log"))
    log_path.parent.mkdir(parents=True, exist_ok=True)
    retention = int(os.environ.get("LOG_RETENTION_DAYS", "7"))
    level_name = os.environ.get("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    key_env = os.environ.get("ENCRYPTED_LOG_KEY")
    if not key_env:
        raise RuntimeError(
            "ENCRYPTED_LOG_KEY environment variable is required for logging"
        )

    key = b64decode(key_env)

    handler = EncryptedFileHandler(
        filename=str(log_path), when="midnight", backupCount=retention, key=key
    )
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s - %(message)s")
    )
    handler.addFilter(SensitiveDataFilter())

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()
    root.addHandler(handler)
