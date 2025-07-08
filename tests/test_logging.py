"""Unit tests for the logging configuration."""

"""Unit tests for the encrypted logging configuration."""

import logging
import os
from base64 import b64encode, b64decode
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backend.logging_config import init_logging


def _decrypt_lines(path: Path, key: str) -> list[str]:
    """Return decrypted log entries from ``path`` using ``key``."""

    aesgcm = AESGCM(b64decode(key))
    lines = []
    for enc in path.read_text().splitlines():
        data = b64decode(enc)
        nonce, ct = data[:12], data[12:]
        plain = aesgcm.decrypt(nonce, ct, None).decode()
        lines.append(plain)
    return lines


def test_log_file_retention(tmp_path, monkeypatch):
    """Old log files beyond the retention limit should be removed."""
    log = tmp_path / "app.log"
    monkeypatch.setenv("LOG_PATH", str(log))
    monkeypatch.setenv("LOG_RETENTION_DAYS", "1")
    enc_key = b64encode(os.urandom(32)).decode()
    monkeypatch.setenv("ENCRYPTED_LOG_KEY", enc_key)

    logging.getLogger().handlers.clear()
    init_logging()
    logger = logging.getLogger("test")
    handler = logging.getLogger().handlers[0]

    logger.info("first")
    handler.doRollover()
    logger.info("second")
    handler.doRollover()
    logger.info("third")

    rotated = list(log.parent.glob("app.log.*"))
    assert len(rotated) == 1

    # Verify encrypted contents decrypt correctly
    # Decryption should succeed for both current and rotated files
    assert _decrypt_lines(log, enc_key)
    assert _decrypt_lines(rotated[0], enc_key)


def test_sensitive_data_redacted(tmp_path, monkeypatch):
    """Tokens and email addresses should be redacted from logs."""
    log = tmp_path / "app.log"
    monkeypatch.setenv("LOG_PATH", str(log))
    enc_key = b64encode(os.urandom(32)).decode()
    monkeypatch.setenv("ENCRYPTED_LOG_KEY", enc_key)

    logging.getLogger().handlers.clear()
    init_logging()
    logger = logging.getLogger("test")

    logger.info("Authorization: Bearer abc.def user@example.com")
    handler = logging.getLogger().handlers[0]
    handler.flush()

    lines = _decrypt_lines(Path(log), enc_key)
    decrypted = "\n".join(lines)
    assert "abc.def" not in decrypted
    assert "user@example.com" not in decrypted
    assert "Bearer [REDACTED]" in decrypted
    assert "[REDACTED_EMAIL]" in decrypted
