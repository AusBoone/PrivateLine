"""Unit tests for the logging configuration."""

import logging
from pathlib import Path

from backend.logging_config import init_logging


def test_log_file_retention(tmp_path, monkeypatch):
    """Old log files beyond the retention limit should be removed."""
    log = tmp_path / "app.log"
    monkeypatch.setenv("LOG_PATH", str(log))
    monkeypatch.setenv("LOG_RETENTION_DAYS", "1")

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


def test_sensitive_data_redacted(tmp_path, monkeypatch):
    """Tokens and email addresses should be redacted from logs."""
    log = tmp_path / "app.log"
    monkeypatch.setenv("LOG_PATH", str(log))

    logging.getLogger().handlers.clear()
    init_logging()
    logger = logging.getLogger("test")

    logger.info("Authorization: Bearer abc.def user@example.com")
    handler = logging.getLogger().handlers[0]
    handler.flush()

    content = Path(log).read_text()
    assert "abc.def" not in content
    assert "user@example.com" not in content
    assert "Bearer [REDACTED]" in content
    assert "[REDACTED_EMAIL]" in content
