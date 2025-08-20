"""Tests covering the standalone background scheduler."""

import pytest

from backend.app import scheduler, start_scheduler


def test_start_scheduler_requires_flag(monkeypatch):
    """Ensure the scheduler refuses to start without RUN_SCHEDULER=1."""
    # Remove any preset flag and stub out the actual start method so tests do
    # not spawn background threads.
    monkeypatch.delenv("RUN_SCHEDULER", raising=False)
    called = {"start": False}

    def fake_start():
        called["start"] = True

    monkeypatch.setattr(scheduler, "start", fake_start)

    with pytest.raises(RuntimeError):
        start_scheduler()

    # ``start`` must not have been invoked due to the missing flag.
    assert called["start"] is False


def test_start_scheduler_runs_with_flag(monkeypatch):
    """Verify the scheduler starts when RUN_SCHEDULER=1 is provided."""
    monkeypatch.setenv("RUN_SCHEDULER", "1")
    started = {"flag": False}

    def fake_start():
        started["flag"] = True

    monkeypatch.setattr(scheduler, "start", fake_start)
    # Avoid registering real ``atexit`` handlers during the test suite.
    monkeypatch.setattr("backend.app.atexit.register", lambda func: None)

    start_scheduler()

    assert started["flag"] is True
