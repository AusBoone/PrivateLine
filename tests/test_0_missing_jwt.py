import importlib
import sys
import os
import pytest


def test_missing_jwt_secret_key(monkeypatch):
    """App import should fail when JWT_SECRET_KEY is unset."""
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    sys.modules.pop("backend.app", None)
    with pytest.raises(RuntimeError):
        importlib.import_module("backend.app")
    sys.modules.pop("backend.app", None)
