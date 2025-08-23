"""Tests for the update_tls_fingerprints.sh helper.

These tests ensure the script derives deterministic fingerprints from a given
certificate file. The development certificate under ``scripts/dev_cert.pem``
allows the checks to run offline without hitting external servers.
"""

import subprocess
from pathlib import Path


def run_script(*args: str) -> subprocess.CompletedProcess:
    """Execute the fingerprint script and return the completed process.

    This wrapper centralises invocation so tests run the script the same way.
    ``check`` is disabled because several tests assert non-zero exit codes.
    """

    script = Path(__file__).parents[1] / "scripts" / "update_tls_fingerprints.sh"
    return subprocess.run(["bash", str(script), *args], capture_output=True, text=True)


def test_outputs_expected_fingerprints() -> None:
    """Script prints both iOS and Android fingerprints for a given certificate.

    The hard-coded base64 value matches the fingerprint of ``dev_cert.pem`` which
    is used by the CI workflow. Any change to the certificate without updating
    consumers will cause this test to fail, surfacing outdated pins early.
    """

    cert = Path(__file__).parents[1] / "scripts" / "dev_cert.pem"
    result = run_script("--cert", str(cert))
    assert result.returncode == 0, result.stderr
    expected = "RM57PGMLd846bJxBOW0DyA3abqB0ERUuvop8iKDrQTM="
    assert f"IOS_FINGERPRINT={expected}" in result.stdout
    assert f"ANDROID_FINGERPRINT=sha256/{expected}" in result.stdout


def test_missing_arguments_errors() -> None:
    """Invoking the script without required arguments should fail gracefully."""

    result = run_script()
    assert result.returncode != 0
    assert "Usage" in result.stderr
