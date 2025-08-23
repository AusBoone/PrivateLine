#!/usr/bin/env bash
# update_tls_fingerprints.sh - derive server TLS certificate fingerprint in
# formats for both iOS and Android clients.
#
# Usage:
#   scripts/update_tls_fingerprints.sh <host> [port]
#   scripts/update_tls_fingerprints.sh --cert <path>
#
# The script retrieves the leaf TLS certificate from the specified host and
# outputs the SHA-256 hash of its SubjectPublicKeyInfo (SPKI) in base64. The
# value is printed in two forms:
#   - IOS_FINGERPRINT: raw base64 suitable for ios/PrivateLine/Resources
#     server_fingerprints.txt.
#   - ANDROID_FINGERPRINT: prefixed with "sha256/" for use in
#     android/app/build.gradle's CERTIFICATE_SHA256 field.
#
# Exits with code 1 if required tools are missing or if the host cannot be
# reached. No files are modified; developers must copy the output to the
# respective client configs.
#
# Example:
#   ./scripts/update_tls_fingerprints.sh api.example.com 443
#
# Requirements:
#   - OpenSSL must be installed and in PATH.
#   - Run from repository root so relative paths resolve correctly.

set -euo pipefail

# When provided, ``CERT_FILE`` bypasses the network handshake and the script
# derives fingerprints directly from the given PEM/DER certificate. This makes
# unit testing straightforward and avoids external dependencies.
CERT_FILE=""

if [[ "${1:-}" == "--cert" ]]; then
  CERT_FILE=${2:-}
  if [[ -z "$CERT_FILE" ]]; then
    echo "Usage: $0 --cert <path>" >&2
    exit 1
  fi
else
  HOST=${1:-}
  PORT=${2:-443}
  if [[ -z "$HOST" ]]; then
    echo "Usage: $0 <host> [port]" >&2
    exit 1
  fi
  TMP_CERT=$(mktemp)
  # Perform TLS handshake and extract leaf certificate in DER format.
  echo | openssl s_client -servername "$HOST" -connect "$HOST:$PORT" -showcerts 2>/dev/null \
    | openssl x509 -outform der > "$TMP_CERT"
  CERT_FILE="$TMP_CERT"
fi

# Compute SPKI SHA-256 fingerprint and present in both platform formats. The
# certificate file may be either PEM or DER; ``openssl x509`` handles both.
FINGERPRINT=$(openssl x509 -in "$CERT_FILE" -noout -pubkey \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | base64)

rm -f "${TMP_CERT:-}"

echo "IOS_FINGERPRINT=$FINGERPRINT"
echo "ANDROID_FINGERPRINT=sha256/$FINGERPRINT"
