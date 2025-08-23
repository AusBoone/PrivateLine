#!/usr/bin/env bash
# update_server_cert.sh - Retrieve latest TLS certificate and update client pins.
#
# This helper automates TLS certificate rotation for both mobile platforms.
# It downloads the server's leaf certificate, derives the SHA-256 fingerprint of
# the certificate's SubjectPublicKeyInfo (SPKI) and stores/prints that value. The
# resulting fingerprint is appended to
# `ios/PrivateLine/Resources/server_fingerprints.txt` so the iOS client can pin
# multiple upcoming certificates. The file is gitignored; run this script whenever
# the backend certificate changes so new builds include the correct pins.
#
# Usage:
#   scripts/update_server_cert.sh <host> [port]
#
# Example:
#   scripts/update_server_cert.sh api.example.com 8443
#
# Arguments:
#   <host>  Hostname of the backend server.
#   [port]  Optional TLS port, defaults to 443.
#
# Requirements:
#   - OpenSSL must be installed and in the PATH.
#   - Run from the repository root so relative paths resolve correctly.

set -euo pipefail

HOST=${1:-}
PORT=${2:-443}

if [[ -z "$HOST" ]]; then
  echo "Usage: $0 <host> [port]" >&2
  exit 1
fi

TMP_CERT=$(mktemp)

# Retrieve the server's certificate in DER format. ``openssl s_client`` performs
# the TLS handshake and outputs the certificate chain, which we then convert to
# raw DER bytes with ``openssl x509``.
echo | openssl s_client -servername "$HOST" -connect "$HOST:$PORT" -showcerts 2>/dev/null \
  | openssl x509 -outform der > "$TMP_CERT"

# Derive the SPKI SHA-256 fingerprint and append it to the pins file for iOS.
PIN_FILE="ios/PrivateLine/Resources/server_fingerprints.txt"
mkdir -p "$(dirname "$PIN_FILE")"
FINGERPRINT=$(openssl x509 -in "$TMP_CERT" -noout -pubkey \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | base64)

echo "Fingerprint: $FINGERPRINT"

# Append the fingerprint if it is not already present so multiple certificates
# can be pinned simultaneously during rotations.
if [[ -f "$PIN_FILE" ]] && grep -qx "$FINGERPRINT" "$PIN_FILE"; then
  echo "Fingerprint already present in $PIN_FILE"
else
  echo "$FINGERPRINT" >> "$PIN_FILE"
  echo "Stored fingerprint in $PIN_FILE"
fi

# Remove the temporary certificate file to avoid leaving sensitive material on
# disk.
rm -f "$TMP_CERT"
