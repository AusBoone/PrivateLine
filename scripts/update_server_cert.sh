#!/usr/bin/env bash
# update_server_cert.sh - Retrieve latest TLS certificate and update client pins.
#
# This helper automates TLS certificate rotation for both mobile platforms.
# It downloads the server's leaf certificate, stores it as
# `ios/PrivateLine/Resources/server.cer` for iOS certificate pinning, and prints
# the SHA-256 public-key fingerprint used by Android's certificate pinner. The
# generated `server.cer` file is gitignored; run this script whenever the backend
# certificate changes so new builds include the correct pin.
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

# Place the DER certificate where the iOS project expects it. The path is
# gitignored so developers and CI pipelines must run this script before building
# when the backend certificate changes.
cp "$TMP_CERT" ios/PrivateLine/Resources/server.cer

# Emit fingerprint used by Android's certificate pinner. This SHA-256 digest of
# the public key is inserted into ``CERTIFICATE_SHA256`` in the Android project.
echo "Android pin SHA-256:"
openssl x509 -in "$TMP_CERT" -noout -pubkey \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | base64

# Remove the temporary certificate file to avoid leaving sensitive material on
# disk.
rm -f "$TMP_CERT"
