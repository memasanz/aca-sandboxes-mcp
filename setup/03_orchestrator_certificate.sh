#!/usr/bin/env bash
# Creates a certificate for the orchestrator and registers its public part on the app registration,
# so the on-premises MCP server signs in with a certificate instead of a client secret.
# Needs openssl and az. Run it where you want the private key to live, or copy orchestrator.pem to the
# on-premises host afterwards and delete other copies.
# Usage: ./03_orchestrator_certificate.sh [days-valid] [output-folder]
set -euo pipefail

DAYS="${1:-365}"
OUT="${2:-.}"
NAME="contoso-orchestrator"

APP=$(az ad app list --display-name "$NAME" --query "[0].appId" -o tsv)
[ -n "$APP" ] || { echo "App registration $NAME not found. Run 01_infra.sh first."; exit 1; }

umask 077
openssl req -x509 -newkey rsa:2048 -nodes -days "$DAYS" -subj "/CN=$NAME" \
  -keyout "$OUT/orchestrator.key" -out "$OUT/orchestrator.crt"

# The server loads one PEM file holding both the private key and the certificate
cat "$OUT/orchestrator.key" "$OUT/orchestrator.crt" > "$OUT/orchestrator.pem"
rm "$OUT/orchestrator.key"

# Upload only the public certificate; the private key never leaves this machine
az ad app credential reset --id "$APP" --cert "@$OUT/orchestrator.crt" --append -o none
rm "$OUT/orchestrator.crt"

echo
echo "Certificate valid for $DAYS days. Expires: $(openssl x509 -in "$OUT/orchestrator.pem" -noout -enddate | cut -d= -f2)"
echo "Move orchestrator.pem to the on-premises host, restrict its permissions, and add this to .env there:"
echo "ORCHESTRATOR_CERT_PATH=<full path to orchestrator.pem>"
echo "Set a reminder to rotate the certificate before it expires, then remove the old one and the client secret."
