#!/usr/bin/env bash
# Deletes everything the setup scripts created. Run in Azure Cloud Shell (Bash).
set -euo pipefail

RG="rg-contoso-sandbox"

echo "This deletes resource group $RG and the app registrations contoso-orchestrator, sp-contoso-admin, contoso-mcp-api and contoso-agent-client."
read -r -p "Type yes to continue: " answer
[ "$answer" = "yes" ] || exit 1

az group delete -n "$RG" --yes --no-wait
for name in contoso-orchestrator sp-contoso-admin contoso-mcp-api contoso-agent-client; do
  for app in $(az ad app list --display-name "$name" --query "[].appId" -o tsv); do
    az ad app delete --id "$app"
  done
done
echo "Deleted. Also remove your local .env."
