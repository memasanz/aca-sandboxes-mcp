#!/usr/bin/env bash
# Creates the two app registrations for the on-premises MCP server: the API it protects and the agent's client identity.
# Run in Azure Cloud Shell (Bash). The signed-in user needs permission to create app registrations.
set -euo pipefail

get_or_create_app() {
  local name="$1" app
  app=$(az ad app list --display-name "$name" --query "[0].appId" -o tsv)
  if [ -z "$app" ]; then
    app=$(az ad app create --display-name "$name" --sign-in-audience AzureADMyOrg --query appId -o tsv)
    az ad sp create --id "$app" -o none
  fi
  echo "$app"
}

# API app: the audience the MCP server accepts, with version 2 tokens
API_APP=$(get_or_create_app contoso-mcp-api)
az ad app update --id "$API_APP" --identifier-uris "api://$API_APP"
API_OBJ=$(az ad app show --id "$API_APP" --query id -o tsv)
az rest --method PATCH --uri "https://graph.microsoft.com/v1.0/applications/$API_OBJ" \
  --headers "Content-Type=application/json" --body '{"api":{"requestedAccessTokenVersion":2}}'

# Client app: the agent's identity (use a certificate instead of a secret in production)
CLIENT_APP=$(get_or_create_app contoso-agent-client)
CLIENT_SECRET=$(az ad app credential reset --id "$CLIENT_APP" --append --query password -o tsv)

echo
echo "Copy these lines into .env (they contain a secret; do not commit):"
echo "MCP_AUDIENCE=api://$API_APP"
echo "MCP_ALLOWED_APP_IDS=$CLIENT_APP"
echo "AGENT_CLIENT_ID=$CLIENT_APP"
echo "AGENT_CLIENT_SECRET=$CLIENT_SECRET"
