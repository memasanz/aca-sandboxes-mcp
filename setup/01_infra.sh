#!/usr/bin/env bash
# Creates the resource group, sandbox group, and the two demo service principals with their roles.
# Run in Azure Cloud Shell (Bash): app registrations need Microsoft Graph access.
# The signed-in user needs Owner (or User Access Administrator) on the subscription.
# Usage: ./01_infra.sh [region] [name-suffix]
set -euo pipefail

REGION="${1:-eastus2}"
SUFFIX="${2:-demo}"
RG="rg-contoso-sandbox"
GROUP="sg-contoso-${SUFFIX}"
SUB=$(az account show --query id -o tsv)
TENANT=$(az account show --query tenantId -o tsv)
API="2026-02-01-preview"
READER_ID="acdd72a7-3385-48ef-bd42-f606fba81ae7"

echo "Subscription $SUB, region $REGION"
az provider register -n Microsoft.App --wait
az group create -n "$RG" -l "$REGION" -o none

echo "Creating sandbox group $GROUP"
az rest --method PUT \
  --uri "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.App/sandboxGroups/$GROUP?api-version=$API" \
  --body "{\"location\":\"$REGION\",\"properties\":{}}" -o none
GROUP_SCOPE="/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.App/sandboxGroups/$GROUP"

# Creates an app registration and service principal if missing
make_sp() {
  local name="$1" app
  app=$(az ad app list --display-name "$name" --query "[0].appId" -o tsv)
  if [ -z "$app" ]; then
    app=$(az ad app create --display-name "$name" --sign-in-audience AzureADMyOrg --query appId -o tsv)
    az ad sp create --id "$app" -o none
  fi
  echo "$app"
}

ORCH_APP=$(make_sp contoso-orchestrator)
ADMIN_APP=$(make_sp sp-contoso-admin)
ORCH_SECRET=$(az ad app credential reset --id "$ORCH_APP" --append --query password -o tsv)
ADMIN_SECRET=$(az ad app credential reset --id "$ADMIN_APP" --append --query password -o tsv)
ORCH_OID=$(az ad sp show --id "$ORCH_APP" --query id -o tsv)
ADMIN_OID=$(az ad sp show --id "$ADMIN_APP" --query id -o tsv)

echo "Waiting for the service principals to replicate"
sleep 30

# Only the orchestrator holds the data-plane role
az role assignment create --assignee-object-id "$ORCH_OID" --assignee-principal-type ServicePrincipal \
  --role "Container Apps SandboxGroup Data Owner" --scope "$GROUP_SCOPE" -o none

# The admin gets control-plane rights and can only hand out Reader
az role assignment create --assignee-object-id "$ADMIN_OID" --assignee-principal-type ServicePrincipal \
  --role Contributor --scope "/subscriptions/$SUB/resourceGroups/$RG" -o none
CONDITION="((!(ActionMatches{'Microsoft.Authorization/roleAssignments/write'})) OR (@Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {$READER_ID})) AND ((!(ActionMatches{'Microsoft.Authorization/roleAssignments/delete'})) OR (@Resource[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {$READER_ID}))"
az role assignment create --assignee-object-id "$ADMIN_OID" --assignee-principal-type ServicePrincipal \
  --role "Role Based Access Control Administrator" --scope "/subscriptions/$SUB/resourceGroups/$RG" \
  --condition "$CONDITION" --condition-version 2.0 -o none

echo
echo "Copy these lines into .env (they contain secrets; do not commit):"
echo "AZURE_SUBSCRIPTION_ID=$SUB"
echo "AZURE_TENANT_ID=$TENANT"
echo "AZURE_RESOURCE_GROUP=$RG"
echo "SANDBOX_GROUP=$GROUP"
echo "SANDBOX_REGION=$REGION"
echo "ORCHESTRATOR_CLIENT_ID=$ORCH_APP"
echo "ORCHESTRATOR_CLIENT_SECRET=$ORCH_SECRET"
echo "ORCHESTRATOR_OBJECT_ID=$ORCH_OID"
echo "ADMIN_CLIENT_ID=$ADMIN_APP"
echo "ADMIN_CLIENT_SECRET=$ADMIN_SECRET"
echo "ADMIN_OBJECT_ID=$ADMIN_OID"
