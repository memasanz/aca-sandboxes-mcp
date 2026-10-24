# Setup scripts

Bash scripts that create the Azure resources and Entra app registrations used by the demos and the MCP server.
Run them in **Azure Cloud Shell (Bash)**: app registrations need Microsoft Graph access, which some local `az`
sessions are blocked from.

If you upload the files instead of cloning, strip Windows line endings first:

```
sed -i 's/\r$//' setup/*.sh
```

## Order

| Script | What it does |
|---|---|
| `01_infra.sh [region] [suffix]` | Creates the resource group `rg-contoso-sandbox` and the sandbox group `sg-contoso-<suffix>` (defaults: `eastus2`, `demo`). Creates two service principals: `contoso-orchestrator`, which gets Container Apps SandboxGroup Data Owner on the group, and `sp-contoso-admin`, which gets Contributor plus Role Based Access Control Administrator on the resource group, limited to assigning Reader. |
| `02_mcp_app_registrations.sh` | Creates `contoso-mcp-api` (the audience the MCP server accepts, version 2 tokens) and `contoso-agent-client` (the agent's identity, with a client secret). |
| `99_teardown.sh` | Deletes the resource group and all four app registrations after you type `yes`. |

Each create script is safe to re-run. It reuses existing app registrations and adds a new secret each time.

## Output

Scripts 01 and 02 print lines to paste into `.env` at the repository root (start from `.env.example`).
The lines contain secrets: do not commit them, and do not share them in chat or email.

## Requirements

- Owner, or User Access Administrator, on the subscription (script 01 creates role assignments).
- Permission to create app registrations in the tenant.
- The `Microsoft.App` resource provider (script 01 registers it).

## Notes

- Only the orchestrator holds the data-plane role. The admin can manage the resource group but cannot open a sandbox or give itself that role.
- The sandbox group is created with a direct ARM call (`az rest`, api-version `2026-02-01-preview`).
- Use a certificate instead of a client secret for production (see `docs\app-registrations.md`).
