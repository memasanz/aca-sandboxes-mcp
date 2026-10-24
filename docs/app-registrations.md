# App Registrations and Authentication for the Code Interpreter

This document explains who is allowed to do what, and how each identity proves
who it is. It covers the Microsoft Entra app registrations used by the on-premises
MCP server (the orchestrator) and the agent that calls it.

![App registrations and who calls what](images/app-registrations.png)

## The idea in plain English

An agent needs to run code on confidential data. We do not give the agent direct
access to the sandbox. Instead:

- The agent calls one tool on an MCP server that Contoso runs on premises.
- The MCP server is the only thing that can create and use sandboxes in Azure.
- Two different identities keep those jobs separate. The agent can only call the
  tool. The MCP server can only manage sandboxes. Neither can do the other's job.

Azure administrators have neither identity, so they cannot reach the data.

## The identities

Microsoft Entra calls each of these an app registration. Each one gets a service
principal (its sign-in account in the tenant).

| App registration | Plain-English role | Credential | Azure permissions |
|---|---|---|---|
| `contoso-mcp-api` | Names the MCP server as a protected API. Tokens are issued "for" this app. It never signs in. | None | None |
| `contoso-agent-client` | The agent's identity. It proves itself to Entra, then calls the MCP server. | Certificate (production) or client secret (demo) | None. It cannot touch Azure resources. |
| `contoso-orchestrator` | The MCP server's identity toward Azure. It creates, uses, and deletes sandboxes. | Certificate kept on premises | Container Apps SandboxGroup Data Owner on the dedicated sandbox group only |
| `contoso-admin` (example administrator) | Stands in for an Azure administrator. | Not used in the flow | Manages Azure resources but has no data-plane role, so it cannot read sandboxes |

Why two apps for the agent side: `contoso-mcp-api` is what the token is for
(the audience). `contoso-agent-client` is who is asking (the caller). The server
checks both.

## What happens on one call

The numbers match the diagram.

1. **The agent asks Entra for a token.** It signs in as `contoso-agent-client` and
   requests a token for `contoso-mcp-api`. Entra returns a short-lived signed token.
2. **The agent calls the tool.** It sends `run_python` to the MCP server with the
   token in the request.
3. **The MCP server signs in to Azure.** It uses the `contoso-orchestrator`
   certificate, which never leaves the on-premises server, to get an Azure token.
4. **The MCP server checks the caller's token.** It confirms the signature is
   from Entra, the audience is `contoso-mcp-api`, the tenant is Contoso's, the token
   has not expired, and the caller is on the allowed list. Anything else is
   refused with 401.
5. **The MCP server runs the session.** It creates a sandbox, locks outbound
   access, exchanges keys with the sandbox, runs the code on encrypted input,
   returns the encrypted result, and deletes the sandbox.

An Azure administrator (`contoso-admin`) cannot do step 5 directly, because it has
no Data Owner role. A valid Entra token from any app other than
`contoso-agent-client` is refused at step 4.

## Creating the app registrations

Run in Cloud Shell (Bash) or any shell signed in with `az login`. The signed-in
user needs permission to create app registrations.

```
# API app: the audience the MCP server accepts
api=$(az ad app create --display-name contoso-mcp-api --sign-in-audience AzureADMyOrg --query appId -o tsv)
az ad app update --id $api --identifier-uris "api://$api"
obj=$(az ad app show --id $api --query id -o tsv)
az rest --method PATCH --uri "https://graph.microsoft.com/v1.0/applications/$obj" \
  --headers "Content-Type=application/json" --body '{"api":{"requestedAccessTokenVersion":2}}'
az ad sp create --id $api

# Client app: the agent's identity
cli=$(az ad app create --display-name contoso-agent-client --sign-in-audience AzureADMyOrg --query appId -o tsv)
az ad sp create --id $cli
secret=$(az ad app credential reset --id $cli --append --query password -o tsv)
```

What each command does:

- `contoso-mcp-api` gets the identifier `api://<app id>` and version 2 tokens.
- `contoso-agent-client` is created with a client secret for the demo. In
  production use a certificate instead (see "Production hardening").
- The orchestrator app (`contoso-orchestrator`) already exists. Its only Azure
  role is Container Apps SandboxGroup Data Owner on the sandbox group.

## Settings the MCP server needs

Set these as environment variables or in `.env`:

| Setting | Meaning |
|---|---|
| `AZURE_TENANT_ID` | The Contoso Entra tenant. |
| `MCP_AUDIENCE` | `api://<contoso-mcp-api app id>`. Tokens must be issued for this. |
| `MCP_ALLOWED_APP_IDS` | App id of `contoso-agent-client` (comma-separated if more than one). Only these callers are accepted. |
| `ORCHESTRATOR_CLIENT_ID` | App id of `contoso-orchestrator`. |
| `ORCHESTRATOR_CERT_PATH` | Path to the orchestrator's certificate on the server. If unset, a client secret is used (local development only). |
| `REQUIRE_AUTH` | Leave at `true`. `false` is for local testing only. |

The agent side needs `AGENT_CLIENT_ID` and its credential to request tokens.

## What was tested

Tested against the running MCP server with real Entra tokens:

| Test | Result |
|---|---|
| Call with no token | Refused (401) |
| Valid Entra token from a different app (`contoso-admin`) | Refused (401, caller app not allowed) |
| Token from `contoso-agent-client` | Accepted. The code ran in a fresh sandbox and the result came back. |
| Orchestrator signed in with a certificate and no client secret | Worked. The same sandbox run succeeded. |

The setup scripts were run end to end on a fresh environment: `01_infra.sh`,
`02_mcp_app_registrations.sh`, `03_orchestrator_certificate.sh`, then
`99_teardown.sh`, which removed everything. A new Data Owner assignment can take
a few minutes to take effect, so the first call after `01_infra.sh` may be slow.

## Orchestrator certificate: create and rotate

`setup\03_orchestrator_certificate.sh` creates a certificate, uploads its public
part to `contoso-orchestrator`, and leaves one file, `orchestrator.pem`, holding
the private key and certificate. Copy that file to the on-premises host, restrict
its permissions, and set `ORCHESTRATOR_CERT_PATH` to it. The private key never
goes to Azure. The server prefers the certificate whenever the path is set.

**What happens when it expires.** Entra stops accepting the certificate, the
orchestrator can no longer get an Azure token, and every call to the MCP server
fails when it tries to create a sandbox. Nothing is exposed. Calls just fail, so
rotate before expiry rather than after.

**Rotation steps (do them a few weeks before the expiry date):**

1. **Create the new certificate.** Run `setup\03_orchestrator_certificate.sh`
   again. It adds a second certificate to the app registration and leaves the old
   one in place, so both work during the changeover.
2. **Install it.** Copy the new `orchestrator.pem` to the on-premises host. Update
   `ORCHESTRATOR_CERT_PATH` if the path changed, and restart the MCP server.
3. **Check that it works.** Run `mcp_server\test_client.py`. The agent-client call
   must still run code in a sandbox.
4. **Remove the old certificate.** List the credentials, then delete the old one:

   ```
   az ad app credential list --id <orchestrator-app-id> --query "[].{keyId:keyId,end:endDateTime}" -o table
   az ad app credential delete --id <orchestrator-app-id> --key-id <old-key-id>
   ```

5. **Delete the old PEM file** from the host and from anywhere else it was copied.

Do not let this slip: put the expiry date in a calendar or monitoring alert when you
create the certificate. The script prints it. If a certificate is lost or leaked,
skip the overlap: delete its credential immediately, then create and install a new one.
Once the certificate works, delete any client secret still on the app registration,
so a secret cannot be used instead.

## Production hardening

- **Use certificates, not secrets.** Use a certificate for both
  `contoso-agent-client` and `contoso-orchestrator`. Keep the orchestrator
  certificate in the on-premises certificate store or HSM. It must not be in
  Azure.
- **Rotate credentials** on a schedule. Rotate any secret that has been shared
  or pasted into a chat or ticket.
- **Restrict where each app can sign in** with Conditional Access for workload
  identities, limited to Contoso's on-premises IP ranges.
- **Alert on sign-ins** by `contoso-orchestrator` and `contoso-agent-client`.
- **Keep the allowed-caller list short.** Only the agent's app id belongs in
  `MCP_ALLOWED_APP_IDS`.
- **Keep the Data Owner role narrow.** Only `contoso-orchestrator`, only on the
  dedicated sandbox group. The security authority owns this assignment, and no
  workload or subscription administrator may be able to change it.
- **Optionally require an app role assignment** on `contoso-mcp-api` so Entra
  itself refuses tokens for unlisted apps, in addition to the server's check.
