# Ephemeral agent code interpreter on ACA Sandboxes

Shows how agents can run code in short-lived Azure Container Apps Sandboxes so that
an administrator cannot access session information or logs. The design relies on
governance controls (role separation, egress lockdown, per-session keys), not on
confidential compute.

## The idea in one paragraph

An agent that needs to run code calls an MCP tool hosted on premises. That MCP server (the orchestrator) is the only identity holding the data-plane role on the sandbox group, so Azure administrators can create and delete sandboxes but cannot open one or read its contents. For each call the orchestrator creates a fresh sandbox, denies all outbound traffic, agrees a one-time key with the sandbox (ECDH), sends the code and data encrypted, reads back the encrypted result, and deletes the sandbox. Nothing is left to recover, and the logs record only metadata, never content. The protection comes from role separation and checks, not from confidential-computing hardware, so the customer has to accept that trade-off (see `docs\sandbox-approach.md`).

## How the pieces connect

![App registrations and who calls what](docs/images/app-registrations.png)

## Layout

| Path | What it is |
|------|-----------|
| `docs\system-requirements.md` | The 25 technology-neutral requirements, plus how keys are established |
| `docs\sandbox-approach.md` | The design, how each requirement is met, and why the MCP server runs on premises |
| `docs\app-registrations.md` | The Entra app registrations and who calls what, with a diagram |
| `demo\` | Four command-line demos (`run_all.ps1`) and `build_notebooks.py`, which builds one executed notebook per requirement into `demo\notebooks\` |
| `mcp_server\` | FastAPI MCP server (the orchestrator) with `run_python`, intended to be hosted on premises, and a real-token test client |
| `setup\` | Cloud Shell scripts that create the Azure resources and app registrations, and a teardown script |

## Setup

1. In Azure Cloud Shell (Bash), run `setup\01_infra.sh` and then `setup\02_mcp_app_registrations.sh`.
   Each prints lines for `.env`. Cloud Shell is needed because app registrations fail from some local
   `az` sessions. See `docs\app-registrations.md` for what the second script creates. If you upload the
   files directly rather than cloning, strip Windows line endings first: `sed -i 's/\r$//' setup/*.sh`.
2. Copy `.env.example` to `.env` and paste in the printed lines. Never commit `.env`.
3. Create a virtual environment and install the packages: `azure-containerapps-sandbox`,
   `azure-identity`, `python-dotenv`, `requests`, `cryptography`, `nbformat`, `nbclient`, `ipykernel`,
   plus `mcp<2`, `fastapi`, `uvicorn` and `pyjwt[crypto]` for the MCP server.
4. Register the notebook kernel: `python -m ipykernel install --user --name contoso-sandbox`.

## Run

- Demos: `demo\run_all.ps1`
- Notebooks: `cd demo; python build_notebooks.py [requirement numbers]`
- MCP server: `cd mcp_server; uvicorn server:app --port 8090`, then `python test_client.py`

ACA Sandboxes are generally available.
