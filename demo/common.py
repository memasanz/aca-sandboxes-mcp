"""Shared helpers for the Contoso sandbox demo."""
import os
from pathlib import Path

from dotenv import load_dotenv
from azure.identity import ClientSecretCredential
from azure.containerapps.sandbox import SandboxGroupClient, endpoint_for_region

HERE = Path(__file__).resolve().parent
load_dotenv(HERE.parent / ".env")

SUBSCRIPTION = os.environ["AZURE_SUBSCRIPTION_ID"]
RESOURCE_GROUP = os.environ["AZURE_RESOURCE_GROUP"]
SANDBOX_GROUP = os.environ["SANDBOX_GROUP"]
REGION = os.environ["SANDBOX_REGION"]
TENANT = os.environ["AZURE_TENANT_ID"]
ADMIN_OID = os.environ["ADMIN_OBJECT_ID"]  # object id of the demo admin service principal
ORCH_OID = os.environ["ORCHESTRATOR_OBJECT_ID"]  # object id of the orchestrator service principal
GROUP_SCOPE = (
    f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{RESOURCE_GROUP}"
    f"/providers/Microsoft.App/sandboxGroups/{SANDBOX_GROUP}"
)
DATA_OWNER_ROLE_ID = None  # resolved at run time by the scripts that need it


def credential(identity: str) -> ClientSecretCredential:
    """identity is 'orchestrator' or 'admin'; reads that service principal from .env."""
    prefix = identity.upper()
    return ClientSecretCredential(
        os.environ["AZURE_TENANT_ID"],
        os.environ[f"{prefix}_CLIENT_ID"],
        os.environ[f"{prefix}_CLIENT_SECRET"],
    )


def sandbox_group_client(identity: str) -> SandboxGroupClient:
    return SandboxGroupClient(
        endpoint_for_region(REGION),
        credential(identity),
        subscription_id=SUBSCRIPTION,
        resource_group=RESOURCE_GROUP,
        sandbox_group=SANDBOX_GROUP,
    )
