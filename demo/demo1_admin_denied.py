"""Demo 1: a workload admin has control-plane rights but no data-plane rights, and cannot self-grant them (requirement 1)."""
import uuid

import requests

from common import ADMIN_OID, GROUP_SCOPE, REGION, RESOURCE_GROUP, SANDBOX_GROUP, SUBSCRIPTION, credential

ARM = "https://management.azure.com"
DATA = f"https://management.{REGION}.azuredevcompute.io"

arm = {"Authorization": "Bearer " + credential("admin").get_token("https://management.azure.com/.default").token}
data = {"Authorization": "Bearer " + credential("admin").get_token("https://dynamicsessions.io/.default").token}

print("== Identity: sp-contoso-admin (Contributor on RG + RBAC Administrator limited to Reader) ==\n")

r = requests.get(f"{ARM}{GROUP_SCOPE}?api-version=2026-07-01", headers=arm, timeout=30)
print(f"1. Control plane: read sandbox group -> HTTP {r.status_code}")

r = requests.get(
    f"{DATA}/subscriptions/{SUBSCRIPTION}/resourceGroups/{RESOURCE_GROUP}/sandboxGroups/{SANDBOX_GROUP}"
    "/sandboxes?api-version=2026-02-01-preview",
    headers=data,
    timeout=30,
)
print(f"2. Data plane: list sandboxes -> HTTP {r.status_code}")


def grant(role_name: str) -> requests.Response:
    defs = requests.get(
        f"{ARM}/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization/roleDefinitions"
        f"?api-version=2022-04-01&$filter=roleName eq '{role_name}'",
        headers=arm,
        timeout=30,
    ).json()
    body = {
        "properties": {
            "roleDefinitionId": defs["value"][0]["id"],
            "principalId": ADMIN_OID,
            "principalType": "ServicePrincipal",
        }
    }
    return requests.put(
        f"{ARM}{GROUP_SCOPE}/providers/Microsoft.Authorization/roleAssignments/{uuid.uuid4()}?api-version=2022-04-01",
        headers=arm,
        json=body,
        timeout=30,
    )


for role in ["Reader", "Container Apps SandboxGroup Data Owner"]:
    r = grant(role)
    outcome = "created" if r.ok else r.json()["error"]["code"]
    print(f"3. Admin assigns itself '{role}' -> HTTP {r.status_code} ({outcome})")
