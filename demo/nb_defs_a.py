"""Notebook definitions for requirements 1-9. Each entry becomes one notebook."""

REQS_A = {
    1: dict(
        title="Administrator confidentiality",
        text="Azure administrative privileges alone must not allow someone to obtain session files, code, results, or secrets, including while execution is running.",
        covered="Both",
        how="Sandbox operations are data-plane operations that need the Entra role **Container Apps SandboxGroup Data Owner**. Only the orchestrator holds it. Administrators hold control-plane roles only, and a conditioned *Role Based Access Control Administrator* role stops them granting themselves Data Owner.",
        cells=[
            """from helpers import *
import uuid
arm = token("admin", "arm")
data = token("admin", "data")
print("Identity: sp-contoso-admin (Contributor on the resource group + RBAC Administrator limited to Reader)")""",
            """# The admin can manage the group on the control plane
r = requests.get(f"{ARM}{GROUP_SCOPE}?api-version=2026-07-01", headers=arm, timeout=30)
check("control plane: admin reads the sandbox group (200)", r.status_code == 200)""",
            """# ...but cannot touch the data plane
r = requests.get(f"{DATA_GROUP_URL}/sandboxes?{DATA_API}", headers=data, timeout=30)
check(f"data plane: admin lists sandboxes -> {r.status_code} (403 expected)", r.status_code == 403)""",
            """# The admin cannot grant itself the data-plane role
def grant(role_name):
    defs = requests.get(
        f"{ARM}/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization/roleDefinitions"
        f"?api-version=2022-04-01&$filter=roleName eq '{role_name}'", headers=arm, timeout=30).json()
    name = uuid.uuid5(uuid.NAMESPACE_DNS, "demo-" + role_name)  # fixed name keeps the demo repeatable
    body = {"properties": {"roleDefinitionId": defs["value"][0]["id"], "principalId": ADMIN_OID, "principalType": "ServicePrincipal"}}
    return requests.put(f"{ARM}{GROUP_SCOPE}/providers/Microsoft.Authorization/roleAssignments/{name}?api-version=2022-04-01",
                        headers=arm, json=body, timeout=30)

r = grant("Reader")
check(f"admin assigns itself Reader -> {r.status_code} (allowed by the condition; 409 means it already exists)", r.status_code in (200, 201, 409))
r = grant("Container Apps SandboxGroup Data Owner")
check(f"admin assigns itself Data Owner -> {r.status_code} (blocked by the condition)", r.status_code == 403)""",
            """# The orchestrator, which holds Data Owner, can use the data plane
r = requests.get(f"{DATA_GROUP_URL}/sandboxes?{DATA_API}", headers=token("orchestrator", "data"), timeout=30)
check("orchestrator lists sandboxes (200)", r.status_code == 200)""",
        ],
        caveat="This holds only for identities that cannot assign roles on the group's scope. Anyone with Owner, User Access Administrator, or tenant-level elevation can grant themselves Data Owner. The scope must be owned by a separate security authority (see the Requirement 1 section of `sandbox-approach.md`).",
    ),
    2: dict(
        title="Explicit plaintext boundary",
        text="Only the trusted calling application and the approved execution environment may handle sensitive plaintext.",
        covered="Both",
        how="The orchestrator encrypts data client side with a per-session key and uploads ciphertext. Plaintext exists only in the orchestrator and in the session's own sandbox after the key is installed there.",
        cells=[
            """from helpers import *
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
sandbox, session_id = new_session()
print("session", session_id)""",
            """session_key = install_session_key(sandbox, session_id)
plaintext = b'{"client": "Acme", "matter": "Project Falcon", "amount": 1200}'
nonce = os.urandom(12)
ciphertext = nonce + AESGCM(session_key).encrypt(nonce, plaintext, session_id.encode())
sandbox.write_file("/tmp/input.enc", ciphertext)
stored = sandbox.read_file("/tmp/input.enc")
check("what the platform stores is ciphertext, not plaintext", b"Falcon" not in stored and stored == ciphertext)
check("the plaintext never appears in the sandbox config or labels", b"Falcon" not in str(sandbox.get()).encode())""",
            """cleanup(sandbox)
check("session deleted", not list(orchestrator().list_sandboxes(labels={"session": session_id})))""",
        ],
        caveat="Anyone with Data Owner on the group can still read the sandbox, including keys and plaintext in memory. The plaintext boundary is enforced by keeping that role to the orchestrator.",
    ),
    3: dict(
        title="Tamper resistance",
        text="Administrator changes to the execution environment must either preserve confidentiality or cause the application to reject the environment before releasing sensitive information.",
        covered="Both",
        how="Prevention: administrators have no data-plane rights, so they cannot change a running sandbox. Detection: before releasing data the orchestrator reads the configuration back and fails closed on any difference.",
        cells=[
            """from helpers import *
sandbox, session_id = new_session()""",
            """results = verify_session(sandbox)
for name, ok in results.items():
    check(name, ok)
print("release data?", all(results.values()))""",
            """# Simulate tampering: loosen egress after the session was approved
sandbox.set_egress_default("Allow")
results = verify_session(sandbox)
check("read-back detects the change", not results["egress default is Deny"])
print("release data?", all(results.values()), "-> the orchestrator fails closed and destroys the session")""",
            """cleanup(sandbox)""",
        ],
        caveat="Only a data-plane holder could make this change in practice, so the demo performs it as the orchestrator to show the detection. Control-plane policy and locks add a further layer.",
    ),
    4: dict(
        title="Verified execution identity",
        text="Before releasing secrets or data, the application must independently establish that it is communicating with the approved execution environment and configuration.",
        covered="Both",
        how="Entra-authenticated TLS identifies the platform endpoint, and the orchestrator checks that the sandbox resolved to the approved image id. This is image-based verification rooted in the platform and Entra, not hardware attestation.",
        cells=[
            """from helpers import *
sandbox, session_id = new_session()""",
            """# The data plane only accepts Entra tokens for its own audience
r = requests.get(f"{DATA_GROUP_URL}/sandboxes?{DATA_API}", timeout=30)
check(f"no token -> {r.status_code} (rejected)", r.status_code in (401, 403))
r = requests.get(f"{DATA_GROUP_URL}/sandboxes?{DATA_API}", headers=token("orchestrator", "arm"), timeout=30)
check(f"token for the wrong audience (ARM) -> {r.status_code} (rejected)", r.status_code in (401, 403))""",
            """# The image the session resolved to is compared with the approved id
info = sandbox.get()
print("resolved image id:", info.sources_ref.disk_image.id)
check("image is the approved one", info.sources_ref.disk_image.id == APPROVED_DISK_ID)
check("an unapproved expected id fails closed", info.sources_ref.disk_image.id != "00000000-0000-0000-0000-000000000000")""",
            """cleanup(sandbox)""",
        ],
        caveat="There is no customer-verifiable hardware attestation. The trust root is the Azure platform and Entra. If Contoso requires hardware attestation, this requirement is not met by sandboxes.",
    ),
    5: dict(
        title="Accept availability attacks",
        text="Administrators may be able to stop, delete, or disrupt sessions. Those actions must cause failure, not disclosure.",
        covered="Caller",
        how="The orchestrator treats any disruption of a session as a failure, discards the session key, and retries only in a new environment with new secrets.",
        cells=[
            """from helpers import *
sandbox, session_id = new_session()
session_key = install_session_key(sandbox, session_id)
print("session", session_id, "established")""",
            """# Someone deletes the sandbox mid-session
orchestrator().delete_sandbox(sandbox.sandbox_id)
try:
    sandbox.exec("echo still here")
    outcome = "operation succeeded"
except Exception as e:
    outcome = f"failed ({type(e).__name__})"
print("next operation:", outcome)
check("disruption produces failure, not disclosure", outcome.startswith("failed"))""",
            """# The orchestrator discards the key and starts over in a new environment
del session_key
sandbox2, session_id2 = new_session()
check("a retry uses a new session id", session_id2 != session_id)
cleanup(sandbox2)""",
        ],
        caveat="An administrator with enough rights could still delete the sandbox. Availability is not protected; confidentiality is.",
    ),
    6: dict(
        title="User authorization",
        text="Authenticate and authorize the requesting user before creating or accessing a session.",
        covered="Caller",
        how="This is the calling application's job and the platform does not provide it. The pattern below shows the orchestrator mapping each session to the user who created it, requiring an approved group, and refusing any other user.",
        cells=[
            """from helpers import *
APPROVED_GROUP = "contoso-interpreter-users"
sessions = {}   # session id -> owning user object id

def create_session(user_oid, user_groups):
    if APPROVED_GROUP not in user_groups:
        raise PermissionError("user is not authorized to create a session")
    session_id = uuid.uuid4().hex[:8]
    sessions[session_id] = user_oid
    return session_id

def access_session(user_oid, session_id):
    if sessions.get(session_id) != user_oid:
        raise PermissionError("session belongs to another user")
    return "access granted"
""",
            """alice = "00000000-aaaa-0000-0000-000000000001"
bob = "00000000-bbbb-0000-0000-000000000002"
sid = create_session(alice, [APPROVED_GROUP])
check("authorized user creates a session", sid in sessions)
check("owner accesses it", access_session(alice, sid) == "access granted")
for label, call in [("user outside the group creates", lambda: create_session(bob, [])),
                    ("another user accesses it", lambda: access_session(bob, sid))]:
    try:
        call(); ok = False
    except PermissionError:
        ok = True
    check(f"{label} -> denied", ok)""",
        ],
        caveat="This is an illustration of the caller-side pattern. In production the user identity comes from the Entra token presented to the interpreter tool (for example an MCP endpoint in a Foundry Toolbox).",
    ),
    7: dict(
        title="Least-privilege application identity",
        text="Give the calling application only the Azure permissions needed to provision, operate, and destroy the execution resources.",
        covered="Both",
        how="The orchestrator service principal holds one role, **Container Apps SandboxGroup Data Owner**, scoped to a single sandbox group. It has no Contributor, Owner, or role-assignment rights.",
        cells=[
            """from helpers import *
import subprocess, json
out = subprocess.run(
    ["az", "role", "assignment", "list", "--all", "--assignee", ORCH_OID, "-o", "json"],
    capture_output=True, text=True, shell=True).stdout
assignments = json.loads(out)
for a in assignments:
    print(a["roleDefinitionName"], "@", a["scope"].split("/providers/")[-1])""",
            """check("exactly one role assignment", len(assignments) == 1)
check("the role is SandboxGroup Data Owner", assignments[0]["roleDefinitionName"] == "Container Apps SandboxGroup Data Owner")
check("scoped to the one sandbox group, not the subscription", assignments[0]["scope"].lower() == GROUP_SCOPE.lower())""",
            """# Negative test: the orchestrator cannot manage Azure resources or assign roles
r = requests.get(f"{ARM}/subscriptions/{SUBSCRIPTION}/resourcegroups?api-version=2021-04-01", headers=token("orchestrator", "arm"), timeout=30)
print("orchestrator lists resource groups ->", r.status_code, "| groups visible:", len(r.json().get("value", [])) if r.status_code == 200 else 0)
check("orchestrator has no control-plane reach", r.status_code in (401, 403) or not r.json().get("value"))""",
        ],
        caveat="Data Owner is the only documented data-plane role, so it cannot be narrowed further today.",
    ),
    8: dict(
        title="Restricted access",
        text="The interpreter must not be directly exposed to the public internet. Restrict inbound access to approved systems. Private connectivity from on-premises is not required.",
        covered="Sandbox",
        how="The data plane accepts only Entra-authenticated callers with the Data Owner role, there are no access keys, and sandboxes expose no ports unless asked to.",
        cells=[
            """from helpers import *
sandbox, session_id = new_session()""",
            """url = f"{DATA_GROUP_URL}/sandboxes?{DATA_API}"
r = requests.get(url, timeout=30)
check(f"anonymous caller -> {r.status_code}", r.status_code in (401, 403))
r = requests.get(url, headers=token("admin", "data"), timeout=30)
check(f"authenticated but not approved (admin) -> {r.status_code}", r.status_code == 403)
r = requests.get(url, headers=token("orchestrator", "data"), timeout=30)
check(f"approved orchestrator -> {r.status_code}", r.status_code == 200)""",
            """check("the session exposes no ports", not sandbox.get().ports)""",
            """cleanup(sandbox)""",
        ],
        caveat="The data plane has no documented private endpoint, so it is reachable from the internet to authenticated callers. The requirement was relaxed accordingly; add conditional access on the orchestrator for network restrictions.",
    ),
    9: dict(
        title="Protected communications",
        text="Encrypt and authenticate sensitive traffic end to end between the trusted application and approved execution environment. Network location alone must not establish trust.",
        covered="Both",
        how="Transport is TLS to an Entra-authenticated endpoint. Because the platform terminates TLS, the orchestrator adds application-layer encryption so data is protected end to end.",
        cells=[
            """from helpers import *
import socket, ssl
host = f"management.{REGION}.azuredevcompute.io"
with socket.create_connection((host, 443), timeout=15) as raw:
    with ssl.create_default_context().wrap_socket(raw, server_hostname=host) as tls:
        print("TLS version:", tls.version())
        print("certificate issuer:", dict(x[0] for x in tls.getpeercert()["issuer"]).get("organizationName"))
        tls_version = tls.version()
check("transport is TLS 1.2 or newer with a validated certificate", tls_version in ("TLSv1.2", "TLSv1.3"))""",
            """from cryptography.hazmat.primitives.ciphers.aead import AESGCM
sandbox, session_id = new_session()
session_key = install_session_key(sandbox, session_id)
secret = b"privileged: merger terms for Project Falcon"
nonce = os.urandom(12)
payload = nonce + AESGCM(session_key).encrypt(nonce, secret, session_id.encode())
check("the application-layer payload contains no plaintext", b"Falcon" not in payload)
sandbox.write_file("/tmp/payload.enc", payload)
check("only the session key holder can decrypt it", AESGCM(session_key).decrypt(nonce, payload[12:], session_id.encode()) == secret)
cleanup(sandbox)""",
        ],
        caveat="The app-layer encryption protects data on the way in and out, but anyone with data-plane access to the sandbox can read keys and memory. See requirements 1 and 10.",
    ),
}
