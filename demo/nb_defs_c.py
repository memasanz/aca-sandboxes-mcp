"""Notebook definitions for requirements 18-25."""

REQS_C = {
    18: dict(
        title="Separate untrusted-code",
        text="Isolate AI-generated Python from the orchestrator, its credentials, and other sessions.",
        covered="Sandbox",
        how="The generated code runs inside the sandbox micro virtual machine. The orchestrator's credentials live in the orchestrator process, never in the sandbox.",
        cells=[
            """from helpers import *
sandbox, session_id = new_session()
sandbox.write_file("/tmp/untrusted.py", "import os, glob\\nprint('env keys:', sorted(k for k in os.environ if 'SECRET' in k or 'CLIENT' in k or 'AZURE' in k))\\nprint('azure cli config:', glob.glob('/root/.azure*') + glob.glob('/home/*/.azure*'))")
run = sandbox.exec("python /tmp/untrusted.py")
print(run.stdout)
check("no orchestrator credentials in the sandbox environment", "[]" in run.stdout.splitlines()[0])
check("no Azure CLI login state in the sandbox", run.stdout.strip().endswith("[]"))""",
            """secret = os.environ["ORCHESTRATOR_CLIENT_SECRET"]
check("the orchestrator's client secret is not on the sandbox disk",
      sandbox.exec(f"grep -rl --exclude-dir=proc --exclude-dir=sys -F '{secret}' /tmp /home /root /etc 2>/dev/null | wc -l").stdout.strip() == "0")
print("hostname inside the sandbox:", sandbox.exec("hostname").stdout.strip())
cleanup(sandbox)""",
        ],
        caveat="Separation from the orchestrator is by process and machine boundary. Escape from the microVM is a platform property that this demo cannot test.",
    ),
    19: dict(
        title="Resource limits",
        text="Enforce execution timeout and limits on CPU, memory, disk, and output.",
        covered="Both",
        how="The platform fixes CPU, memory and disk per sandbox. The orchestrator enforces a time limit with `timeout` and caps output size before returning results.",
        cells=[
            """from helpers import *
sandbox, session_id = new_session()
info = sandbox.get()
print("resources:", info.resources if hasattr(info, "resources") else "see stats below")
print(sandbox.get_stats())
print(sandbox.exec("nproc; free -m | head -2; df -h / | tail -1").stdout)""",
            """# Timeout: a runaway loop is killed after 5 seconds
run = sandbox.exec("timeout 5 python -c 'while True: pass'")
print("exit code:", run.exit_code)
check("runaway code is killed by the time limit (exit 124)", run.exit_code == 124)""",
            """# Output cap: the orchestrator truncates what it returns
MAX_OUTPUT = 1000
run = sandbox.exec("python -c \\"print('x' * 100000)\\"")
returned = run.stdout[:MAX_OUTPUT]
print(f"sandbox produced {len(run.stdout)} chars; orchestrator returns {len(returned)}")
check("output is capped", len(returned) == MAX_OUTPUT)
cleanup(sandbox)""",
        ],
        caveat="CPU, memory and disk are sized when the sandbox is created and cannot be changed by the generated code. The time limit and output cap are the orchestrator's own logic.",
    ),
    20: dict(
        title="Restricted outbound access",
        text="Prevent arbitrary internet access, package installation, and metadata-endpoint access.",
        covered="Sandbox",
        how="The sandbox egress policy is deny-by-default. Only hosts on an explicit allow-list are reachable. Decisions are logged.",
        cells=[
            """from helpers import *
sandbox, session_id = new_session()
print("default action:", sandbox.get().egress_policy.default_action)
def code(url):
    return sandbox.exec(f"curl -s -o /dev/null -m 10 -w '%{{http_code}}' {url}").stdout.strip()
blocked = code("https://example.com")
print("example.com ->", blocked)
check("arbitrary internet is blocked", blocked != "200")""",
            """pip = sandbox.exec("pip install requests-toolbelt 2>&1 | tail -2")
print(pip.stdout)
check("package installation from the internet is blocked", "Successfully installed" not in pip.stdout)
meta = sandbox.exec("curl -s -m 5 -H 'Metadata: true' http://169.254.169.254/metadata/instance?api-version=2021-02-01; echo exit=$?")
print("metadata endpoint ->", meta.stdout.strip()[:120])
check("cloud metadata endpoint is unreachable", "compute" not in meta.stdout)""",
            """sandbox.add_egress_host_rule("example.com", action="Allow")
import time; time.sleep(3)
allowed = code("https://example.com")
print("example.com after allow rule ->", allowed)
check("allow-listed host is reachable", allowed == "200")
check("other hosts stay blocked", code("https://www.bing.com") != "200")
cleanup(sandbox)""",
        ],
        caveat="Egress decisions appear in the audit with about 30 seconds of delay and include host, method and path, which is why the orchestrator's log policy must treat them as sensitive (requirement 23).",
    ),
    21: dict(
        title="Protected temporary data",
        text="Avoid persistent plaintext storage. Establish where temporary files live and ensure they are destroyed.",
        covered="Sandbox",
        how="Working files live on the sandbox's local disk only, with no shared volumes or snapshots. When the sandbox is deleted its disk goes with it, and a new sandbox starts clean.",
        cells=[
            """from helpers import *
sandbox, session_id = new_session()
info = sandbox.get()
print("volumes/mounts:", getattr(info, "volumes", None) or getattr(info, "mounts", None) or "none")
check("no snapshot source", info.sources_ref.snapshot is None)
sandbox.write_file("/work/plaintext.txt", "CONFIDENTIAL-MARKER-" + session_id)
print(sandbox.exec("df -h /work | tail -1").stdout)
print("file lives on:", sandbox.exec("findmnt -no SOURCE,FSTYPE -T /work").stdout.strip())""",
            """marker = "CONFIDENTIAL-MARKER-" + session_id
cleanup(sandbox)
check("sandbox is gone", not list(orchestrator().list_sandboxes(labels={"session": session_id})))
# A new sandbox from the same disk does not contain the old file (indirect wipe evidence)
fresh, _ = new_session()
check("new sandbox has no trace of the old file", fresh.exec("ls /work/plaintext.txt 2>&1").stdout.find("No such file") >= 0)
check("marker text not found anywhere on the new disk", fresh.exec(f"grep -rl --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev -F '{marker}' / 2>/dev/null | wc -l").stdout.strip() == "0")
cleanup(fresh)""",
        ],
        caveat="Disk wipe on delete is shown only indirectly. A new sandbox starting clean is evidence, not proof that the old blocks were scrubbed. Ask Microsoft for a written statement if Contoso needs it.",
    ),
    22: dict(
        title="Direct result delivery",
        text="Return sensitive results through the protected session channel only.",
        covered="Caller",
        how="The sandbox encrypts the result with the session key before it leaves, and the orchestrator decrypts it. The result is never written to shared storage or sent through another service.",
        cells=[
            """from helpers import *
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
sandbox, session_id = new_session()
session_key = install_session_key(sandbox, session_id)
sandbox.write_file("/tmp/encrypt_result.py", '''
import os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key = open("/tmp/session_key.bin", "rb").read()
nonce = os.urandom(12)
sid = sys.argv[1].encode()
open("/tmp/result.enc", "wb").write(nonce + AESGCM(key).encrypt(nonce, b"total=2000", sid))
''')
print(sandbox.exec(f"python /tmp/encrypt_result.py {session_id}"))""",
            """blob = sandbox.read_file("/tmp/result.enc")
print("what travels back:", blob.hex()[:48], "...")
check("the returned bytes are not readable plaintext", b"total" not in blob)
plain = AESGCM(session_key).decrypt(blob[:12], blob[12:], session_id.encode())
print("orchestrator decrypts:", plain)
check("orchestrator recovers the result", plain == b"total=2000")""",
            """try:
    AESGCM(session_key).decrypt(blob[:12], blob[12:], b"other-session")
    check("wrong session binding rejected", False)
except Exception:
    check("wrong session binding rejected", True)
cleanup(sandbox)""",
        ],
        caveat="The result channel is protected by the session key. It does not stop a Data Owner holder from reading the file inside the sandbox, so the role restriction (requirement 1) still matters.",
    ),
    23: dict(
        title="Content-free operational telemetry",
        text="Record lifecycle events, verification outcomes, and resource identifiers only, never prompts, files, results, or secrets.",
        covered="Both",
        how="The orchestrator writes a metadata-only log. The Azure Activity Log records only management actions. We scan it to confirm that no session content shows up.",
        cells=[
            """from helpers import *
import json, logging, time
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", force=True)
log = logging.getLogger("orchestrator")
sandbox, session_id = new_session()
session_key = install_session_key(sandbox, session_id)
marker = "CONFIDENTIAL-" + session_id
sandbox.write_file("/work/doc.txt", marker)
# What the orchestrator logs: identifiers, outcomes, durations. Never contents.
log.info(json.dumps({"event": "session_created", "session": session_id, "sandbox": sandbox.sandbox_id}))
log.info(json.dumps({"event": "verification", "session": session_id, "passed": all(verify_session(sandbox).values())}))
log.info(json.dumps({"event": "session_deleted", "session": session_id}))
cleanup(sandbox)""",
            """import subprocess
raw = subprocess.run(
    f"az monitor activity-log list --resource-group {RESOURCE_GROUP} --offset 1h -o json",
    capture_output=True, text=True, shell=True).stdout
events = json.loads(raw or "[]")
print("activity log events in the last hour:", len(events))
print("operations seen:", sorted({e["operationName"]["localizedValue"] for e in events})[:6])
check("the Activity Log contains no session content", marker not in raw)""",
            """# Diagnostic settings on the sandbox group: which log categories exist?
diag = subprocess.run(
    f"az monitor diagnostic-settings categories list --resource {GROUP_SCOPE} -o json",
    capture_output=True, text=True, shell=True).stdout
print(diag[:600] or "no diagnostic categories returned")
categories = [(c["name"], c["categoryType"]) for c in json.loads(diag or "{}").get("value", [])]
print("categories:", categories)
check("the group offers metrics only, no content log category", all(kind == "Metrics" for _, kind in categories))""",
        ],
        caveat="Egress audit entries record host, method and URL path, which can reveal content. Treat that audit as sensitive. The orchestrator's log discipline is code Contoso must write and review.",
    ),
    24: dict(
        title="Approved, immutable deployment",
        text="Build and approve a known interpreter image. Reject anything else.",
        covered="Both",
        how="The orchestrator holds the approved image ID. It compares it with the ID the sandbox actually resolved and refuses to release data on a mismatch (fail closed).",
        cells=[
            """from helpers import *
sandbox, session_id = new_session()
resolved = sandbox.get().sources_ref.disk_image.id
print("approved:", APPROVED_DISK_ID)
print("resolved:", resolved)
check("sandbox runs the approved image", resolved == APPROVED_DISK_ID)""",
            """# Fail closed: pretend the approved ID is different and confirm the check refuses
results = verify_session(sandbox, expected_disk_id="00000000-0000-0000-0000-000000000000")
print(results)
def release_data_if_verified(checks):
    if not all(checks.values()):
        raise PermissionError("verification failed; nothing released")
    return "released"
try:
    release_data_if_verified(results)
    check("mismatched image is refused", False)
except PermissionError as err:
    check(f"mismatched image is refused ({err})", True)
check("correct image is released", release_data_if_verified(verify_session(sandbox)) == "released")
cleanup(sandbox)""",
        ],
        caveat="This pins the platform's public image by ID. A private disk image built from Contoso's own approved container would pin their build, and is the production recommendation.",
    ),
    25: dict(
        title="Demonstrable enforcement",
        text="Prove these controls through a working implementation and negative tests.",
        covered="Caller",
        how="This notebook runs the key negative tests in one pass and prints a pass/fail table. Each test tries to break a control and expects it to hold.",
        cells=[
            """from helpers import *
import requests
results = {}
def test(name, fn):
    try:
        results[name] = bool(fn())
    except Exception as err:
        results[name] = False
        print("error in", name, "->", type(err).__name__, str(err)[:100])""",
            """# Administrator tries to read sandbox contents
def admin_denied():
    url = f"{DATA_GROUP_URL}/sandboxes?{DATA_API}"
    return requests.get(url, headers=token("admin", "data"), timeout=30).status_code == 403
test("1  admin cannot list sandboxes on the data plane", admin_denied)

# Administrator tries to grant itself Data Owner
def self_grant_denied():
    import uuid
    defs = requests.get(f"{ARM}{GROUP_SCOPE}/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01&$filter=roleName eq 'Container Apps SandboxGroup Data Owner'",
                        headers=token("orchestrator", "arm"), timeout=30).json()
    body = {"properties": {"roleDefinitionId": defs["value"][0]["id"], "principalId": ADMIN_OID, "principalType": "ServicePrincipal"}}
    r = requests.put(f"{ARM}{GROUP_SCOPE}/providers/Microsoft.Authorization/roleAssignments/{uuid.uuid4()}?api-version=2022-04-01",
                     headers=token("admin", "arm"), json=body, timeout=30)
    return r.status_code in (403,)
test("1  admin cannot grant itself Data Owner", self_grant_denied)""",
            """sandbox, session_id = new_session()
other, other_id = new_session()
key = install_session_key(sandbox, session_id)
install_session_key(other, other_id)
test("3  tampered configuration is detected", lambda: not all(verify_session(sandbox, expected_disk_id="bad").values()))
test("10 replayed request is rejected", lambda: (send(sandbox, signed_request(key, session_id, 1, [1])), "replay" in send(sandbox, signed_request(key, session_id, 1, [1])))[1])
test("10 request signed with the wrong key is rejected", lambda: "REJECTED" in send(sandbox, signed_request(os.urandom(32), session_id, 5, [1])))
test("13 sessions are isolated", lambda: "No such file" in (sandbox.write_file("/tmp/a.txt", "x"), other.exec("cat /tmp/a.txt 2>&1").stdout)[1])
test("19 runaway code is stopped", lambda: sandbox.exec("timeout 3 python -c 'while True: pass'").exit_code == 124)
test("20 internet is blocked", lambda: sandbox.exec("curl -s -o /dev/null -m 8 -w '%{http_code}' https://example.com").stdout.strip() != "200")
test("14 suspend is disabled", lambda: not sandbox.get().lifecycle.auto_suspend.enabled)""",
            """cleanup(sandbox, other)
test("15 sessions are gone after cleanup", lambda: not list(orchestrator().list_sandboxes(labels={"session": session_id})))
print()
for name, ok in results.items():
    print("PASS" if ok else "FAIL", name)
check("all negative tests held", all(results.values()))""",
        ],
        caveat="Restart and interruption tests (orchestrator crash mid-session, network drop) are not yet covered, and should be added before Contoso relies on requirement 14 in production.",
    ),
}
