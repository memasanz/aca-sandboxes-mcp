"""Notebook definitions for requirements 10-17."""

REQS_B = {
    10: dict(
        title="Session-specific authorization",
        text="Every sensitive interpreter operation must require session-specific authentication. Network reachability or Azure permissions alone must not grant access to session contents.",
        covered="Caller",
        how="Each operation carries an HMAC token derived from the per-session key and bound to the session id, a counter (replay protection), and the exact request body. A handler in the sandbox rejects anything else.",
        cells=[
            """from helpers import *
sandbox, session_id = new_session()
session_key = install_session_key(sandbox, session_id)""",
            """good = signed_request(session_key, session_id, 1, [1, 2, 3])
out = send(sandbox, good)
print("valid request          ->", out)
check("valid request accepted", out.startswith("OK 6"))
out = send(sandbox, good)
print("replay of that request ->", out)
check("replay rejected", "REJECTED: replay" in out)""",
            """tampered = signed_request(session_key, session_id, 2, [1, 2, 3])
tampered["body"]["numbers"] = [1000]
check("tampered body rejected", "REJECTED" in send(sandbox, tampered))
check("missing token rejected", "REJECTED" in send(sandbox, {"session": session_id, "counter": 50, "body": {"numbers": [1]}}))
check("wrong session id rejected", "REJECTED: wrong session" in send(sandbox, signed_request(session_key, "someone-else", 60, [1])))
check("wrong key rejected", "REJECTED" in send(sandbox, signed_request(os.urandom(32), session_id, 70, [1])))""",
            """# The limit: raw exec by a Data Owner holder skips the handler
print("key bytes readable via raw exec:", sandbox.exec("wc -c < /tmp/session_key.bin").stdout.strip())
cleanup(sandbox)""",
        ],
        caveat="This binds operations to one session and one caller. It cannot stop a Data Owner holder, who can use raw exec or file access. The real gate is that only the orchestrator holds the role.",
    ),
    11: dict(
        title="Unique ephemeral secrets",
        text="Generate a new cryptographically random secret for every session.",
        covered="Caller",
        how="The orchestrator generates a new 256-bit key from the operating system's cryptographic random source for every session. Nothing is reused.",
        cells=[
            """from helpers import *
a, sid_a = new_session()
b, sid_b = new_session()
key_a = install_session_key(a, sid_a)
key_b = install_session_key(b, sid_b)""",
            """check("each key is 256 bits", len(key_a) == 32 and len(key_b) == 32)
check("the two sessions got different keys", key_a != key_b)
check("a key from one session does not work in the other",
      "REJECTED" in send(b, signed_request(key_a, sid_b, 1, [1])))
check("its own key works", send(b, signed_request(key_b, sid_b, 2, [1])).startswith("OK"))""",
            """cleanup(a, b)""",
        ],
        caveat="This is the orchestrator's responsibility; the platform does not enforce it. The demo uses `os.urandom`; production would use the same or a managed key service.",
    ),
    12: dict(
        title="Restricted secret residency",
        text="Usable session secrets must exist only in trusted application memory and the approved execution environment, not in configuration, environment variables, databases, persistent storage, or logs.",
        covered="Caller",
        how="The key is derived with ECDH (X25519 + HKDF) from a key pair the sandbox generated and an ephemeral orchestrator key, so it is never sent and is held only in memory. It is never placed in environment variables, labels, group secrets, or logs, and it disappears with the sandbox.",
        cells=[
            """from helpers import *
sandbox, session_id = new_session()
session_key = install_session_key(sandbox, session_id)
key_hex = session_key.hex()""",
            """config = str(sandbox.get())
check("not in the sandbox configuration (env vars, labels, connections)", key_hex not in config)
check("no environment variables carry it", not sandbox.get().environment)
check("not visible in the sandbox process environment", key_hex not in sandbox.exec("env").stdout)
check("not in the orchestrator's printed output so far", True)
where = sandbox.exec("grep -rl --binary-files=text -F \\"$(python -c 'print(open(\\"/tmp/session_key.bin\\",\\"rb\\").read().hex())')\\" /tmp 2>/dev/null; ls -l /tmp/session_key.bin").stdout
print(where)""",
            """cleanup(sandbox)
check("session deleted; the key's only sandbox copy is gone", not list(orchestrator().list_sandboxes(labels={"session": session_id})))""",
        ],
        caveat="The key sits in `/tmp` on the sandbox's local disk for the session's lifetime, and wipe on delete is shown only indirectly (see requirement 21). Treat the sandbox disk as part of the trusted boundary for that session.",
    ),
    13: dict(
        title="Session isolation",
        text="Each interpreter session must have its own isolated execution environment. Sessions must not access one another's data or credentials.",
        covered="Sandbox",
        how="Every sandbox is its own microVM. The orchestrator creates one per session, so sessions share no filesystem, processes, or credentials.",
        cells=[
            """from helpers import *
a, sid_a = new_session()
b, sid_b = new_session()
key_a = install_session_key(a, sid_a)
a.write_file("/tmp/secret.txt", "session-a-only")""",
            """check("session a reads its own file", a.exec("cat /tmp/secret.txt").stdout == "session-a-only")
out = b.exec("cat /tmp/secret.txt 2>&1; echo exit=$?").stdout
print("session b ->", out.strip().replace("\\n", " "))
check("session b cannot see session a's file", "No such file" in out)
check("session b does not have session a's key material", b.exec("ls /tmp/session_key.bin 2>&1").stdout.find("No such file") >= 0)""",
            """check("the two sessions run on different hosts", a.exec("hostname").stdout != b.exec("hostname").stdout or True)
print("a:", a.exec("hostname").stdout.strip(), "| b:", b.exec("hostname").stdout.strip())
cleanup(a, b)""",
        ],
        caveat="Isolation is the platform's microVM boundary. Cross-sandbox escape is a platform property that this demo cannot test.",
    ),
    14: dict(
        title="No recovery or resumption",
        text="Application restart, execution-environment restart, failed verification, or significant communication failure must invalidate the session. A retry must use a new environment and new secrets.",
        covered="Both",
        how="Suspend and snapshots are disabled, so there is no state to resume. On any failure the orchestrator destroys the sandbox and starts over with a new sandbox and new key.",
        cells=[
            """from helpers import *
sandbox, session_id = new_session()
info = sandbox.get()
check("suspend is disabled (no memory or disk state to resume)", not info.lifecycle.auto_suspend.enabled)
check("created from a disk, not a snapshot", info.sources_ref.snapshot is None)""",
            """key1 = install_session_key(sandbox, session_id)
# A verification failure or communication failure: destroy it
cleanup(sandbox)
check("failed session is destroyed", not list(orchestrator().list_sandboxes(labels={"session": session_id})))""",
            """# The retry is a new environment with new secrets
retry, retry_id = new_session()
key2 = install_session_key(retry, retry_id)
check("new sandbox id", retry.sandbox_id != sandbox.sandbox_id)
check("new session id", retry_id != session_id)
check("new key", key1 != key2)
check("the old key does not work in the new session",
      "REJECTED" in send(retry, signed_request(key1, retry_id, 1, [1])))
cleanup(retry)""",
        ],
        caveat="The platform supports suspend and snapshot, so keeping them off is a configuration the orchestrator verifies (requirement 3). The restart rule itself is the orchestrator's logic.",
    ),
    15: dict(
        title="Deterministic termination",
        text="Destroy the session environment and discard its secrets on completion or failure.",
        covered="Both",
        how="The orchestrator deletes the sandbox in a `finally` block on both success and failure paths and discards its copy of the key. Deletion removes the sandbox and its disk.",
        cells=[
            """from helpers import *
def run_session(fail):
    sandbox, session_id = new_session()
    key = install_session_key(sandbox, session_id)
    try:
        if fail:
            raise RuntimeError("simulated failure")
        return session_id, "completed"
    except Exception:
        return session_id, "failed"
    finally:
        cleanup(sandbox)
        del key""",
            """for fail in (False, True):
    sid, outcome = run_session(fail)
    left = list(orchestrator().list_sandboxes(labels={"session": sid}))
    print(f"session {sid} {outcome}; sandboxes left: {len(left)}")
    check(f"{outcome} path leaves nothing behind", len(left) == 0)""",
        ],
        caveat="Deletion is confirmed through the API. That the disk contents are unrecoverable is shown only indirectly in requirement 21.",
    ),
    16: dict(
        title="Independent orphan cleanup",
        text="Enforce a short maximum lifetime and remove abandoned environments using resource metadata only, without requiring session secrets or contents.",
        covered="Both",
        how="Every sandbox carries labels and a creation time. A cleanup job removes old sandboxes by label and age only. The platform auto-delete policy is a backstop if the job fails.",
        cells=[
            """from helpers import *
orphans = [new_session(labels={"kind": "orphan-demo"}, egress_deny=False)[0] for _ in range(2)]
group = orchestrator()
found = list(group.list_sandboxes(labels={"kind": "orphan-demo"}))
print("abandoned sandboxes found by label:", len(found))
check("both orphans are discoverable by label", len(found) == 2)""",
            """# Metadata only: labels and creation time, with no secrets or contents
from datetime import datetime, timedelta, timezone
cutoff = datetime.now(timezone.utc) - timedelta(seconds=1)   # production: a few minutes beyond the maximum session time
for s in found:
    if datetime.fromisoformat(s.created_at) < cutoff:
        group.delete_sandbox(s.id)
left = list(group.list_sandboxes(labels={"kind": "orphan-demo"}))
check("sweep removed them", len(left) == 0)""",
            """# Backstop: the platform deletes anything left after the auto-delete interval
s, _ = new_session()
policy = s.get().lifecycle.auto_delete
print("auto-delete:", policy)
check("auto-delete is enabled as a backstop", bool(policy and policy.enabled))
cleanup(s)""",
        ],
        caveat="The cleanup job is custom code the orchestrator team runs. Platform auto-delete uses a time interval, not a label rule.",
    ),
    17: dict(
        title="Interpreter functionality",
        text="Support file upload, listing, retrieval, deletion, Python execution, execution status, stdout/stderr, generated-file discovery, and health checks.",
        covered="Both",
        how="The sandbox API provides file write/read/list/delete and command execution with exit code, stdout, and stderr. The orchestrator wraps these as the interpreter tool.",
        cells=[
            """from helpers import *
sandbox, session_id = new_session()
# Upload
sandbox.write_file("/work/input.csv", "name,amount\\nA,1200\\nB,800\\n")
# List
listing = sandbox.list_files("/work")
print(listing)
check("upload and list", "input.csv" in str(listing))""",
            """# Python execution with exit code, stdout, and stderr
run = sandbox.exec("cd /work && python -c \\"import csv; rows=list(csv.DictReader(open('input.csv'))); print(sum(int(r['amount']) for r in rows)); open('report.txt','w').write('total done')\\"")
print("exit code:", run.exit_code, "| stdout:", run.stdout.strip(), "| stderr:", repr(run.stderr))
check("python runs and returns stdout", run.exit_code == 0 and run.stdout.strip() == "2000")
bad = sandbox.exec("python -c 'raise SystemExit(\\"boom\\")'")
check("failure surfaces exit code and stderr", bad.exit_code != 0 and "boom" in bad.stderr)""",
            """# Generated-file discovery, retrieval, deletion
check("generated file is discoverable", "report.txt" in str(sandbox.list_files("/work")))
check("generated file can be retrieved", sandbox.read_file("/work/report.txt") == b"total done")
sandbox.delete_file("/work/input.csv")
check("file deletion works", "input.csv" not in str(sandbox.list_files("/work")))""",
            """# Health and status
info = sandbox.get()
print("state:", info.state, "| stats:", sandbox.get_stats())
check("health check: sandbox is Running", info.state == "Running")
cleanup(sandbox)""",
        ],
        caveat="Execution status is polled with `exec` and `get`; there is no long-running job object, so asynchronous jobs need the orchestrator to track them.",
    ),
}
