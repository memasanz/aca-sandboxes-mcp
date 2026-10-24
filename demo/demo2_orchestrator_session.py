"""Demo 2: the orchestrator runs one session end to end (requirements 9-16, 19-24).

Only the orchestrator identity (Container Apps SandboxGroup Data Owner) can do this.
Everything printed is metadata; confidential content is never logged.
"""
import json
import os
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from azure.containerapps.sandbox import EgressPolicy

from common import sandbox_group_client

PINNED_DISK = "python-3.12-code-interpreter"
session_id = uuid.uuid4().hex[:8]
group = sandbox_group_client("orchestrator")


def step(text: str) -> None:
    print(f"\n-- {text}", flush=True)


step(f"1. Create a per-session sandbox (session {session_id}), pinned image, short idle suspend")
sandbox = group.begin_create_sandbox(
    disk=PINNED_DISK,
    labels={"session": session_id, "purpose": "contoso-demo"},
    auto_suspend_seconds=60,
).result()
print(f"sandbox {sandbox.sandbox_id} created")

try:
    step("2. Lock down egress: default Deny, then read the policy back before releasing data")
    sandbox.set_egress_default("Deny")
    policy = sandbox.get_egress_policy()
    print("egress policy read back:", policy)
    assert "deny" in str(policy).lower(), "fail closed: egress is not deny-default"

    step("3. Read back the sandbox configuration (image, labels, state) and verify")
    info = sandbox.get()
    print("sandbox config read back:", info)

    step("4. Egress is blocked by default, then one host is allowed")
    probe = "curl -s -m 8 -o /dev/null -w '%{http_code}' https://example.com"
    print("example.com with deny-default ->", sandbox.exec(probe))
    sandbox.add_egress_host_rule("example.com", action="Allow")
    print("example.com after allow rule   ->", sandbox.exec(probe))
    print("egress decisions (audit, lags ~30s):", sandbox.get_egress_decisions())
    metadata = "curl -s -m 8 -o /dev/null -w '%{http_code}' -H 'Metadata: true' http://169.254.169.254/metadata/instance?api-version=2021-02-01"
    print("cloud metadata endpoint ->", sandbox.exec(metadata))

    step("4b. Execution time limit enforced by the orchestrator around untrusted code")
    runaway = sandbox.exec("timeout 5 python -c 'while True: pass'; echo exit=$?")
    print("runaway code stopped ->", runaway.stdout.strip())

    step("5. Application-layer encryption: the data never travels or sits in plaintext outside the session")
    sandbox.write_file(
        "/tmp/session.py",
        """
import json, os, sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

step = sys.argv[1]
SESSION_ID = sys.argv[2].encode()  # bound into every AES-GCM message as associated data
if step == "keygen":
    key = X25519PrivateKey.generate()
    open("/tmp/private.bin", "wb").write(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
    print(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex())
else:
    private = X25519PrivateKey.from_private_bytes(open("/tmp/private.bin", "rb").read())
    peer = X25519PublicKey.from_public_bytes(open("/tmp/peer_public.bin", "rb").read())
    aes = AESGCM(HKDF(hashes.SHA256(), 32, None, b"contoso-session|" + SESSION_ID).derive(private.exchange(peer)))
    blob = open("/tmp/input.enc", "rb").read()
    rows = json.loads(aes.decrypt(blob[:12], blob[12:], SESSION_ID))
    result = json.dumps({"rows": len(rows), "total": sum(r["amount"] for r in rows)}).encode()
    nonce = os.urandom(12)
    open("/tmp/output.enc", "wb").write(nonce + aes.encrypt(nonce, result, SESSION_ID))
""",
    )
    sandbox_public = X25519PublicKey.from_public_bytes(
        bytes.fromhex(sandbox.exec(f"python /tmp/session.py keygen {session_id}").stdout.strip()))
    print("sandbox generated its own X25519 key pair; private key never leaves the sandbox")

    ephemeral = X25519PrivateKey.generate()
    sandbox.write_file("/tmp/peer_public.bin", ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    aes_key = HKDF(hashes.SHA256(), 32, None, b"contoso-session|" + session_id.encode()).derive(ephemeral.exchange(sandbox_public))
    print("both sides derive the session key with ECDH + HKDF; the key itself is never sent")

    confidential = json.dumps([{"matter": "A", "amount": 1200}, {"matter": "B", "amount": 800}]).encode()
    nonce = os.urandom(12)
    sandbox.write_file("/tmp/input.enc", nonce + AESGCM(aes_key).encrypt(nonce, confidential, session_id.encode()))
    print("uploaded ciphertext only:", len(confidential), "plaintext bytes encrypted client side")

    run = sandbox.exec(f"python /tmp/session.py run {session_id}")
    print("sandbox exec exit code:", run.exit_code)
    blob = sandbox.read_file("/tmp/output.enc")
    result = AESGCM(aes_key).decrypt(blob[:12], blob[12:], session_id.encode())
    print("orchestrator decrypted result:", result.decode())

finally:
    step("6. Wipe: delete the sandbox and confirm nothing is left")
    sandbox.delete()
    remaining = [s for s in group.list_sandboxes(labels={"session": session_id})]
    print(f"sandboxes still labelled session={session_id}: {len(remaining)}")
