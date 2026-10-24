"""Helpers shared by the requirement notebooks. Keeps each notebook focused on the requirement."""
import hashlib
import hmac
import json
import os
import uuid

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from common import (
    ADMIN_OID, ORCH_OID, GROUP_SCOPE, REGION, RESOURCE_GROUP, SANDBOX_GROUP, SUBSCRIPTION, credential, sandbox_group_client,
)

ARM = "https://management.azure.com"
DATA = f"https://management.{REGION}.azuredevcompute.io"
DATA_GROUP_URL = f"{DATA}/subscriptions/{SUBSCRIPTION}/resourceGroups/{RESOURCE_GROUP}/sandboxGroups/{SANDBOX_GROUP}"
DATA_API = "api-version=2026-02-01-preview"
DISK = "python-3.12-code-interpreter"
APPROVED_DISK_ID = "b8782cab-82d3-4eaa-880d-24549076ea98"  # id the platform resolves DISK to
# Handler that runs inside the sandbox: ECDH key agreement and per-operation authentication
HANDLER = '''
import hmac, hashlib, json, sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

mode = sys.argv[1]
if mode == "keygen":
    key = X25519PrivateKey.generate()
    open("/tmp/private.bin", "wb").write(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
    print(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex())
    sys.exit(0)
if mode == "install_key":
    session_id = sys.argv[2]
    private = X25519PrivateKey.from_private_bytes(open("/tmp/private.bin", "rb").read())
    peer = X25519PublicKey.from_public_bytes(open("/tmp/peer_public.bin", "rb").read())
    key = HKDF(hashes.SHA256(), 32, None, b"contoso-session|" + session_id.encode()).derive(private.exchange(peer))
    open("/tmp/session_key.bin", "wb").write(key)
    open("/tmp/session_id", "w").write(session_id)
    print("session key derived")
    sys.exit(0)
session_key = open("/tmp/session_key.bin", "rb").read()
req = json.load(open("/tmp/request.json"))
if req.get("session") != open("/tmp/session_id").read():
    print("REJECTED: wrong session"); sys.exit(4)
body = json.dumps(req.get("body"), sort_keys=True)
message = f"{req.get('session')}|{req.get('counter')}|{body}".encode()
expected = hmac.new(session_key, message, hashlib.sha256).hexdigest()
if not hmac.compare_digest(expected, str(req.get("token", ""))):
    print("REJECTED: bad or missing token"); sys.exit(2)
try:
    last = int(open("/tmp/last_counter").read())
except FileNotFoundError:
    last = 0
if req["counter"] <= last:
    print("REJECTED: replay"); sys.exit(3)
open("/tmp/last_counter", "w").write(str(req["counter"]))
print("OK", sum(req["body"]["numbers"]))
'''


def check(label: str, condition: bool) -> None:
    print(f"{'PASS' if condition else 'FAIL'}  {label}")
    assert condition, label


def token(identity: str, scope: str) -> dict:
    """Bearer header for 'orchestrator' or 'admin'; scope is 'arm' or 'data'."""
    audience = "https://management.azure.com/.default" if scope == "arm" else "https://dynamicsessions.io/.default"
    return {"Authorization": "Bearer " + credential(identity).get_token(audience).token}


def orchestrator():
    return sandbox_group_client("orchestrator")


def new_session(labels: dict | None = None, egress_deny: bool = True):
    """Create one per-session sandbox with the approved disk, suspend off, auto-delete as backstop."""
    from azure.containerapps.sandbox import AutoDeletePolicy, AutoSuspendPolicy, LifecyclePolicy

    session_id = uuid.uuid4().hex[:8]
    group = orchestrator()
    sandbox = group.begin_create_sandbox(
        disk=DISK, labels={"purpose": "contoso-demo", "session": session_id, **(labels or {})}
    ).result()
    sandbox.set_lifecycle_policy(
        LifecyclePolicy(
            auto_suspend=AutoSuspendPolicy(enabled=False),
            auto_delete=AutoDeletePolicy(enabled=True, delete_interval_seconds=900),
        )
    )
    if egress_deny:
        sandbox.set_egress_default("Deny")
    return sandbox, session_id


def install_session_key(sandbox, session_id: str) -> bytes:
    """ECDH (X25519) + HKDF: the sandbox makes a key pair, the orchestrator makes an ephemeral one,
    and both derive the same session key. The key itself never travels. Returns the key."""
    sandbox.write_file("/tmp/handler.py", HANDLER)
    sandbox_public = X25519PublicKey.from_public_bytes(bytes.fromhex(sandbox.exec("python /tmp/handler.py keygen").stdout.strip()))
    ephemeral = X25519PrivateKey.generate()
    sandbox.write_file("/tmp/peer_public.bin", ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    sandbox.exec(f"python /tmp/handler.py install_key {session_id}")
    return HKDF(hashes.SHA256(), 32, None, b"contoso-session|" + session_id.encode()).derive(ephemeral.exchange(sandbox_public))


def signed_request(session_key: bytes, session_id: str, counter: int, numbers: list) -> dict:
    body = {"numbers": numbers}
    message = f"{session_id}|{counter}|{json.dumps(body, sort_keys=True)}".encode()
    return {
        "session": session_id,
        "counter": counter,
        "body": body,
        "token": hmac.new(session_key, message, hashlib.sha256).hexdigest(),
    }


def send(sandbox, request: dict) -> str:
    sandbox.write_file("/tmp/request.json", json.dumps(request))
    return sandbox.exec("python /tmp/handler.py op; echo exit=$?").stdout.strip().replace("\n", " ")


def cleanup(*sandboxes) -> None:
    for sandbox in sandboxes:
        try:
            sandbox.delete()
        except Exception:
            pass


def verify_session(sandbox, expected_disk_id: str = APPROVED_DISK_ID) -> dict:
    """Read the configuration back and compare to what the security authority approved."""
    info = sandbox.get()
    return {
        "disk image is the approved one": info.sources_ref.disk_image.id == expected_disk_id,
        "created from a disk, not a snapshot": info.sources_ref.snapshot is None,
        "egress default is Deny": info.egress_policy.default_action == "Deny",
        "no ports exposed": not info.ports,
        "suspend disabled": not info.lifecycle.auto_suspend.enabled,
        "auto-delete enabled": bool(info.lifecycle.auto_delete and info.lifecycle.auto_delete.enabled),
    }
