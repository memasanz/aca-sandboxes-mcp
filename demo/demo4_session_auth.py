"""Demo 4: per-operation session authentication (requirement 10).

Every operation carries an HMAC token derived from the per-session key, bound to the
session id, a counter (replay protection) and the exact request body. The sandbox-side
handler rejects anything else. A Data Owner holder can still bypass the handler with raw exec;
that limit is shown at the end.
"""
import hashlib
import hmac
import json
import os
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from common import sandbox_group_client

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

# mode == "op": authenticate the request before touching its contents
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

session_id = uuid.uuid4().hex[:8]
group = sandbox_group_client("orchestrator")
sandbox = group.begin_create_sandbox(disk="python-3.12-code-interpreter", labels={"session": session_id}).result()


def step(text: str) -> None:
    print(f"\n-- {text}", flush=True)


def send(request: dict) -> str:
    sandbox.write_file("/tmp/request.json", json.dumps(request))
    return sandbox.exec("python /tmp/handler.py op; echo exit=$?").stdout.strip().replace("\n", " ")


counter = 0


def signed(numbers: list, session: str = session_id, key: bytes | None = None) -> dict:
    global counter
    counter += 1
    body = {"numbers": numbers}
    message = f"{session}|{counter}|{json.dumps(body, sort_keys=True)}".encode()
    token = hmac.new(key or session_key, message, hashlib.sha256).hexdigest()
    return {"session": session, "counter": counter, "body": body, "token": token}


try:
    step("1. Establish the per-session key (ECDH between a sandbox key pair and an ephemeral orchestrator key)")
    sandbox.write_file("/tmp/handler.py", HANDLER)
    sandbox_public = X25519PublicKey.from_public_bytes(bytes.fromhex(sandbox.exec("python /tmp/handler.py keygen").stdout.strip()))
    ephemeral = X25519PrivateKey.generate()
    sandbox.write_file("/tmp/peer_public.bin", ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    print(sandbox.exec(f"python /tmp/handler.py install_key {session_id}").stdout.strip())
    session_key = HKDF(hashes.SHA256(), 32, None, b"contoso-session|" + session_id.encode()).derive(ephemeral.exchange(sandbox_public))

    step("2. Authenticated operations")
    good = signed([1, 2, 3])
    print("valid request          ->", send(good))
    print("replay of that request ->", send(good))

    step("3. Operations that must be rejected")
    tampered = signed([1, 2, 3])
    tampered["body"]["numbers"] = [1000]
    print("tampered body          ->", send(tampered))
    print("no token               ->", send({"session": session_id, "counter": 99, "body": {"numbers": [1]}}))
    print("wrong session id       ->", send(signed([1], session="someone-else")))
    print("wrong key              ->", send(signed([1], key=os.urandom(32))))

    step("4. Limit: a Data Owner holder can skip the handler entirely with raw exec")
    print("raw exec reads the key ->", sandbox.exec("wc -c < /tmp/session_key.bin").stdout.strip(), "bytes available to any Data Owner caller")
finally:
    sandbox.delete()
    print("\nsandbox deleted")
