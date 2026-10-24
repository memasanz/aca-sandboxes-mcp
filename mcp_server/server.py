"""MCP server (the orchestrator) that exposes one tool, run_python, backed by an ACA Sandbox.

Host this on premises, next to the agent. It is the only identity with the
"Container Apps SandboxGroup Data Owner" role. The agent calls the tool with an Entra token
and never sees the sandbox, the session key, or the orchestrator credential.

Run:  uvicorn server:app --host 0.0.0.0 --port 8080
"""
import asyncio
import contextlib
import json
import logging
import os
import uuid
from pathlib import Path

import jwt
from azure.containerapps.sandbox import SandboxGroupClient, endpoint_for_region
from azure.identity import CertificateCredential, ClientSecretCredential
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from mcp.server.fastmcp import FastMCP

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

TENANT_ID = os.environ["AZURE_TENANT_ID"]
SUBSCRIPTION = os.environ["AZURE_SUBSCRIPTION_ID"]
RESOURCE_GROUP = os.environ["AZURE_RESOURCE_GROUP"]
SANDBOX_GROUP = os.environ["SANDBOX_GROUP"]
REGION = os.environ["SANDBOX_REGION"]

# Who may call the MCP tool: tokens for this audience, issued to these client app ids.
MCP_AUDIENCE = os.environ.get("MCP_AUDIENCE", "")
MCP_ALLOWED_APP_IDS = [a for a in os.environ.get("MCP_ALLOWED_APP_IDS", "").split(",") if a]
REQUIRE_AUTH = os.environ.get("REQUIRE_AUTH", "true").lower() != "false"  # false for local testing only

DISK = "python-3.12-code-interpreter"  # pinned approved image
TIMEOUT_SECONDS = 30

# Only metadata is logged. Code, data, and results are never logged.
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("orchestrator")

# Runs inside the sandbox. It derives the session key with ECDH, decrypts the request,
# runs the code, and returns an encrypted result.
RUNNER = '''
import json, sys, io, traceback, contextlib, os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

mode, session_id = sys.argv[1], sys.argv[2].encode()
if mode == "keygen":
    key = X25519PrivateKey.generate()
    open("/tmp/private.bin", "wb").write(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
    print(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex())
    sys.exit(0)

private = X25519PrivateKey.from_private_bytes(open("/tmp/private.bin", "rb").read())
peer = X25519PublicKey.from_public_bytes(open("/tmp/peer_public.bin", "rb").read())
aes = AESGCM(HKDF(hashes.SHA256(), 32, None, b"contoso-session|" + session_id).derive(private.exchange(peer)))

blob = open("/tmp/request.enc", "rb").read()
request = json.loads(aes.decrypt(blob[:12], blob[12:], session_id))

namespace = {"data": request.get("data"), "result": None}
stdout = io.StringIO()
error = None
try:
    with contextlib.redirect_stdout(stdout):
        exec(request["code"], namespace)
except Exception:
    error = traceback.format_exc()

reply = json.dumps({"result": namespace["result"], "stdout": stdout.getvalue(), "error": error}, default=str).encode()
nonce = os.urandom(12)
open("/tmp/response.enc", "wb").write(nonce + aes.encrypt(nonce, reply, session_id))
'''


def orchestrator_credential():
    """Certificate for production; client secret only as a local-development fallback."""
    client_id = os.environ["ORCHESTRATOR_CLIENT_ID"]
    cert_path = os.environ.get("ORCHESTRATOR_CERT_PATH")
    if cert_path:
        return CertificateCredential(TENANT_ID, client_id, certificate_path=cert_path)
    return ClientSecretCredential(TENANT_ID, client_id, os.environ["ORCHESTRATOR_CLIENT_SECRET"])


def run_in_sandbox(code: str, data: object) -> dict:
    """One session: create a sandbox, lock egress, exchange keys, run, return the result, delete."""
    session_id = uuid.uuid4().hex[:8]
    group = SandboxGroupClient(
        endpoint_for_region(REGION),
        orchestrator_credential(),
        subscription_id=SUBSCRIPTION,
        resource_group=RESOURCE_GROUP,
        sandbox_group=SANDBOX_GROUP,
    )
    sandbox = group.begin_create_sandbox(
        disk=DISK, labels={"session": session_id, "purpose": "mcp"}, auto_suspend_seconds=60
    ).result()
    log.info("session=%s sandbox created", session_id)
    try:
        # Fail closed: do not release data unless egress is deny-default.
        sandbox.set_egress_default("Deny")
        if "deny" not in str(sandbox.get_egress_policy()).lower():
            raise RuntimeError("egress is not deny-default; refusing to release data")

        # ECDH: the sandbox makes a key pair, the orchestrator makes an ephemeral one.
        sandbox.write_file("/tmp/runner.py", RUNNER)
        sandbox_public = X25519PublicKey.from_public_bytes(
            bytes.fromhex(sandbox.exec(f"python /tmp/runner.py keygen {session_id}").stdout.strip())
        )
        ephemeral = X25519PrivateKey.generate()
        sandbox.write_file("/tmp/peer_public.bin", ephemeral.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        aes = AESGCM(HKDF(hashes.SHA256(), 32, None, b"contoso-session|" + session_id.encode()).derive(
            ephemeral.exchange(sandbox_public)))

        # Only ciphertext is uploaded; the session id is bound in as associated data.
        request = json.dumps({"code": code, "data": data}).encode()
        nonce = os.urandom(12)
        sandbox.write_file("/tmp/request.enc", nonce + aes.encrypt(nonce, request, session_id.encode()))

        run = sandbox.exec(f"timeout {TIMEOUT_SECONDS} python /tmp/runner.py run {session_id}")
        if run.exit_code != 0:
            return {"error": f"execution failed or timed out (exit {run.exit_code})"}

        blob = sandbox.read_file("/tmp/response.enc")
        return json.loads(aes.decrypt(blob[:12], blob[12:], session_id.encode()))
    finally:
        sandbox.delete()
        log.info("session=%s sandbox deleted", session_id)


mcp = FastMCP("contoso-code-interpreter", stateless_http=True, json_response=True)


@mcp.tool()
async def run_python(code: str, data: str = "") -> str:
    """Run Python in a fresh, isolated, ephemeral sandbox and return the result.

    `data` is optional JSON text, available to the code as the variable `data`.
    Assign the final answer to the variable `result`. Anything printed is returned as stdout.
    The sandbox has no network access and is deleted when the call ends.
    """
    parsed = json.loads(data) if data else None
    outcome = await asyncio.to_thread(run_in_sandbox, code, parsed)
    return json.dumps(outcome, default=str)


jwks_client = jwt.PyJWKClient(f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys")


def validate_caller(token: str) -> str | None:
    """Return an error string if the token is not acceptable, otherwise None."""
    try:
        key = jwks_client.get_signing_key_from_jwt(token).key
        # v2 tokens carry the bare app id as audience; v1 tokens carry the api:// form.
        audiences = [MCP_AUDIENCE, MCP_AUDIENCE.removeprefix("api://")]
        claims = jwt.decode(token, key, algorithms=["RS256"], audience=audiences, options={"require": ["exp", "aud", "iss"]})
    except jwt.PyJWTError as e:
        return f"invalid token: {type(e).__name__}"
    if claims.get("tid") != TENANT_ID:
        return "wrong tenant"
    caller = claims.get("azp") or claims.get("appid")
    if caller not in MCP_ALLOWED_APP_IDS:
        return "caller app is not allowed"
    return None


@contextlib.asynccontextmanager
async def lifespan(_: FastAPI):
    async with mcp.session_manager.run():
        yield


app = FastAPI(title="Contoso code interpreter MCP", lifespan=lifespan)


@app.middleware("http")
async def require_entra_token(request: Request, call_next):
    if request.url.path.startswith("/mcp") and REQUIRE_AUTH:
        header = request.headers.get("authorization", "")
        if not header.lower().startswith("bearer "):
            return JSONResponse({"error": "missing bearer token"}, status_code=401)
        problem = validate_caller(header[7:])
        if problem:
            log.info("rejected caller: %s", problem)
            return JSONResponse({"error": problem}, status_code=401)
    return await call_next(request)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


app.mount("/", mcp.streamable_http_app())
