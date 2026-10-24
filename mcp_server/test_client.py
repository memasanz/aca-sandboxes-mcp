"""Calls the MCP server like the agent would, with a real Entra token.

Needs in .env: MCP_AUDIENCE, AGENT_CLIENT_ID, AGENT_CLIENT_SECRET (and the admin SP for the negative test).
Start the server first:  uvicorn server:app --port 8090
"""
import asyncio
import json
import os
from pathlib import Path

import httpx
from azure.identity import ClientSecretCredential
from dotenv import load_dotenv
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

URL = "http://127.0.0.1:8090/mcp"
TENANT = os.environ["AZURE_TENANT_ID"]
SCOPE = os.environ["MCP_AUDIENCE"] + "/.default"


def token_for(client_id: str, client_secret: str) -> str:
    return ClientSecretCredential(TENANT, client_id, client_secret).get_token(SCOPE).token


async def main() -> None:
    print("-- Negative: no token")
    print("status:", httpx.post(URL).status_code)

    print("-- Negative: valid Entra token from an app that is not allowed (sp-contoso-admin)")
    admin = token_for(os.environ["ADMIN_CLIENT_ID"], os.environ["ADMIN_CLIENT_SECRET"])
    response = httpx.post(URL, headers={"Authorization": f"Bearer {admin}"})
    print("status:", response.status_code, response.text)

    print("-- Positive: token from contoso-agent-client")
    agent = token_for(os.environ["AGENT_CLIENT_ID"], os.environ["AGENT_CLIENT_SECRET"])
    async with streamablehttp_client(URL, headers={"Authorization": f"Bearer {agent}"}) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            print("tools:", [t.name for t in (await session.list_tools()).tools])
            code = "result = {'rows': len(data), 'total': sum(r['amount'] for r in data)}\nprint('done')"
            data = json.dumps([{"matter": "A", "amount": 1200}, {"matter": "B", "amount": 800}])
            reply = await session.call_tool("run_python", {"code": code, "data": data})
            print("result:", reply.content[0].text)


asyncio.run(main())
