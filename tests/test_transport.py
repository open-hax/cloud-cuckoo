"""Exercise real HTTP auth, Google's WebSocket transport, and the droplet relay.

The notebook peer is a fixture, not evidence of a live Google runtime.
"""
import asyncio
from contextlib import asynccontextmanager
import json
import socket

from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
import httpx
import pytest
import uvicorn
import websockets
from websockets.exceptions import InvalidStatus

from knoxx_colab_mcp.server import BrowserBridge, Gateway, TOOL_NAMES, make_server, read_secret

TOKEN = "bridge-test-" + "a" * 40
GATEWAY_TOKEN = "gateway-test-" + "b" * 40


@asynccontextmanager
async def serve(server):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    app = server.http_app(stateless_http=True, json_response=True)
    # Retain standard pytest log capture rather than installing console
    # handlers over it. The original error threshold remains unchanged.
    runner = uvicorn.Server(uvicorn.Config(app, log_level="error", lifespan="on", log_config=None))
    task = asyncio.create_task(runner.serve(sockets=[sock]))
    try:
        for _ in range(200):
            if runner.started:
                break
            if task.done():
                await task
            await asyncio.sleep(.01)
        assert runner.started
        yield f"http://127.0.0.1:{port}"
    finally:
        runner.should_exit = True
        await asyncio.wait_for(task, 10)
        sock.close()


async def notebook_peer(ws):
    async for text in ws:
        request = json.loads(text)
        if "id" not in request:
            continue
        method = request["method"]
        result = {}
        if method == "initialize":
            result = {"protocolVersion": request["params"]["protocolVersion"],
                      "capabilities": {"tools": {}}, "serverInfo": {"name": "fixture-notebook", "version": "1"}}
        elif method == "tools/list":
            result = {"tools": [{"name": "fixture_echo", "description": "fixture only",
                                  "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}}]}
        elif method == "tools/call":
            text = request["params"]["arguments"].get("text", "")
            result = {"content": [{"type": "text", "text": text}], "isError": text == "failure"}
        await ws.send(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}))


async def test_real_http_and_official_browser_transport(tmp_path, diagnostics):
    bridge = BrowserBridge(tmp_path)
    async with serve(make_server(bridge, TOKEN)) as base:
        async with httpx.AsyncClient() as http:
            response = await http.post(base + "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            assert response.status_code == 401
            response = await http.post(base + "/mcp", headers={"Authorization": "Bearer wrong"}, json={})
            assert response.status_code == 401
        transport = StreamableHttpTransport(base + "/mcp", auth=TOKEN)
        async with Client(transport) as client:
            assert {t.name for t in await client.list_tools()} == set(TOOL_NAMES)
            status = (await client.call_tool("colab_status", {})).data
            assert status["browser_connected"] is False
            assert status["execution_verified"] is False
            assert "mcpProxyToken" not in json.dumps(status)
            result = await client.call_tool("colab_tools", {}, raise_on_error=False)
            assert result.is_error
            diagnostics.expect(logger='fastmcp.tools.tool_manager', level=40,
                message="Error calling tool 'colab_tools'",
                exception=ValueError('No Colab browser connected. Run the local open-browser command and accept the connection in Colab.'))
            connect = (await client.call_tool("colab_connect", {})).data
            assert "mcpProxyToken" not in json.dumps(connect)
        assert (tmp_path / "browser-url").stat().st_mode & 0o077 == 0
        ws_url = f"ws://127.0.0.1:{bridge.socket.port}/?access_token={bridge.socket.token}"
        with pytest.raises(InvalidStatus):
            async with websockets.connect(ws_url, origin="https://evil.invalid", subprotocols=["mcp"]):
                pass
        with pytest.raises(InvalidStatus):
            async with websockets.connect(f"ws://127.0.0.1:{bridge.socket.port}/", origin="https://colab.research.google.com", subprotocols=["mcp"]):
                pass
        async with websockets.connect(ws_url, origin="https://colab.research.google.com", subprotocols=["mcp"]) as ws:
            peer_task = asyncio.create_task(notebook_peer(ws))
            for _ in range(100):
                if bridge.proxy.is_connected():
                    break
                await asyncio.sleep(.01)
            assert bridge.proxy.is_connected()
            gateway = Gateway(base + "/mcp", TOKEN)
            async with serve(make_server(gateway, GATEWAY_TOKEN)) as gateway_base:
                async with Client(StreamableHttpTransport(gateway_base + "/mcp", auth=GATEWAY_TOKEN)) as client:
                    status = (await client.call_tool("colab_status", {})).data
                    assert status["bridge"]["browser_connected"] is True
                    discovered = (await client.call_tool("colab_tools", {})).structured_content["result"]
                    assert discovered[0]["name"] == "fixture_echo"
                    output = await client.call_tool("colab_call", {"name": "fixture_echo", "arguments": {"text": "relay verified"}})
                    assert output.content[0].text == "relay verified"
                    failure = await client.call_tool("colab_call", {"name": "fixture_echo", "arguments": {"text": "failure"}}, raise_on_error=False)
                    assert failure.is_error
                    diagnostics.expect(logger='fastmcp.tools.tool_manager', level=40,
                        message="Error calling tool 'colab_call'", exception=ValueError("Error calling tool 'colab_call': Colab notebook tool failed: failure"))
                    diagnostics.expect(logger='fastmcp.tools.tool_manager', level=40,
                        message="Error calling tool 'colab_call'", exception=ValueError('Colab notebook tool failed: failure'))
                    unknown = await client.call_tool("colab_call", {"name": "invented", "arguments": {}}, raise_on_error=False)
                    assert unknown.is_error
                    diagnostics.expect(logger='fastmcp.tools.tool_manager', level=40,
                        message="Error calling tool 'colab_call'", exception=ValueError("Error calling tool 'colab_call': Unknown notebook tool. Call colab_tools and use an exact discovered name."))
                    diagnostics.expect(logger='fastmcp.tools.tool_manager', level=40,
                        message="Error calling tool 'colab_call'", exception=ValueError('Unknown notebook tool. Call colab_tools and use an exact discovered name.'))
                    oversized = await client.call_tool("colab_call", {"name": "fixture_echo", "arguments": {"text": "x" * 262145}}, raise_on_error=False)
                    assert oversized.is_error
                    diagnostics.expect(logger='fastmcp.tools.tool_manager', level=40,
                        message="Error calling tool 'colab_call'", exception=ValueError('Arguments exceed 256 KiB; use a notebook-managed artifact instead'))
            await ws.close()
            await peer_task
        for _ in range(100):
            if not bridge.status()["browser_connected"]:
                break
            await asyncio.sleep(.01)
        assert not bridge.status()["browser_connected"]
        with pytest.raises(ValueError, match="disconnected"):
            await bridge.call("fixture_echo", {})
    assert not (tmp_path / "browser-url").exists()


def test_secret_files_fail_closed(tmp_path):
    path = tmp_path / "token"
    path.write_text(TOKEN)
    path.chmod(0o644)
    with pytest.raises(ValueError, match="0600"):
        read_secret(str(path))
    path.chmod(0o600)
    assert read_secret(str(path)) == TOKEN
