"""Read-only authenticated MCP verification with explicit browser/compute limits."""
import argparse
import asyncio
import json
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
import httpx
from knoxx_colab_mcp.server import TOOL_NAMES, read_secret
from knoxx_colab_mcp.compute import COMPUTE_TOOLS


async def verify(args):
    token = read_secret(args.token_file)
    async with httpx.AsyncClient(timeout=20) as http:
        for name, headers in [("anonymous", {}), ("incorrect credential", {"Authorization": "Bearer invalid-fixture"})]:
            response = await http.post(args.url, headers=headers, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            assert response.status_code == 401, f"{name}: expected 401, got {response.status_code}"
            print(f"PASS  {name} request rejected with HTTP 401")
    async with Client(StreamableHttpTransport(args.url, auth=token), timeout=30) as client:
        info = await client.initialize()
        assert info.serverInfo.name == "Knoxx Colab", "The running upstream is not Knoxx Colab"
        tools = await client.list_tools()
        expected = TOOL_NAMES + (COMPUTE_TOOLS if args.compute else [])
        assert {t.name for t in tools} == set(expected), "Unexpected server tool surface"
        print(f"PASS  authenticated MCP initialization and exact {len(expected)}-tool catalog")
        status = (await client.call_tool("colab_status", {})).structured_content
        bridge = status.get("bridge", status)
        assert bridge["upstream_revision"] == "b9ab3899e0f1fa493390b1fd6d54aa2e464ecdf1"
        print("PASS  running bridge reports the pinned official Google implementation")
        print("STATUS " + json.dumps(status))
        if bridge["browser_connected"]:
            catalog = (await client.call_tool("colab_tools", {})).structured_content
            print("PASS  actual browser notebook tool discovery")
            print("NOTEBOOK_TOOLS " + json.dumps(catalog))
        else:
            result = await client.call_tool("colab_tools", {}, raise_on_error=False)
            assert result.is_error, "Disconnected browser must not return a successful notebook catalog"
            print("PASS  disconnected browser refuses notebook operations")
            if args.require_browser:
                raise SystemExit("FAIL  actual Colab browser connection required")
            print("WARN  Google browser consent and notebook connectivity are pending")
        if args.compute:
            print("COMPUTE_STATUS " + json.dumps((await client.call_tool("colab_compute_status", {})).structured_content))
            print("COMPUTE_USAGE " + json.dumps((await client.call_tool("colab_compute_usage", {})).structured_content))
            print("COMPUTE_SESSIONS " + json.dumps((await client.call_tool("colab_compute_sessions", {})).structured_content))
        if args.notebook_probe:
            assert bridge["browser_connected"], "Notebook probe requires the connected browser"
            async def notebook(name, arguments):
                result = await client.call_tool("colab_call", {"name": name, "arguments": arguments})
                return result.structured_content
            original = await notebook("get_cells", {"includeOutputs": False})
            created = await notebook("add_code_cell", {"cellIndex": len(original["cells"]), "language": "python", "code": "print('knoxx-colab-ok')"})
            cell_id = created["newCellId"]
            try:
                result = await notebook("run_code_cell", {"cellId": cell_id})
                assert any("knoxx-colab-ok\n" in item.get("text", []) for item in result.get("outputs", [])), "Missing actual notebook stdout"
                print("PASS  actual Google notebook execution returned knoxx-colab-ok")
            finally:
                await notebook("delete_cell", {"cellId": cell_id})
                print("PASS  own notebook probe cell removed")
        else:
            print("WARN  this read-only probe does not prove a cell ran, a GPU exists, or artifacts were saved")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--require-browser", action="store_true")
    parser.add_argument("--compute", action="store_true", help="Verify the combined ten-tool public gateway and read real account usage")
    parser.add_argument("--notebook-probe", action="store_true", help="Add, execute and remove a probe cell in the connected notebook")
    asyncio.run(verify(parser.parse_args()))
