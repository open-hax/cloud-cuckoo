"""Read-only identity preflight. Never supplies a key or completes human consent."""
import asyncio
import httpx
from knoxx_colab_mcp.oauth import AXXIUM_ISSUER, PUBLIC_BASE, validate_discovery


async def verify():
    async with httpx.AsyncClient(timeout=15, follow_redirects=False) as http:
        identity = await http.get(AXXIUM_ISSUER + "/.well-known/openid-configuration")
        print("Axxium shared issuer discovery HTTP", identity.status_code)
        pending = identity.status_code != 200
        if not pending:
            validate_discovery(identity.json())
        for path in ("/authorize", "/consent"):
            response = await http.get(PUBLIC_BASE + path)
            assert '<input' not in response.text and 'name="operator_key"' not in response.text
            if pending:
                assert response.status_code == 503 and "Axxium sign-in pending" in response.text
            print("Public", path, "HTTP", response.status_code, "— no key-entry form")
        denied = await http.post(PUBLIC_BASE + "/mcp", json={})
        assert denied.status_code == 401
        print("Anonymous MCP access denied")
        if pending:
            print("PENDING: activate and qualify Axxium shared login, then register this relying party.")
            return 2
        print("Discovery alone is not proof of a real account connection or revocation.")
        return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(verify()))
