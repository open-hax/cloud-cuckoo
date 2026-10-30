"""Relying-party boundaries. Fixtures do not prove a deployed Axxium login."""
import base64
import hashlib
import json
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.server.auth.oauth_proxy import ClientCode
import httpx
import pytest

import knoxx_colab_mcp.oauth as oauth
from knoxx_colab_mcp.oauth import (
    AXXIUM_ISSUER, PUBLIC_BASE, CHATGPT_REDIRECT, SCOPES,
    AxxiumClient, AxxiumOAuthProxy, AxxiumTokenVerifier, IdentityUnavailable,
    make_gateway_auth, validate_discovery,
)
from knoxx_colab_mcp.server import make_server
from test_transport import serve, GATEWAY_TOKEN

ACTOR = "actor_00000000-0000-4000-8000-000000000001"
SECRET = "fixture-client-secret-" + "a" * 48
CONFIG = AxxiumClient("knoxx-colab", SECRET, frozenset([ACTOR]))
DISCOVERY = {"issuer": AXXIUM_ISSUER, "code_challenge_methods_supported": ["S256"],
             "token_endpoint_auth_methods_supported": ["client_secret_post"],
             **{key: AXXIUM_ISSUER + value for key, value in {
                 "authorization_endpoint": "/auth", "token_endpoint": "/token",
                 "introspection_endpoint": "/token/introspection",
                 "revocation_endpoint": "/token/revocation", "jwks_uri": "/jwks"}.items()}}


class StatusBackend:
    def status(self):
        return {"mode": "fixture", "browser_connected": False}


async def test_pending_identity_never_accepts_operator_key(tmp_path):
    auth = make_gateway_auth(PUBLIC_BASE, tmp_path / "state")
    assert isinstance(auth, IdentityUnavailable)
    async with serve(make_server(StatusBackend(), GATEWAY_TOKEN, auth)) as base:
        async with httpx.AsyncClient() as http:
            for bearer in [None, "wrong", GATEWAY_TOKEN, "previous-oauth-token"]:
                headers = {"Authorization": "Bearer " + bearer} if bearer else {}
                assert (await http.post(base + "/mcp", headers=headers, json={})).status_code == 401
            for path in ["/authorize", "/consent"]:
                page = await http.get(base + path)
                assert page.status_code == 503
                assert "Axxium sign-in pending" in page.text
                assert "<input" not in page.text and "<form" not in page.text
                assert "operator_key" not in page.text and GATEWAY_TOKEN not in page.text
                assert page.headers["cache-control"] == "no-store"
            for path in ["/authorize", "/consent", "/register", "/token", "/revoke", "/auth/callback"]:
                assert (await http.post(base + path, data={"operator_key": GATEWAY_TOKEN})).status_code == 503
            discovered = []
            for path in ["/.well-known/oauth-authorization-server", "/.well-known/oauth-authorization-server/colab"]:
                response = await http.get(base + path, headers={"Origin": "https://chatgpt.com"})
                assert response.status_code == 200
                assert response.headers["cache-control"] == "no-store"
                assert response.headers["access-control-allow-origin"] == "*"
                discovered.append(response.json())
                preflight = await http.options(base + path, headers={
                    "Origin": "https://chatgpt.com", "Access-Control-Request-Method": "GET"})
                assert preflight.status_code == 200
                assert (await http.post(base + path)).status_code == 405
            assert discovered[0] == discovered[1]
            metadata = discovered[0]
            assert metadata["issuer"] == PUBLIC_BASE
            assert metadata["scopes_supported"] == SCOPES
            assert metadata["code_challenge_methods_supported"] == ["S256"]
            for key, path in {"authorization_endpoint": "/authorize", "token_endpoint": "/token",
                              "registration_endpoint": "/register", "revocation_endpoint": "/revoke"}.items():
                assert metadata[key] == PUBLIC_BASE + path
            resource = (await http.get(base + "/.well-known/oauth-protected-resource/colab/mcp")).json()
            assert resource["resource"] == PUBLIC_BASE + "/mcp"
            assert resource["authorization_servers"] == [PUBLIC_BASE]
            assert resource["scopes_supported"] == metadata["scopes_supported"]
            assert (await http.get(base + "/health")).json()["identity_available"] is False
    assert not (tmp_path / "state").exists()


async def test_pending_discovery_matches_the_active_proxy_contract():
    active = AxxiumOAuthProxy(
        upstream_authorization_endpoint=DISCOVERY["authorization_endpoint"],
        upstream_token_endpoint=DISCOVERY["token_endpoint"],
        upstream_revocation_endpoint=DISCOVERY["revocation_endpoint"],
        upstream_client_id=CONFIG.client_id, upstream_client_secret=SECRET,
        token_verifier=AxxiumTokenVerifier(CONFIG, DISCOVERY["introspection_endpoint"]),
        base_url=PUBLIC_BASE, issuer_url=PUBLIC_BASE, valid_scopes=SCOPES,
        allowed_client_redirect_uris=[CHATGPT_REDIRECT])
    active.colab_profile = oauth.PRODUCTION
    pending = IdentityUnavailable()
    async with serve(make_server(StatusBackend(), GATEWAY_TOKEN, pending)) as pending_base:
        async with serve(make_server(StatusBackend(), GATEWAY_TOKEN, active)) as active_base:
            async with httpx.AsyncClient() as http:
                path = "/.well-known/oauth-authorization-server/colab"
                assert (await http.get(pending_base + path)).json() == (await http.get(active_base + path)).json()


def test_configuration_requires_private_file_and_explicit_actor_identity(tmp_path):
    path = tmp_path / "client.json"
    data = {"issuer": AXXIUM_ISSUER, "client_id": CONFIG.client_id,
            "client_secret": SECRET, "allowed_subjects": [ACTOR]}
    path.write_text(json.dumps(data))
    path.chmod(0o644)
    with pytest.raises(ValueError, match="0600"):
        AxxiumClient.read(path)
    path.chmod(0o600)
    assert AxxiumClient.read(path) == CONFIG
    path.write_text(json.dumps({**data, "allowed_client_redirect_uris": ["http://127.0.0.1:9876/callback"]}))
    assert AxxiumClient.read(path).allowed_client_redirect_uris == (CHATGPT_REDIRECT, "http://127.0.0.1:9876/callback")
    for callback in ["http://localhost:1/callback", "http://127.0.0.1:65535/callback"]:
        path.write_text(json.dumps({**data, "allowed_client_redirect_uris": [callback]}))
        assert AxxiumClient.read(path).allowed_client_redirect_uris == (CHATGPT_REDIRECT, callback)
    for callback in ["http://evil.invalid/callback", "http://localhost:*/callback",
                     "http://localhost/callback", "http://localhost:/callback", "http://127.0.0.1/callback",
                     "http://localhost:0/callback", "http://127.0.0.1:65536/callback",
                     "https://user@example.com/cb",
                     "https://example.com/cb?next=x", "https://example.com/cb#fragment", CHATGPT_REDIRECT]:
        path.write_text(json.dumps({**data, "allowed_client_redirect_uris": [callback]}))
        with pytest.raises(ValueError):
            AxxiumClient.read(path)
    assert SECRET not in repr(CONFIG)
    for bad in [{"issuer": "https://other.invalid/oidc"}, {"client_id": "knoxx"},
                {"client_secret": "short"}, {"allowed_subjects": []},
                {"allowed_subjects": ["system_admin"]}, {"allowed_subjects": ["human@example.com"]}]:
        path.write_text(json.dumps({**data, **bad}))
        with pytest.raises(ValueError):
            AxxiumClient.read(path)
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(ValueError, match="regular"):
        AxxiumClient.read(link)
    with pytest.raises(ValueError, match="Public Colab"):
        make_gateway_auth("https://other.invalid/colab", tmp_path / "state")


def test_discovery_confines_secrets_to_axxium():
    assert validate_discovery(DISCOVERY) == DISCOVERY
    for bad in ["http://axxium.promethean.rest/oidc/token", "https://evil.invalid/oidc/token",
                "https://axxium.promethean.rest/token", "https://axxium.promethean.rest/oidc/../token",
                "https://axxium.promethean.rest/oidc/%2e%2e/token", "https://axxium.promethean.rest/oidc/token?x=1",
                "https://user@axxium.promethean.rest/oidc/token"]:
        with pytest.raises(ValueError, match="escaped"):
            validate_discovery({**DISCOVERY, "token_endpoint": bad})
    for bad in [{"issuer": "https://other.invalid"}, {"jwks_uri": None},
                {"code_challenge_methods_supported": ["plain"]}, {"token_endpoint_auth_methods_supported": ["none"]}]:
        with pytest.raises(ValueError):
            validate_discovery({**DISCOVERY, **bad})


async def test_introspection_requires_current_grant_client_actor_scope_expiry():
    data = {"active": True, "sub": ACTOR, "client_id": CONFIG.client_id,
            "exp": time.time() + 300, "scope": "openid profile"}
    calls = []
    async def introspect(request):
        calls.append(request)
        form = parse_qs(request.content.decode())
        assert str(request.url) == DISCOVERY["introspection_endpoint"]
        assert form == {"client_id": [CONFIG.client_id], "client_secret": [SECRET], "token": ["fixture-axxium-access-7bdac9"]}
        return httpx.Response(200, json=data)
    verifier = AxxiumTokenVerifier(CONFIG, DISCOVERY["introspection_endpoint"], httpx.MockTransport(introspect))
    assert (await verifier.verify_token("fixture-axxium-access-7bdac9")).claims["sub"] == ACTOR
    good = data.copy()
    for bad in [{"active": False}, {"active": "true"}, {"client_id": "other"}, {"sub": "system_admin"},
                {"sub": None}, {"exp": 0}, {"exp": True}, {"exp": "tomorrow"}, {"exp": None},
                {"scope": "openid"}, {"scope": None}, {"aud": "other"}, {"iss": "https://other.invalid"}]:
        data.clear()
        data.update({**good, **bad})
        assert await verifier.verify_token("fixture-axxium-access-7bdac9") is None
    data.clear()
    data.update(good)
    assert await verifier.verify_token("fixture-axxium-access-7bdac9")
    data["active"] = False  # Central logout/disable is checked again, without a cache.
    assert await verifier.verify_token("fixture-axxium-access-7bdac9") is None
    assert len(calls) == 16
    async def down(request):
        raise httpx.ConnectError("fixture unavailable", request=request)
    verifier.transport = httpx.MockTransport(down)
    assert await verifier.verify_token("fixture-axxium-access-7bdac9") is None


@pytest.mark.parametrize("downstream", [CHATGPT_REDIRECT, "http://127.0.0.1:9876/callback"])
async def test_proxy_http_mcp_identity_revocation_and_client_boundaries(tmp_path, monkeypatch, downstream):
    # Use the production factory, encrypted storage and HTTP surface. Only
    # discovery/introspection are fixture responses; no human login is implied.
    path = tmp_path / "client.json"
    local_redirect = "http://127.0.0.1:9876/callback"
    path.write_text(json.dumps({"issuer": AXXIUM_ISSUER, "client_id": CONFIG.client_id,
                               "client_secret": SECRET, "allowed_subjects": [ACTOR],
                               "allowed_client_redirect_uris": [local_redirect]}))
    path.chmod(0o600)
    class DiscoveryHTTP:
        def __init__(self, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def get(self, url):
            return httpx.Response(200, json=DISCOVERY, request=httpx.Request("GET", url))
    with monkeypatch.context() as m:
        m.setattr(oauth, "httpx", SimpleNamespace(Client=DiscoveryHTTP))
        auth = make_gateway_auth(PUBLIC_BASE, tmp_path / "state", path)
    assert isinstance(auth, AxxiumOAuthProxy)
    upstream = auth._build_upstream_authorize_url("fixture-state", {
        "resource": PUBLIC_BASE + "/mcp", "scopes": SCOPES, "proxy_code_verifier": "verifier"})
    assert "resource" not in parse_qs(urlsplit(upstream).query)
    assert parse_qs(urlsplit(upstream).query)["client_id"] == [CONFIG.client_id]
    active = True
    async def introspect(request):
        return httpx.Response(200, json={"active": active, "sub": ACTOR, "client_id": CONFIG.client_id,
                                       "exp": time.time() + 300, "scope": "openid profile"})
    auth._token_validator.transport = httpx.MockTransport(introspect)
    async with serve(make_server(StatusBackend(), GATEWAY_TOKEN, auth)) as base:
        async with httpx.AsyncClient() as http:
            metadata = (await http.get(base + "/.well-known/oauth-authorization-server/colab")).json()
            assert metadata["issuer"] == PUBLIC_BASE
            assert metadata["authorization_endpoint"] == PUBLIC_BASE + "/authorize"
            async def register(redirect=CHATGPT_REDIRECT):
                return await http.post(base + "/register", json={"client_name": "ChatGPT fixture",
                    "redirect_uris": [redirect], "token_endpoint_auth_method": "none",
                    "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"], "scope": "openid profile"})
            assert (await register("https://evil.invalid/callback")).status_code == 400
            one = (await register(downstream)).json()
            two = (await register()).json()
            local = (await register(local_redirect)).json()
            assert "client_id" in local
            client = await auth.get_client(one["client_id"])
            verifier = "fixture-verifier-" + "x" * 48
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
            crossed = await http.get(base + "/authorize", params={"client_id": local["client_id"],
                "redirect_uri": CHATGPT_REDIRECT, "response_type": "code", "scope": "openid profile",
                "code_challenge": challenge, "code_challenge_method": "S256", "state": "fixture"})
            assert crossed.status_code == 400
            removed = auth._allowed_client_redirect_uris
            auth._allowed_client_redirect_uris = [CHATGPT_REDIRECT]
            assert await auth.get_client(local["client_id"]) is None
            auth._allowed_client_redirect_uris = removed
            start = await http.get(base + "/authorize", params={"client_id": one["client_id"],
                "redirect_uri": downstream, "response_type": "code", "scope": "openid profile",
                "code_challenge": challenge, "code_challenge_method": "S256", "state": "fixture",
                "resource": PUBLIC_BASE + "/mcp"})
            assert start.status_code in {302, 303}
            consent = await http.get(base + "/consent", params=urlsplit(start.headers["location"]).query)
            assert consent.status_code == 200
            assert "operator_key" not in consent.text and SECRET not in consent.text
            # Seed the post-Axxium callback record, then exercise real SDK PKCE,
            # exchange, encrypted persistence, MCP auth and revocation over HTTP.
            code = ClientCode(code="fixture-code", client_id=one["client_id"], redirect_uri=downstream,
                code_challenge=challenge, code_challenge_method="S256", scopes=SCOPES,
                idp_tokens={"access_token": "fixture-axxium-access-7bdac9", "refresh_token": "fixture-axxium-refresh-083aa1",
                            "expires_in": 300, "refresh_expires_in": 600, "token_type": "Bearer"},
                expires_at=time.time() + 60, created_at=time.time())
            await auth._code_store.put(key=code.code, value=code, ttl=60)
            fields = {"grant_type": "authorization_code", "client_id": one["client_id"], "code": code.code,
                      "redirect_uri": downstream, "code_verifier": verifier, "resource": PUBLIC_BASE + "/mcp"}
            assert (await http.post(base + "/token", data={**fields, "resource": "https://other.invalid/mcp"})).status_code == 400
            assert (await http.post(base + "/token", data={**fields, "code_verifier": "wrong"})).status_code == 400
            result = await http.post(base + "/token", data=fields)
            assert result.status_code == 200, result.text
            tokens = result.json()
            assert tokens["access_token"] != "fixture-axxium-access-7bdac9"
            assert tokens["refresh_token"] != "fixture-axxium-refresh-083aa1"
            assert (await http.post(base + "/token", data=fields)).status_code == 400
            assert await auth.load_access_token(tokens["refresh_token"]) is None
            assert await auth.load_refresh_token(client, tokens["refresh_token"])
            async with Client(StreamableHttpTransport(base + "/mcp", auth=tokens["access_token"])) as mcp:
                assert (await mcp.call_tool("colab_status", {})).data["mode"] == "fixture"
            active = False
            assert await auth.load_access_token(tokens["access_token"]) is None
            active = True
            assert await auth.load_access_token(tokens["access_token"])
            for key in [GATEWAY_TOKEN, "fixture-axxium-access-7bdac9", "wrong"]:
                assert (await http.post(base + "/mcp", headers={"Authorization": "Bearer " + key}, json={})).status_code == 401
            assert (await http.post(base + "/revoke", data={"client_id": two["client_id"], "token": tokens["access_token"]})).status_code == 200
            assert await auth.load_access_token(tokens["access_token"])
            revoked = []
            async def revoke(request):
                data = parse_qs(request.content.decode())
                assert data["client_id"] == [CONFIG.client_id] and data["client_secret"] == [SECRET]
                assert "authorization" not in request.headers
                revoked.append(data["token"][0])
                return httpx.Response(200)
            factory = httpx.AsyncClient
            with monkeypatch.context() as m:
                m.setattr(oauth, "httpx", SimpleNamespace(AsyncClient=lambda **kw: factory(**kw, transport=httpx.MockTransport(revoke)), HTTPError=httpx.HTTPError))
                assert (await http.post(base + "/revoke", data={"client_id": one["client_id"], "token": tokens["access_token"]})).status_code == 200
            assert revoked == ["fixture-axxium-refresh-083aa1", "fixture-axxium-access-7bdac9"]
            assert await auth.load_access_token(tokens["access_token"]) is None
            assert await auth.load_refresh_token(client, tokens["refresh_token"]) is None
    for file in (tmp_path / "state").rglob("*"):
        if file.is_file():
            assert b"fixture-axxium-access-7bdac9" not in file.read_bytes()
            assert b"fixture-axxium-refresh-083aa1" not in file.read_bytes()


def test_closed_staging_profile_rejects_production_confusion(tmp_path):
    from knoxx_colab_mcp.oauth import STAGING, PRODUCTION, auth_profile
    from knoxx_colab_mcp.server import gateway_backend, validate_gateway_binding
    path = tmp_path / "stage-client.json"
    config = {"issuer": STAGING.issuer, "client_id": STAGING.client_id, "client_secret": SECRET,
              "allowed_subjects": [ACTOR], "allowed_client_redirect_uris": ["http://127.0.0.1:18762/callback"]}
    path.write_text(json.dumps(config))
    path.chmod(0o600)
    assert AxxiumClient.read(path, STAGING).client_id == STAGING.client_id
    with pytest.raises(ValueError):
        AxxiumClient.read(path, PRODUCTION)
    for wrong in [{"issuer": PRODUCTION.issuer}, {"client_id": PRODUCTION.client_id},
                  {"allowed_client_redirect_uris": []}]:
        path.write_text(json.dumps({**config, **wrong}))
        with pytest.raises(ValueError):
            AxxiumClient.read(path, STAGING)
    assert auth_profile("staging") == STAGING and auth_profile("production") == PRODUCTION
    with pytest.raises(ValueError):
        auth_profile("https://evil.invalid")
    with pytest.raises(ValueError):
        make_gateway_auth(PRODUCTION.base_url, tmp_path / "state", path, STAGING)
    validate_gateway_binding("staging", "127.0.0.1", 18761)
    for host, port in [("0.0.0.0", 18761), ("127.0.0.1", 18762), ("localhost", 18761)]:
        with pytest.raises(ValueError):
            validate_gateway_binding("staging", host, port)
    class DenyEnv(dict):
        def __getitem__(self, key):
            raise AssertionError("Staging accessed a production bridge setting")
        def get(self, key, default=None):
            raise AssertionError("Staging accessed a production bridge setting")
    backend = gateway_backend("staging", DenyEnv())
    assert backend.status()["execution_verified"] is False


async def test_staging_oauth_mcp_and_environment_boundaries(tmp_path, monkeypatch, diagnostics):
    from knoxx_colab_mcp.oauth import STAGING, PRODUCTION
    from knoxx_colab_mcp.server import gateway_backend
    path = tmp_path / "client.json"
    callback = "http://127.0.0.1:18762/callback"
    path.write_text(json.dumps({"issuer": STAGING.issuer, "client_id": STAGING.client_id,
                               "client_secret": SECRET, "allowed_subjects": [ACTOR],
                               "allowed_client_redirect_uris": [callback]}))
    path.chmod(0o600)
    discovery = {**DISCOVERY, "issuer": STAGING.issuer,
                 **{key: value.replace(AXXIUM_ISSUER, STAGING.issuer)
                    for key, value in DISCOVERY.items() if key.endswith("_endpoint") or key == "jwks_uri"}}
    assert validate_discovery(discovery, STAGING) == discovery
    with pytest.raises(ValueError):
        validate_discovery(discovery, PRODUCTION)
    with pytest.raises(ValueError):
        validate_discovery({**discovery, "token_endpoint": DISCOVERY["token_endpoint"]}, STAGING)
    class DiscoveryHTTP:
        def __init__(self, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def get(self, url):
            assert url == STAGING.issuer + "/.well-known/openid-configuration"
            return httpx.Response(200, json=discovery, request=httpx.Request("GET", url))
    with monkeypatch.context() as m:
        m.setattr(oauth, "httpx", SimpleNamespace(Client=DiscoveryHTTP))
        auth = make_gateway_auth(STAGING.base_url, tmp_path / "state", path, STAGING)
    diagnostics.expect(logger='fastmcp.server.auth.oauth_proxy', level=30,
        message='Using non-secure cookies for development; deploy with HTTPS for production.')
    transaction = {"resource": STAGING.base_url + "/mcp", "scopes": SCOPES,
                   "proxy_code_verifier": "verifier"}
    upstream = auth._build_upstream_authorize_url("fixture-state", transaction)
    assert "resource" not in parse_qs(urlsplit(upstream).query)
    assert transaction["resource"] == STAGING.base_url + "/mcp"
    assert parse_qs(urlsplit(upstream).query)["client_id"] == [STAGING.client_id]
    current_issuer = STAGING.issuer
    async def introspect(request):
        return httpx.Response(200, json={"active": True, "sub": ACTOR, "client_id": STAGING.client_id,
            "exp": time.time() + 300, "scope": "openid profile", "iss": current_issuer})
    auth._token_validator.transport = httpx.MockTransport(introspect)
    assert await auth._token_validator.verify_token("stage-token")
    current_issuer = PRODUCTION.issuer
    assert await auth._token_validator.verify_token("stage-token") is None
    current_issuer = STAGING.issuer
    async with serve(make_server(gateway_backend("staging", {}), "", auth)) as base:
        async with httpx.AsyncClient() as http:
            metadata = (await http.get(base + "/.well-known/oauth-authorization-server")).json()
            assert metadata["issuer"].rstrip("/") == STAGING.base_url
            async def register(redirect):
                return await http.post(base + "/register", json={"client_name": "staging fixture",
                    "redirect_uris": [redirect], "token_endpoint_auth_method": "none",
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"], "scope": "openid profile"})
            assert (await register(CHATGPT_REDIRECT)).status_code == 400
            registration = (await register(callback)).json()
            verifier = "stage-fixture-verifier-" + "x" * 48
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
            auth_params = {"client_id": registration["client_id"], "redirect_uri": callback,
                           "response_type": "code", "scope": "openid profile", "state": "fixture",
                           "code_challenge": challenge, "code_challenge_method": "S256"}
            wrong = await http.get(base + "/authorize", params={**auth_params,
                "resource": PRODUCTION.base_url + "/mcp"})
            assert wrong.status_code == 302
            wrong_query = parse_qs(urlsplit(wrong.headers["location"]).query)
            assert wrong_query["error"] == ["invalid_request"] and "code" not in wrong_query
            assert (await http.get(base + "/authorize", params={**auth_params,
                "resource": STAGING.base_url + "/mcp"})).status_code in {302, 303}
            code = ClientCode(code="stage-fixture-code", client_id=registration["client_id"], redirect_uri=callback,
                code_challenge=challenge, code_challenge_method="S256", scopes=SCOPES,
                idp_tokens={"access_token": "stage-access", "refresh_token": "stage-refresh", "expires_in": 300,
                            "refresh_expires_in": 600, "token_type": "Bearer"},
                expires_at=time.time() + 60, created_at=time.time())
            await auth._code_store.put(key=code.code, value=code, ttl=60)
            fields = {"grant_type": "authorization_code", "client_id": registration["client_id"], "code": code.code,
                      "redirect_uri": callback, "code_verifier": verifier, "resource": STAGING.base_url + "/mcp"}
            assert (await http.post(base + "/token", data={**fields, "resource": PRODUCTION.base_url + "/mcp"})).status_code == 400
            response = await http.post(base + "/token", data=fields)
            assert response.status_code == 200, response.text
            async with Client(StreamableHttpTransport(base + "/mcp", auth=response.json()["access_token"])) as mcp:
                status = (await mcp.call_tool("colab_status", {})).data
                assert status["mode"] == "staging-fixture" and status["execution_verified"] is False
                connection = (await mcp.call_tool("colab_connect", {})).data
                assert "cannot connect" in connection["instructions"] and "command" not in connection
                assert (await mcp.call_tool("colab_call", {"name": "x", "arguments": {}}, raise_on_error=False)).is_error
                diagnostics.expect(logger='fastmcp.tools.tool_manager', level=40,
                    message="Error calling tool 'colab_call'",
                    exception=ValueError('Staging identity probe cannot execute Colab operations'))
    assert (tmp_path / "state" / "staging" / "axxium-proxy").is_dir()
