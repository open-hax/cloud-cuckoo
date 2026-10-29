"""Revocation failure must deny locally and remain retryable centrally."""
import base64
import asyncio
import hashlib
import json
import time
from types import SimpleNamespace
from urllib.parse import parse_qs

from fastmcp.server.auth.oauth_proxy import ClientCode
import httpx
import pytest
from mcp.server.auth.provider import TokenError

import knoxx_colab_mcp.oauth as oauth
from knoxx_colab_mcp.oauth import PUBLIC_BASE, CHATGPT_REDIRECT, SCOPES, make_gateway_auth
from knoxx_colab_mcp.server import make_server
from test_oauth import ACTOR, SECRET, DISCOVERY, CONFIG, StatusBackend
from test_transport import serve, GATEWAY_TOKEN


@pytest.mark.parametrize("failure_index", [0, 1, "crash", "before-marker"])
async def test_revocation_retry_survives_outage_and_restart(tmp_path, monkeypatch, failure_index):
    path = tmp_path / "client.json"
    path.write_text(json.dumps({"issuer": oauth.AXXIUM_ISSUER, "client_id": CONFIG.client_id,
                                "client_secret": SECRET, "allowed_subjects": [ACTOR]}))
    path.chmod(0o600)

    class DiscoveryHTTP:
        def __init__(self, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def get(self, url):
            return httpx.Response(200, json=DISCOVERY, request=httpx.Request("GET", url))

    def provider():
        with monkeypatch.context() as m:
            m.setattr(oauth, "httpx", SimpleNamespace(Client=DiscoveryHTTP))
            instance = make_gateway_auth(PUBLIC_BASE, tmp_path / "state", path)
        async def introspect(request):
            return httpx.Response(200, json={"active": True, "sub": ACTOR, "client_id": CONFIG.client_id,
                                           "exp": time.time() + 300, "scope": "openid profile"})
        instance._token_validator.transport = httpx.MockTransport(introspect)
        return instance

    async def make_family(http, base, auth, suffix):
        registration = await http.post(base + "/register", json={"client_name": "fixture " + suffix,
            "redirect_uris": [CHATGPT_REDIRECT], "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
            "scope": "openid profile"})
        client_id = registration.json()["client_id"]
        verifier = "fixture-verifier-" + suffix * 48
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        code = ClientCode(code="code-" + suffix, client_id=client_id, redirect_uri=CHATGPT_REDIRECT,
            code_challenge=challenge, code_challenge_method="S256", scopes=SCOPES,
            idp_tokens={"access_token": "upstream-access-" + suffix, "refresh_token": "upstream-refresh-" + suffix,
                        "expires_in": 3 if suffix == "a" and isinstance(failure_index, str) else 300,
                        "refresh_expires_in": 600, "token_type": "Bearer"},
            expires_at=time.time() + 60, created_at=time.time())
        await auth._code_store.put(key=code.code, value=code, ttl=60)
        response = await http.post(base + "/token", data={"grant_type": "authorization_code", "client_id": client_id,
            "code": code.code, "redirect_uri": CHATGPT_REDIRECT, "code_verifier": verifier, "resource": PUBLIC_BASE + "/mcp"})
        assert response.status_code == 200
        return client_id, response.json()

    auth = provider()
    upstream_requests = []
    factory = httpx.AsyncClient
    async def unavailable(request):
        upstream_requests.append(parse_qs(request.content.decode())["token"][0])
        if len(upstream_requests) <= failure_index:
            return httpx.Response(200)
        raise httpx.ConnectError("identity unavailable", request=request)

    async with serve(make_server(StatusBackend(), GATEWAY_TOKEN, auth)) as base:
        async with httpx.AsyncClient() as http:
            client, tokens = await make_family(http, base, auth, "a")
            other_client, other = await make_family(http, base, auth, "b")
            assert await auth.load_access_token(tokens["access_token"])
            assert await auth.load_access_token(other["access_token"])
            client_info = await auth.get_client(client)
            prevalidated_refresh = await auth.load_refresh_token(client_info, tokens["refresh_token"])
            original_put = auth._client_storage.put
            async def crash_after_family(*args, **kwargs):
                family_write = kwargs.get("collection") == auth._pending_collection and kwargs.get("key", "").startswith("family-")
                if family_write and failure_index == "before-marker":
                    raise RuntimeError("fixture crash before family marker")
                await original_put(*args, **kwargs)
                if family_write and failure_index == "crash":
                    raise RuntimeError("fixture crash after durable family marker")
            with monkeypatch.context() as m:
                m.setattr(oauth, "httpx", SimpleNamespace(
                    AsyncClient=lambda **kw: factory(**kw, transport=httpx.MockTransport(unavailable)), HTTPError=httpx.HTTPError))
                if isinstance(failure_index, str):
                    m.setattr(auth._client_storage, "put", crash_after_family)
                response = await http.post(base + "/revoke", data={"client_id": client, "token": tokens["access_token"]})
            assert response.status_code == (500 if isinstance(failure_index, str) else 503)
            expected_calls = 0 if isinstance(failure_index, str) else failure_index + 1
            assert upstream_requests == ["upstream-refresh-a", "upstream-access-a"][:expected_calls]
            if isinstance(failure_index, str):
                await asyncio.sleep(3.2)  # The original access token and its original JTI TTL expire.
            assert await auth.load_access_token(tokens["access_token"]) is None
            if failure_index == "before-marker":
                # No revocation decision was durably recorded before the crash.
                assert await auth.load_refresh_token(client_info, tokens["refresh_token"])
            else:
                assert await auth.load_refresh_token(client_info, tokens["refresh_token"]) is None
                # A refresh prevalidated before revocation cannot resurrect the family.
                with pytest.raises(TokenError, match="Refresh token unavailable"):
                    await auth.exchange_refresh_token(client_info, prevalidated_refresh, SCOPES)
            assert await auth.load_access_token(other["access_token"])
            assert await auth.load_refresh_token(await auth.get_client(other_client), other["refresh_token"])
            # A durable-state read error must not masquerade as an unknown
            # token and a successful central revocation.
            async def unavailable_state(*args, **kwargs):
                raise OSError("fixture revocation storage unavailable")
            for target, method in [(auth._client_store, "get"), (auth._jti_mapping_store, "get"),
                                   (auth, "_pending_family"), (auth._upstream_token_store, "get")]:
                with monkeypatch.context() as m:
                    m.setattr(target, method, unavailable_state)
                    failed = await http.post(base + "/revoke", data={"client_id": client, "token": tokens["access_token"]})
                    assert failed.status_code == 503
                    assert await auth.load_access_token(tokens["access_token"]) is None
                assert len(upstream_requests) == expected_calls
            # Another DCR client cannot finish this family's pending revocation.
            with monkeypatch.context() as m:
                m.setattr(oauth, "httpx", SimpleNamespace(
                    AsyncClient=lambda **kw: factory(**kw, transport=httpx.MockTransport(unavailable)), HTTPError=httpx.HTTPError))
                wrong = await http.post(base + "/revoke", data={"client_id": other_client, "token": tokens["access_token"]})
            assert wrong.status_code == 200
            assert len(upstream_requests) == expected_calls
            # Validly signed tokens with the wrong issuer, audience or client,
            # and an invalid signature, cannot target this pending family.
            original_claims = dict(auth.jwt_issuer._jwt.decode(tokens["access_token"], auth._jwt_signing_key))
            headers = {"alg": "HS256", "typ": "JWT"}
            invalid_tokens = [auth.jwt_issuer._jwt.encode(headers, {**original_claims, field: "wrong"}, auth._jwt_signing_key).decode()
                              for field in ("iss", "aud", "client_id")]
            invalid_tokens.append(auth.jwt_issuer._jwt.encode(headers, original_claims, b"x" * 32).decode())
            with monkeypatch.context() as m:
                m.setattr(oauth, "httpx", SimpleNamespace(
                    AsyncClient=lambda **kw: factory(**kw, transport=httpx.MockTransport(unavailable)), HTTPError=httpx.HTTPError))
                for invalid in invalid_tokens:
                    assert (await http.post(base + "/revoke", data={"client_id": client, "token": invalid})).status_code == 200
            assert len(upstream_requests) == expected_calls
            for file in (tmp_path / "state").rglob("*"):
                if file.is_file():
                    assert b"upstream-access-a" not in file.read_bytes()
                    assert b"upstream-refresh-a" not in file.read_bytes()

    # No local bearer credential becomes valid on restart; retry can still
    # send both upstream credentials to Axxium under the original client.
    restored = provider()
    revoked = []
    async def central(request):
        form = parse_qs(request.content.decode())
        assert form["client_id"] == [CONFIG.client_id] and form["client_secret"] == [SECRET]
        revoked.append(form["token"][0])
        return httpx.Response(200)

    async with serve(make_server(StatusBackend(), GATEWAY_TOKEN, restored)) as base:
        async with httpx.AsyncClient() as http:
            assert await restored.load_access_token(tokens["access_token"]) is None
            assert await restored.load_access_token(other["access_token"])
            original_verify = restored.jwt_issuer.verify_token
            def expired_token(value):
                if value == tokens["access_token"]:
                    raise ValueError("fixture expired after failed revocation")
                return original_verify(value)
            with monkeypatch.context() as m:
                # The retry index must outlive a short-lived access JWT.
                m.setattr(restored.jwt_issuer, "verify_token", expired_token)
                m.setattr(oauth, "httpx", SimpleNamespace(
                    AsyncClient=lambda **kw: factory(**kw, transport=httpx.MockTransport(central)), HTTPError=httpx.HTTPError))
                response = await http.post(base + "/revoke", data={"client_id": client, "token": tokens["access_token"]})
            assert response.status_code == 200
            assert revoked == ["upstream-refresh-a", "upstream-access-a"]
            assert await restored.load_access_token(tokens["access_token"]) is None
            assert await restored.load_access_token(other["access_token"])


async def test_concurrent_authorization_code_exchange_is_one_use(tmp_path, monkeypatch):
    path = tmp_path / "client.json"
    path.write_text(json.dumps({"issuer": oauth.AXXIUM_ISSUER, "client_id": CONFIG.client_id,
                                "client_secret": SECRET, "allowed_subjects": [ACTOR]}))
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
    async with serve(make_server(StatusBackend(), GATEWAY_TOKEN, auth)) as base:
        async with httpx.AsyncClient() as http:
            registration = await http.post(base + "/register", json={"client_name": "fixture concurrent",
                "redirect_uris": [CHATGPT_REDIRECT], "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
                "scope": "openid profile"})
            client_id = registration.json()["client_id"]
            verifier = "fixture-verifier-" + "c" * 48
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
            code = ClientCode(code="concurrent-code", client_id=client_id, redirect_uri=CHATGPT_REDIRECT,
                code_challenge=challenge, code_challenge_method="S256", scopes=SCOPES,
                idp_tokens={"access_token": "upstream-access", "expires_in": 300, "token_type": "Bearer"},
                expires_at=time.time() + 60, created_at=time.time())
            await auth._code_store.put(key=code.code, value=code, ttl=60)
            original_get = auth._code_store.get
            async def interleaved_get(*args, **kwargs):
                result = await original_get(*args, **kwargs)
                # Expose the read/delete race deterministically, as a real
                # asynchronous storage implementation can interleave requests.
                await asyncio.sleep(0.02)
                return result
            monkeypatch.setattr(auth._code_store, "get", interleaved_get)
            fields = {"grant_type": "authorization_code", "client_id": client_id, "code": code.code,
                      "redirect_uri": CHATGPT_REDIRECT, "code_verifier": verifier, "resource": PUBLIC_BASE + "/mcp"}
            first, second = await asyncio.gather(http.post(base + "/token", data=fields),
                                                 http.post(base + "/token", data=fields))
            assert sorted([first.status_code, second.status_code]) == [200, 400]
