"""Axxium relying-party adapter. This gateway does not authenticate humans.

FastMCP owns MCP OAuth/PKCE. Axxium owns login, actors and root sessions.
Missing identity configuration denies access, including legacy keys.
"""
import base64
from dataclasses import dataclass, field
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import time
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
from fastmcp.server.auth import AccessToken, AuthProvider, TokenVerifier
from fastmcp.server.auth.auth import TokenHandler
from fastmcp.server.auth.oauth_proxy import OAuthProxy
import httpx
from key_value.aio.stores.disk import DiskStore
from key_value.aio.wrappers.encryption import FernetEncryptionWrapper
from mcp.server.auth.middleware.client_auth import AuthenticationError, ClientAuthenticator
from mcp.server.auth.provider import RegistrationError
from mcp.shared.auth import OAuthClientInformationFull
from pydantic import AnyUrl
from mcp.server.auth.routes import cors_middleware, create_protected_resource_routes
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route

AXXIUM_ISSUER = "https://axxium.promethean.rest/oidc"
PUBLIC_BASE = "https://knoxx.promethean.rest/colab"
SCOPES = ["openid", "profile"]
CHATGPT_REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect"
UNAVAILABLE = "Axxium sign-in is not available for Knoxx Colab yet. No access was granted."


def protected(response):
    response.headers.update({"Cache-Control": "no-store", "Pragma": "no-cache",
                             "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY",
                             "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"})
    return response


class IdentityUnavailable(AuthProvider):
    """Keep public transport running without substituting another login method."""

    def __init__(self, base_url=PUBLIC_BASE):
        super().__init__(base_url=base_url, required_scopes=SCOPES)

    async def verify_token(self, token):
        return None

    async def unavailable(self, request):
        if request.method == "GET" and request.url.path.endswith(("/authorize", "/consent")):
            return protected(HTMLResponse(
                '<!doctype html><html lang="en"><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width,initial-scale=1">'
                '<title>Knoxx Colab — Axxium sign-in pending</title>'
                '<h1>Axxium sign-in pending</h1><p>' + UNAVAILABLE + '</p>'
                '<p>This connection will use your existing Axxium account once the shared '
                'identity service is activated. Close this page; there is no credential to enter here.</p></html>',
                status_code=503, headers={"Retry-After": "300"}))
        return protected(JSONResponse({"error": "temporarily_unavailable", "error_description": UNAVAILABLE},
                                      status_code=503, headers={"Retry-After": "300"}))

    def get_routes(self, mcp_path=None):
        self.set_mcp_path(mcp_path)
        routes = create_protected_resource_routes(
            resource_url=self._resource_url, authorization_servers=[self.base_url],
            scopes_supported=SCOPES, resource_name="Knoxx Colab (Axxium pending)")
        paths = ["/authorize", "/consent", "/register", "/token", "/revoke", "/auth/callback",
                 "/.well-known/oauth-authorization-server",
                 "/.well-known/oauth-authorization-server" + urlsplit(str(self.base_url)).path]
        return routes + [Route(path, self.unavailable, methods=["GET", "POST", "OPTIONS"]) for path in paths]


@dataclass(frozen=True)
class AxxiumClient:
    client_id: str
    client_secret: str = field(repr=False)
    allowed_subjects: frozenset[str]
    allowed_client_redirect_uris: tuple[str, ...] = (CHATGPT_REDIRECT,)

    @classmethod
    def read(cls, path: Path):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError("Axxium client configuration must be a regular private 0600 file")
        data = json.loads(path.read_text())
        if data.get("issuer") != AXXIUM_ISSUER or data.get("client_id") != "knoxx-colab":
            raise ValueError("Axxium issuer and registered Colab client must match")
        secret = data.get("client_secret", "")
        if not isinstance(secret, str) or len(secret) < 32:
            raise ValueError("A strong registered Axxium client secret is required")
        subjects = data.get("allowed_subjects")
        if not isinstance(subjects, list) or not subjects or any(
            not isinstance(s, str) or not re.fullmatch(r"actor_[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", s)
            for s in subjects
        ):
            raise ValueError("Explicit stable Axxium actor IDs are required; names, email and roles are not identities")
        extra_redirects = data.get("allowed_client_redirect_uris", [])
        if not isinstance(extra_redirects, list) or len(extra_redirects) > 16:
            raise ValueError("Client redirect allowlist must contain at most 16 exact URIs")
        redirects = [CHATGPT_REDIRECT]
        for value in extra_redirects:
            if not isinstance(value, str) or not value or len(value) > 2048 or any(c in value for c in "*?#[%\\"):
                raise ValueError("Invalid client redirect URI")
            try:
                uri = AnyUrl(value)
                parts = urlsplit(str(uri))
                valid = (parts.scheme == "https" or
                         (parts.scheme == "http" and parts.hostname in {"localhost", "127.0.0.1"}))
                if not valid or not parts.hostname or parts.username or parts.password:
                    raise ValueError("Invalid client redirect URI")
            except (TypeError, ValueError) as exc:
                raise ValueError("Invalid client redirect URI") from exc
            if str(uri) in redirects:
                raise ValueError("Duplicate client redirect URI")
            redirects.append(str(uri))
        return cls(data["client_id"], secret, frozenset(subjects), tuple(redirects))


def validate_discovery(data):
    """Constrain destinations before sending the confidential client secret."""
    if data.get("issuer") != AXXIUM_ISSUER:
        raise ValueError("Unexpected Axxium issuer")
    for name in ("authorization_endpoint", "token_endpoint", "introspection_endpoint", "revocation_endpoint", "jwks_uri"):
        value = data.get(name)
        if not isinstance(value, str):
            raise ValueError("Incomplete Axxium discovery")
        uri = urlsplit(value)
        if (uri.scheme != "https" or uri.netloc != "axxium.promethean.rest" or
                not uri.path.startswith("/oidc/") or uri.query or uri.fragment or "/../" in uri.path or "%" in uri.path):
            raise ValueError("Axxium endpoint escaped its pinned issuer")
    if "S256" not in data.get("code_challenge_methods_supported", []):
        raise ValueError("Axxium must support S256 PKCE")
    if "client_secret_post" not in data.get("token_endpoint_auth_methods_supported", []):
        raise ValueError("Axxium registered-client authentication unavailable")
    return data


class AxxiumTokenVerifier(TokenVerifier):
    """Check the current central grant on every request; no local actor fallback."""

    def __init__(self, config, endpoint, transport=None):
        super().__init__(required_scopes=SCOPES)
        self.config, self.endpoint, self.transport = config, endpoint, transport

    async def verify_token(self, token):
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=False, transport=self.transport) as http:
                response = await http.post(self.endpoint, data={
                    "client_id": self.config.client_id, "client_secret": self.config.client_secret, "token": token})
                response.raise_for_status()
                data = response.json()
            expiry = data.get("exp")
            scopes = data.get("scope", "").split()
            if (data.get("active") is not True or data.get("client_id") != self.config.client_id or
                    data.get("sub") not in self.config.allowed_subjects or
                    isinstance(expiry, bool) or not isinstance(expiry, (int, float)) or
                    not math.isfinite(expiry) or expiry <= time.time() or
                    not set(SCOPES).issubset(scopes) or data.get("iss", AXXIUM_ISSUER) != AXXIUM_ISSUER):
                return None
            audience = data.get("aud")
            if audience is not None and audience not in (self.config.client_id, [self.config.client_id]):
                return None
            return AccessToken(token=token, client_id=self.config.client_id, scopes=scopes,
                               expires_at=int(expiry), subject=data["sub"], resource=PUBLIC_BASE + "/mcp",
                               claims={"sub": data["sub"], "iss": AXXIUM_ISSUER})
        except (httpx.HTTPError, ValueError, TypeError, AttributeError):
            return None


class AxxiumOAuthProxy(OAuthProxy):
    """Only protocol adaptations to the pinned proxy, never a human login form."""

    async def register_client(self, client_info):
        if not client_info.redirect_uris or any(str(uri) not in self._allowed_client_redirect_uris for uri in client_info.redirect_uris):
            raise RegistrationError("invalid_redirect_uri", "Use an operator-approved exact callback")
        return await super().register_client(client_info)

    async def get_client(self, client_id):
        client = await super().get_client(client_id)
        if not client or not client.redirect_uris or any(
            str(uri) not in self._allowed_client_redirect_uris for uri in client.redirect_uris
        ):
            return None
        # ProxyDCRClient validates against global patterns, allowing another
        # client's callback. The SDK model enforces this client's registered URIs.
        return OAuthClientInformationFull.model_validate(client.model_dump())

    async def load_access_token(self, token):
        try:
            if self.jwt_issuer.verify_token(token).get("token_use") is not None:
                return None
        except Exception:
            return None
        return await super().load_access_token(token)

    async def load_refresh_token(self, client, token):
        try:
            payload = self.jwt_issuer.verify_token(token)
            if payload.get("token_use") != "refresh":
                return None
            mapping = await self._jti_mapping_store.get(key=payload["jti"])
            upstream = await self._upstream_token_store.get(key=mapping.upstream_token_id) if mapping else None
            if not upstream or upstream.client_id != client.client_id:
                return None
        except Exception:
            return None
        return await super().load_refresh_token(client, token)

    async def revoke_request(self, request):
        # MCP 1.30.0's revocation model requires client_secret for public clients.
        # Keep its authenticator and permit the RFC 7009 public-client form.
        try:
            client = await ClientAuthenticator(self).authenticate_request(request)
        except AuthenticationError:
            return protected(JSONResponse({"error": "invalid_client"}, status_code=401))
        form = await request.form()
        raw = form.get("token")
        if not isinstance(raw, str) or not raw or form.get("token_type_hint") not in {None, "access_token", "refresh_token"}:
            return protected(JSONResponse({"error": "invalid_request"}, status_code=400))
        try:
            payload = self.jwt_issuer.verify_token(raw)
            mapping = await self._jti_mapping_store.get(key=payload["jti"])
            upstream = await self._upstream_token_store.get(key=mapping.upstream_token_id) if mapping else None
        except Exception:
            upstream = None
        if upstream and upstream.client_id == client.client_id:
            # Invalidate the entire local family even if central revocation fails.
            await self._upstream_token_store.delete(key=upstream.upstream_token_id)
            await self._jti_mapping_store.delete(key=payload["jti"])
            await self._refresh_token_store.delete(key=hashlib.sha256(raw.encode()).hexdigest())
            try:
                async with httpx.AsyncClient(timeout=10, follow_redirects=False) as http:
                    for token in filter(None, (upstream.refresh_token, upstream.access_token)):
                        response = await http.post(self._upstream_revocation_endpoint, data={
                            "client_id": self._upstream_client_id,
                            "client_secret": self._upstream_client_secret.get_secret_value(), "token": token})
                        response.raise_for_status()
            except httpx.HTTPError:
                return protected(JSONResponse({"error": "temporarily_unavailable",
                    "error_description": "Local access revoked; central revocation could not be confirmed."}, status_code=503))
        return protected(Response(status_code=200))

    def get_routes(self, mcp_path=None):
        routes = super().get_routes(mcp_path)
        metadata = next(r for r in routes if r.path == "/.well-known/oauth-authorization-server")
        routes = [r for r in routes if r.path not in {"/revoke", "/token"}]
        routes.append(Route("/revoke", cors_middleware(self.revoke_request, ["POST", "OPTIONS"]), methods=["POST", "OPTIONS"]))
        handler = ResourceTokenHandler(self, ClientAuthenticator(self))
        routes.append(Route("/token", cors_middleware(handler.handle, ["POST", "OPTIONS"]), methods=["POST", "OPTIONS"]))
        routes.append(Route("/.well-known/oauth-authorization-server" + urlsplit(str(self.base_url)).path,
                            metadata.endpoint, methods=["GET", "OPTIONS"]))
        return routes


class ResourceTokenHandler(TokenHandler):
    async def handle(self, request):
        form = await request.form()
        if form.get("resource") not in {None, PUBLIC_BASE + "/mcp"}:
            return protected(JSONResponse({"error": "invalid_target"}, status_code=400))
        return await super().handle(request)


def make_gateway_auth(base_url, state_dir, config_path=None):
    if base_url != PUBLIC_BASE:
        raise ValueError("Public Colab URL must match the registered Axxium callback")
    if config_path is None or not config_path.exists():
        return IdentityUnavailable(base_url)
    config = AxxiumClient.read(config_path)
    with httpx.Client(timeout=10, follow_redirects=False) as http:
        response = http.get(AXXIUM_ISSUER + "/.well-known/openid-configuration")
        response.raise_for_status()
        discovery = validate_discovery(response.json())
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if state_dir.is_symlink() or state_dir.stat().st_mode & 0o077:
        raise ValueError("OAuth state directory must be private (0700)")
    os.umask(0o077)
    encryption_key = base64.urlsafe_b64encode(hashlib.sha256(
        b"knoxx-colab-axxium-storage-v1\0" + config.client_secret.encode()).digest())
    storage = FernetEncryptionWrapper(key_value=DiskStore(directory=state_dir / "axxium-proxy"),
                                     fernet=Fernet(encryption_key))
    return AxxiumOAuthProxy(
        upstream_authorization_endpoint=discovery["authorization_endpoint"],
        upstream_token_endpoint=discovery["token_endpoint"],
        upstream_revocation_endpoint=discovery["revocation_endpoint"],
        upstream_client_id=config.client_id, upstream_client_secret=config.client_secret,
        token_verifier=AxxiumTokenVerifier(config, discovery["introspection_endpoint"]),
        base_url=base_url, redirect_path="/auth/callback", issuer_url=base_url,
        allowed_client_redirect_uris=list(config.allowed_client_redirect_uris), valid_scopes=SCOPES,
        forward_pkce=True, token_endpoint_auth_method="client_secret_post",
        client_storage=storage, require_authorization_consent=True,
        fallback_access_token_expiry_seconds=300)
