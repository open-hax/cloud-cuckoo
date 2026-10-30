"""Behavioral regressions for the pinned JOSE and stream-cleanup compatibility stack."""

import gc
import time
import pytest
from joserfc import jwk, jwt
from joserfc.errors import JoseError
from fastmcp.server.auth.jwt_issuer import JWTIssuer
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from colab_mcp.websocket_server import ColabWebSocketServer
from knoxx_colab_mcp.oauth import AxxiumOAuthProxy

KEY = b"prototype-only-signing-material-" * 3
ISSUER = "https://fixture.invalid/colab"
AUDIENCE = ISSUER + "/mcp"
CLIENT = "prototype-client"


def proxy():
    """Build only the local decoder state; allocate no remote OAuth session."""
    value = object.__new__(AxxiumOAuthProxy)
    value._jwt_signing_key = KEY
    value._jwt_issuer = JWTIssuer(issuer=ISSUER, audience=AUDIENCE, signing_key=KEY)
    return value


def signed(payload, *, key=KEY, algorithm="HS256"):
    """Sign fixture claims with the explicitly selected algorithm and key."""
    return jwt.encode(
        {"alg": algorithm}, payload, jwk.import_key(key, "oct"), algorithms=[algorithm]
    )


def expired_payload():
    """Return bound expired refresh claims for the revocation-only path."""
    return {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "client_id": CLIENT,
        "jti": "owned-fixture-family",
        "iat": int(time.time()) - 120,
        "exp": int(time.time()) - 60,
        "token_use": "refresh",
    }


def test_expired_signed_refresh_can_only_be_used_for_bound_revocation():
    """Expired signed refresh tokens remain revocable but unusable for ordinary verification."""
    value = proxy()
    token = signed(expired_payload())
    with pytest.raises(JoseError):
        value.jwt_issuer.verify_token(token)
    payload = value._revocation_payload(token, CLIENT)
    assert payload["exp"] < time.time()
    assert payload["jti"] == "owned-fixture-family"
    assert payload["client_id"] == CLIENT


@pytest.mark.parametrize(
    "change",
    [
        {"iss": "https://other.invalid"},
        {"aud": "other"},
        {"client_id": "other"},
        {"jti": ""},
        {"jti": None},
        {"token_use": "access"},
    ],
)
def test_revocation_decoder_preserves_every_binding_check(change):
    """Revocation rejects mismatched issuer, audience, client, family and token use."""
    with pytest.raises(ValueError):
        proxy()._revocation_payload(signed({**expired_payload(), **change}), CLIENT)


@pytest.mark.parametrize(
    "key,algorithm",
    [(b"different-fixture-signing-material-" * 3, "HS256"), (KEY, "HS512")],
)
def test_expired_revocation_refuses_bad_signature_and_unallowed_algorithm(
    key, algorithm
):
    """Expired-token revocation still requires the correct signature and HS256."""
    with pytest.raises(JoseError):
        proxy()._revocation_payload(
            signed(expired_payload(), key=key, algorithm=algorithm), CLIENT
        )


def test_native_issuer_roundtrip_keeps_signature_and_audience_guards():
    """Issuer verification preserves signature and audience guards."""
    value = proxy()
    token = value.jwt_issuer.issue_access_token(
        CLIENT, ["openid", "profile"], "access-fixture", expires_in=60
    )
    assert value.jwt_issuer.verify_token(token)["jti"] == "access-fixture"
    other = JWTIssuer(issuer=ISSUER, audience="wrong-audience", signing_key=KEY)
    with pytest.raises(JoseError):
        other.verify_token(token)
    other = JWTIssuer(
        issuer=ISSUER, audience=AUDIENCE, signing_key=b"other-fixture-material-" * 3
    )
    with pytest.raises(JoseError):
        other.verify_token(token)


async def test_native_rsa_provider_roundtrip_invalid_signature_and_expiry():
    """The installed RSA verifier accepts valid tokens and rejects invalid signatures and expiry."""
    pair = RSAKeyPair.generate()
    other = RSAKeyPair.generate()
    verifier = JWTVerifier(
        public_key=pair.public_key,
        issuer=ISSUER,
        audience=AUDIENCE,
        algorithm="RS256",
        required_scopes=["openid"],
    )
    token = pair.create_token(
        subject="fixture",
        issuer=ISSUER,
        audience=AUDIENCE,
        scopes=["openid"],
        expires_in_seconds=60,
    )
    assert await verifier.load_access_token(token) is not None
    forged = other.create_token(
        subject="fixture",
        issuer=ISSUER,
        audience=AUDIENCE,
        scopes=["openid"],
        expires_in_seconds=60,
    )
    assert await verifier.load_access_token(forged) is None
    expired = pair.create_token(
        subject="fixture",
        issuer=ISSUER,
        audience=AUDIENCE,
        scopes=["openid"],
        expires_in_seconds=-60,
    )
    assert await verifier.load_access_token(expired) is None


def endpoints(server):
    """Return all endpoints owned by the installed browser transport."""
    return [
        server.read_stream,
        server.write_stream,
        server._read_stream_writer,
        server._write_stream_reader,
    ]


async def test_actual_websocket_context_closes_all_four_owned_endpoints():
    """An actual installed browser transport releases all four stream endpoints."""
    server = ColabWebSocketServer(host="127.0.0.1")
    streams = endpoints(server)
    assert not any(s._closed for s in streams)
    async with server:
        assert server.port > 0
    assert all(s._closed for s in streams)
    gc.collect()


async def test_unstarted_server_cleanup_still_closes_all_four_endpoints():
    """Cleanup before startup still releases all owned stream endpoints."""
    server = ColabWebSocketServer(host="127.0.0.1")
    streams = endpoints(server)
    assert server._server is None
    await server.__aexit__(None, None, None)
    assert all(s._closed for s in streams)


async def test_native_shutdown_wait_failure_does_not_leave_stream_endpoints_open():
    """A shutdown wait failure occurs after all owned stream endpoints close."""
    server = ColabWebSocketServer(host="127.0.0.1")
    streams = endpoints(server)

    class FailedWait:
        def close(self):
            pass

        async def wait_closed(self):
            raise RuntimeError("fixture shutdown wait failed")

    server._server = FailedWait()
    with pytest.raises(RuntimeError, match="shutdown wait failed"):
        await server.__aexit__(None, None, None)
    assert all(s._closed for s in streams)
