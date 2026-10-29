"""The documented two-hop production binding must match both client contracts."""
import json
from pathlib import Path

import pytest

from knoxx_colab_mcp.oauth import AxxiumClient, CHATGPT_REDIRECT, PRODUCTION

ROOT = Path(__file__).parents[1]
ACTOR = "actor_00000000-0000-4000-8000-000000000001"


def test_documented_client_binding_is_inert_and_cross_consistent(tmp_path):
    authority = json.loads((ROOT / "examples/production-axxium-client.json").read_text())
    gateway = json.loads((ROOT / "examples/production-gateway-client.json").read_text())

    # A checked-in example must never be accepted as a live credential file.
    path = tmp_path / "client.json"
    path.write_text(json.dumps(gateway))
    path.chmod(0o600)
    with pytest.raises(ValueError, match="strong registered"):
        AxxiumClient.read(path)

    assert authority["id"] == gateway["client_id"] == PRODUCTION.client_id
    assert authority["secret"] == gateway["client_secret"] == "UNSET"
    assert authority["redirect-uris"] == [PRODUCTION.base_url + "/auth/callback"]
    assert authority["refresh-enabled?"] is True
    assert authority["device-enabled?"] is False
    assert gateway["issuer"] == PRODUCTION.issuer
    assert gateway["allowed_subjects"] == [ACTOR]

    # A synthetic replacement exercises the actual gateway parser; it is never
    # written to a service directory or used to contact an external authority.
    gateway["client_secret"] = "fixture-secret-" + "x" * 48
    path.write_text(json.dumps(gateway))
    client = AxxiumClient.read(path)
    assert client.allowed_subjects == frozenset([ACTOR])
    assert client.allowed_client_redirect_uris == (CHATGPT_REDIRECT,)
