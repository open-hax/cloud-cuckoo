"""Protocol-stage fixtures exercise forwarding, never a live Google runtime."""
import base64
import hashlib
import json
import time

from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.server.auth.oauth_proxy import ClientCode
import httpx
import pytest

from knoxx_colab_mcp import server
from knoxx_colab_mcp.oauth import TRANSPORT_STAGING, PRODUCTION, SCOPES, auth_profile, make_gateway_auth
from knoxx_colab_mcp.transport_stage import BridgeFixture, ComputeFixture, make_fixture_server
from test_transport import serve

TOKEN = 'transport-stage-fixture-' + 's' * 40
DOWNSTREAM = 'transport-stage-caller-' + 'd' * 40


def test_profile_and_gateway_binding_are_fixed_and_separate():
    profile = auth_profile('transport-staging')
    assert profile is TRANSPORT_STAGING
    assert profile.issuer == 'https://staging.axxium.promethean.rest/oidc'
    assert profile.base_url == 'http://127.0.0.1:18771'
    assert profile.client_id == 'knoxx-colab-transport-staging'
    server.validate_gateway_binding('transport-staging', '127.0.0.1', 18771)
    for host, port in [('0.0.0.0', 18771), ('172.31.255.1', 18024), ('127.0.0.1', 18761)]:
        with pytest.raises(ValueError):
            server.validate_gateway_binding('transport-staging', host, port)


def test_transport_stage_never_reads_production_backend_settings(monkeypatch):
    paths = []
    def token(path):
        paths.append(str(path))
        return TOKEN
    monkeypatch.setattr(server, 'read_transport_stage_token', token)
    backend = server.gateway_backend('transport-staging', {
        'COLAB_BRIDGE_URL': 'https://production.invalid/mcp',
        'COLAB_BRIDGE_TOKEN_FILE': '/production/secret',
        'COLAB_COMPUTE_URL': 'https://production.invalid/compute'})
    assert isinstance(backend, server.Gateway)
    assert backend.url == 'http://127.0.0.1:18773/mcp'
    assert backend.compute_url == 'http://127.0.0.1:18775/mcp'
    assert paths == [str(server.TRANSPORT_STAGE_TOKEN)]


def test_fixture_token_requires_an_owned_private_regular_file(tmp_path):
    path = tmp_path / 'fixture-token'
    path.write_text(TOKEN)
    path.chmod(0o600)
    assert server.read_transport_stage_token(path) == TOKEN
    path.chmod(0o644)
    with pytest.raises(ValueError):
        server.read_transport_stage_token(path)
    path.chmod(0o600)
    link = tmp_path / 'symlink'
    link.symlink_to(path)
    with pytest.raises(ValueError):
        server.read_transport_stage_token(link)


@pytest.mark.parametrize(('role', 'port'), [('bridge', 18773), ('compute', 18775)])
def test_fixture_listeners_refuse_other_interfaces_ports_and_profiles(role, port):
    server.validate_transport_fixture_binding('transport-staging', role, '127.0.0.1', port)
    for profile, host, candidate in [('production', '127.0.0.1', port),
                                      ('transport-staging', '0.0.0.0', port),
                                      ('transport-staging', '127.0.0.1', 18024)]:
        with pytest.raises(ValueError):
            server.validate_transport_fixture_binding(profile, role, host, candidate)


async def test_real_gateway_forwards_to_dedicated_mcp_fixtures_and_preserves_errors(diagnostics):
    async with serve(make_fixture_server('bridge', TOKEN)) as bridge:
        async with serve(make_fixture_server('compute', TOKEN)) as compute:
            backend = server.TransportStagingGateway(TOKEN)
            # Only the test harness substitutes ephemeral loopback listeners;
            # the deployable profile has no endpoint override.
            backend.url, backend.compute_url = bridge + '/mcp', compute + '/mcp'
            async with serve(server.make_server(backend, DOWNSTREAM)) as base:
                async with httpx.AsyncClient() as http:
                    assert (await http.post(base + '/mcp', json={})).status_code == 401
                async with Client(StreamableHttpTransport(base + '/mcp', auth=DOWNSTREAM)) as client:
                    names = {tool.name for tool in await client.list_tools()}
                    assert set(server.TOOL_NAMES) <= names
                    assert 'colab_compute_usage' in names
                    status = (await client.call_tool('colab_status', {})).data
                    assert status['synthetic_upstreams'] is True
                    assert status['bridge']['browser_connected'] is False
                    assert status['bridge']['execution_verified'] is False
                    connect = (await client.call_tool('colab_connect', {})).data
                    assert connect['synthetic_upstreams'] is True and 'open-browser' not in json.dumps(connect)
                    tools = (await client.call_tool('colab_tools', {})).structured_content['result']
                    assert [tool['name'] for tool in tools] == ['fixture_echo']
                    output = await client.call_tool('colab_call', {'name': 'fixture_echo', 'arguments': {'text': 'transport assertion'}})
                    assert output.structured_content['fixture_echo'] == 'transport assertion'
                    assert output.structured_content['synthetic_upstreams'] is True
                    error = await client.call_tool('colab_call', {'name': 'fixture_failure', 'arguments': {}}, raise_on_error=False)
                    assert error.is_error
                    diagnostics.expect(logger='fastmcp.tools.tool_manager', level=40,
                        message="Error calling tool 'colab_call'",
                        exception=ValueError('Synthetic fixture accepts only the discovered read-only echo tool'))
                    diagnostics.expect(logger='fastmcp.tools.tool_manager', level=40,
                        message="Error calling tool 'colab_call'",
                        exception=ValueError("Error calling tool 'colab_call': Synthetic fixture accepts only the discovered read-only echo tool"))
                    usage = (await client.call_tool('colab_compute_usage', {})).data
                    assert usage['synthetic_upstreams'] is True and usage['compute_units'] is None
                    sessions = (await client.call_tool('colab_compute_sessions', {})).data
                    assert sessions['sessions'] == [] and sessions['synthetic_upstreams'] is True
                    refused = await client.call_tool('colab_compute_start', {'code': "raise RuntimeError('never execute')"}, raise_on_error=False)
                    assert refused.is_error
                    diagnostics.expect(logger='fastmcp.tools.tool_manager', level=40,
                        message="Error calling tool 'colab_compute_start'",
                        exception=ValueError('Synthetic transport stage cannot execute code or allocate a runtime'))
                    diagnostics.expect(logger='fastmcp.tools.tool_manager', level=40,
                        message="Error calling tool 'colab_compute_start'",
                        exception=ValueError("Error calling tool 'colab_compute_start': Synthetic transport stage cannot execute code or allocate a runtime"))


async def test_fixture_backends_never_execute_code_or_allocate_jobs():
    bridge, compute = BridgeFixture(), ComputeFixture()
    with pytest.raises(ValueError):
        await bridge.call('execute_python', {'code': "raise RuntimeError('never execute')"})
    for operation in [compute.start('arbitrary code', 'cpu', 120), compute.cancel('foreign'), compute.job('foreign')]:
        with pytest.raises(ValueError):
            await operation


def test_transport_cli_uses_only_its_fixed_client_and_state(monkeypatch):
    import knoxx_colab_mcp.oauth as oauth
    observed = []
    monkeypatch.setenv('COLAB_AUTH_PROFILE', 'transport-staging')
    monkeypatch.setenv('COLAB_AXXIUM_CLIENT_FILE', '/production/forbidden-client')
    monkeypatch.setenv('COLAB_OAUTH_STATE_DIR', '/production/forbidden-state')
    monkeypatch.setenv('COLAB_OAUTH_BASE_URL', PRODUCTION.base_url)
    monkeypatch.setattr(server, 'read_transport_stage_token', lambda path: TOKEN)
    monkeypatch.setattr(oauth, 'make_gateway_auth', lambda *args: observed.append(args) or object())
    class PreparedServer:
        def run(self, **kwargs):
            assert kwargs['host'] == '127.0.0.1' and kwargs['port'] == 18771
    monkeypatch.setattr(server, 'make_server', lambda *args, **kwargs: PreparedServer())
    monkeypatch.setattr('sys.argv', ['knoxx-colab-mcp', 'gateway', '--host', '127.0.0.1', '--port', '18771'])
    server.main()
    assert observed == [(TRANSPORT_STAGING.base_url, server.TRANSPORT_STAGE_STATE,
                         server.TRANSPORT_STAGE_CLIENT, TRANSPORT_STAGING)]


@pytest.mark.parametrize('mode', ['bridge', 'open-browser'])
def test_transport_profile_cannot_launch_a_google_browser(monkeypatch, mode):
    monkeypatch.setenv('COLAB_AUTH_PROFILE', 'transport-staging')
    monkeypatch.setattr('sys.argv', ['knoxx-colab-mcp', mode])
    monkeypatch.setattr(server, 'read_secret', lambda path: pytest.fail('Production key was read'))
    monkeypatch.setattr(server.webbrowser, 'open', lambda url: pytest.fail('Google browser was opened'))
    with pytest.raises(ValueError, match='cannot start or open'):
        server.main()


async def test_oauth_authenticates_real_stage_forwarding_and_denies_replay_and_revocation(tmp_path, monkeypatch, diagnostics):
    profile = TRANSPORT_STAGING
    actor = 'actor_00000000-0000-4000-8000-000000000001'
    callback = 'http://127.0.0.1:18776/callback'
    config = tmp_path / 'client.json'
    config.write_text(json.dumps({'issuer': profile.issuer, 'client_id': profile.client_id,
        'client_secret': 'fixture-transport-client-' + 'x' * 48, 'allowed_subjects': [actor],
        'allowed_client_redirect_uris': [callback]}))
    config.chmod(0o600)
    discovery = {'issuer': profile.issuer, 'code_challenge_methods_supported': ['S256'],
        'token_endpoint_auth_methods_supported': ['client_secret_post'],
        **{key: profile.issuer + path for key, path in {'authorization_endpoint': '/auth',
            'token_endpoint': '/token', 'introspection_endpoint': '/token/introspection',
            'revocation_endpoint': '/token/revocation', 'jwks_uri': '/jwks'}.items()}}
    real_http = httpx.Client
    def fixture_discovery(*args, **kwargs):
        return real_http(transport=httpx.MockTransport(lambda request: httpx.Response(200, json=discovery)))
    monkeypatch.setattr(httpx, 'Client', fixture_discovery)
    auth = make_gateway_auth(profile.base_url, tmp_path / 'oauth', config, profile)
    diagnostics.expect(logger='fastmcp.server.auth.oauth_proxy', level=30,
        message='Using non-secure cookies for development; deploy with HTTPS for production.')
    active = True
    async def introspection(request):
        return httpx.Response(200, json={'active': active, 'sub': actor, 'client_id': profile.client_id,
            'exp': time.time() + 300, 'scope': 'openid profile', 'iss': profile.issuer})
    auth._token_validator.transport = httpx.MockTransport(introspection)
    async with serve(make_fixture_server('bridge', TOKEN)) as bridge:
        async with serve(make_fixture_server('compute', TOKEN)) as compute:
            backend = server.TransportStagingGateway(TOKEN)
            backend.url, backend.compute_url = bridge + '/mcp', compute + '/mcp'
            async with serve(server.make_server(backend, '', auth)) as base:
                async with httpx.AsyncClient() as http:
                    metadata = (await http.get(base + '/.well-known/oauth-authorization-server')).json()
                    assert metadata['issuer'].rstrip('/') == profile.base_url
                    assert metadata['scopes_supported'] == SCOPES
                    assert metadata['code_challenge_methods_supported'] == ['S256']
                    registration = await http.post(base + '/register', json={'client_name': 'synthetic transport-stage caller',
                        'redirect_uris': [callback], 'token_endpoint_auth_method': 'none',
                        'grant_types': ['authorization_code', 'refresh_token'], 'response_types': ['code'], 'scope': 'openid profile'})
                    assert registration.status_code == 201
                    client_id = registration.json()['client_id']
                    verifier = 'fixture-pkce-' + 'v' * 48
                    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
                    # A synthetic upstream grant exercises the real gateway
                    # code/PKCE/storage/token boundary; no human sign-in claim.
                    code = ClientCode(code='synthetic-stage-code', client_id=client_id, redirect_uri=callback,
                        code_challenge=challenge, code_challenge_method='S256', scopes=SCOPES,
                        idp_tokens={'access_token': 'fixture-upstream-access', 'refresh_token': 'fixture-upstream-refresh',
                                    'expires_in': 300, 'refresh_expires_in': 600, 'token_type': 'Bearer'},
                        expires_at=time.time() + 60, created_at=time.time())
                    await auth._code_store.put(key=code.code, value=code, ttl=60)
                    fields = {'grant_type': 'authorization_code', 'client_id': client_id, 'code': code.code,
                              'redirect_uri': callback, 'code_verifier': verifier, 'resource': profile.base_url + '/mcp'}
                    assert (await http.post(base + '/token', data={**fields, 'resource': PRODUCTION.base_url + '/mcp'})).status_code == 400
                    response = await http.post(base + '/token', data=fields)
                    assert response.status_code == 200
                    bearer = response.json()['access_token']
                    async with Client(StreamableHttpTransport(base + '/mcp', auth=bearer)) as mcp:
                        status = (await mcp.call_tool('colab_status', {})).data
                        assert status['synthetic_upstreams'] is True
                        result = await mcp.call_tool('colab_call', {'name': 'fixture_echo', 'arguments': {'text': 'oauth transport'}})
                        assert result.structured_content['fixture_echo'] == 'oauth transport'
                        assert (await mcp.call_tool('colab_compute_sessions', {})).data['sessions'] == []
                    assert (await http.post(base + '/token', data=fields)).status_code == 400
                    active = False
                    denied = await http.post(base + '/mcp', headers={'Authorization': 'Bearer ' + bearer},
                        json={'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
                            'protocolVersion': '2025-03-26', 'capabilities': {},
                            'clientInfo': {'name': 'synthetic-stage', 'version': '1'}}})
                    assert denied.status_code == 401
    assert (tmp_path / 'oauth' / 'transport-staging' / 'axxium-proxy').is_dir()
