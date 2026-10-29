# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic MCP peers for a deployed transport stage, never Google execution."""
from fastmcp import FastMCP
from fastmcp.tools.tool import ToolResult


class BridgeFixture:
    synthetic_upstreams = True

    def status(self):
        return {'mode': 'transport-stage-bridge-fixture', 'synthetic_upstreams': True,
                'browser_connected': False, 'execution_verified': False}

    async def tools(self):
        return [{'name': 'fixture_echo', 'description': 'Synthetic read-only echo; no notebook or code execution',
                 'inputSchema': {'type': 'object', 'properties': {'text': {'type': 'string'}},
                                 'required': ['text'], 'additionalProperties': False},
                 'annotations': {'readOnlyHint': True, 'destructiveHint': False, 'openWorldHint': False}}]

    async def call(self, name, arguments):
        if name != 'fixture_echo' or set(arguments) != {'text'} or not isinstance(arguments['text'], str):
            raise ValueError('Synthetic fixture accepts only the discovered read-only echo tool')
        return ToolResult(content=[], structured_content={'synthetic_upstreams': True,
                          'execution_verified': False, 'fixture_echo': arguments['text']})


class ComputeFixture:
    def status(self):
        return {'mode': 'transport-stage-compute-fixture', 'synthetic_upstreams': True,
                'execution_verified': False, 'active_jobs': [], 'authentication_verified': False}

    async def invoke(self, operation):
        if operation == 'usage':
            return {'synthetic_upstreams': True, 'compute_units': None, 'execution_verified': False}
        if operation == 'sessions':
            return {'synthetic_upstreams': True, 'sessions': [], 'execution_verified': False}
        raise ValueError('Synthetic compute fixture only reports usage and sessions')

    async def start(self, code, accelerator, timeout_seconds):
        raise ValueError('Synthetic transport stage cannot execute code or allocate a runtime')

    async def job(self, job_id):
        raise ValueError('Synthetic transport stage owns no compute jobs')

    async def cancel(self, job_id):
        raise ValueError('Synthetic transport stage owns no compute jobs to cancel')


def make_fixture_server(role, token):
    # Import lazily: server's CLI imports this module only after validation.
    from knoxx_colab_mcp.server import BearerVerifier, make_server
    if role == 'bridge':
        return make_server(BridgeFixture(), token)
    if role != 'compute':
        raise ValueError('Unknown transport-stage fixture role')
    from knoxx_colab_mcp.compute import register_compute_tools
    server = FastMCP('Synthetic Colab Compute Transport Stage', auth=BearerVerifier(token),
                     instructions='Synthetic transport fixture only. No Google login, balance, sessions or execution is available.')
    return register_compute_tools(server, ComputeFixture())
