<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Maintained JOSE compatibility

Cloud Cuckoo consumes Google's browser Colab implementation through a
FastMCP 2.14.5 compatibility line. The official Google source still pins
that public FastMCP version. OpenHAX maintains two small source forks so
this application can use patched Authlib and the current joserfc/HTTPX2
stack without deprecated Authlib JOSE imports.

The FastMCP fork adapts the two applicable auth files from official
PrefectHQ/fastmcp PR4221 onto upstream 21221b4ab128e8dd71b5d9637fa70a9139511380.
It preserves the twelve advertised HS/RS/ES/PS algorithms and JWKS cache
rotation. The Google fork starts at official
b9ab3899e0f1fa493390b1fd6d54aa2e464ecdf1 and closes all four owned endpoints
of its two paired memory streams. Both forks retain the original Apache
LICENSE and attribution, with full LGPL3-or-later terms and a clear
OpenHAX-authored modification boundary. This application remains GPL3-or-later.

The accepted source changes are [FastMCP fork PR1](https://github.com/open-hax/fastmcp/pull/1)
at [ece14b78](https://github.com/open-hax/fastmcp/commit/ece14b78b0c44bc80ef7fe8c2955caa6bf5f6732)
and [Google Colab fork PR1](https://github.com/open-hax/colab-mcp/pull/1)
at [493fa290](https://github.com/open-hax/colab-mcp/commit/493fa290f7e9051000cb124b7cd5a55add18af50).

Application requirements and uv.lock bind reachable immutable fork Git
objects; native PR acceptance and ancestry are separate adoption evidence. They contain no private file URI, local-version PyPI fiction,
or fallback to a similarly named unrelated package. Docker already uses
this committed lock via frozen uv sync. The final dependency graph is
checked independently from each library's supported development lock.

The revocation decoder uses joserfc for a verified HS256 signature while
retaining issuer, audience, client, family and token-use checks. Its
expired-token allowance belongs only to revocation; normal access and
refresh verification continues to reject expired tokens. The existing
revocation-retry assertions are preserved while their signing fixture
uses the public joserfc API. Explicit function-scoped pytest async fixtures
remove an unset-scope configuration warning. No warning filter is added.

The regression suite checks expired revocation, incorrect signatures and
binding claims, issuer/RSA behavior, and actual installed Google stream
cleanup. These tests and cold imports must be warning-free in the locked
application environment. Passing source tests or a native wheel build
does not admit a production image or claim human ChatGPT OAuth completion.
