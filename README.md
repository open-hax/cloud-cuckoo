# Cloud Cuckoo

Cloud Cuckoo is OpenHAX’s private Colab MCP bridge: a cuckoo carrying agent requests into Google’s cloud notebooks and compute runtimes. It extracts the existing `knoxx/integrations/colab-mcp` 0.4.0 implementation without changing its wire protocol or command names. The implementation initially existed as uncommitted Knoxx source; the running gateway’s three Python modules were byte-matched to this extraction on 2026-10-28. Deployment and authenticated access remain separate from this source snapshot.

This package is a Python **transport boundary** around Google's official
[`googlecolab/colab-mcp`](https://github.com/googlecolab/colab-mcp), pinned to
`b9ab3899e0f1fa493390b1fd6d54aa2e464ecdf1`. It contains no Knoxx backend domain
logic; Knoxx capability/role/connection declarations remain EDN and connection
resolution is ClojureScript.

```
ChatGPT private plugin → HTTPS Knoxx ingress → authenticated gateway (droplet)
                                                 ↓ private SSH reverse relay
local Knoxx agent → authenticated browser bridge (Stealth) ↔ official Colab UI
```

Google's server is local/browser-oriented and dynamically discovers tools.
Four stable wrapper tools avoid relying on clients reacting to tool-list-change
notifications: `colab_status`, `colab_connect`, `colab_tools`, `colab_call`.
Tool discovery and calls are serialized into the selected notebook. Every call
rechecks the actual upstream catalog. Errors stay MCP errors across the relay.

The Colab browser WebSocket stays on `127.0.0.1` and uses Google's origin and
connection-token checks. Its short-lived connection URL is written mode 0600
under `~/.local/state/knoxx-colab/browser-url`; it never enters MCP responses.
The notebook bridge does not read Google credentials. Private bridge HTTP hops
use a service key; public ChatGPT access requires Axxium identity.
This is a private single-operator service, not a shared multi-user Colab pool.

## Development

Python 3.13+, `uv sync --frozen --extra test`, then `uv run pytest -q`.
Dependencies are frozen in `uv.lock`. The upstream's FastMCP 2.14.5 dependency
is retained. Existing Authlib transitive deprecation warnings are reported by
the suite; they are not Knoxx compiler warnings.

Run the local bridge with `COLAB_MCP_TOKEN_FILE=/private/bridge-token
uv run --frozen knoxx-colab-mcp bridge`. The default HTTP listener is loopback
port 8023. The installed Stealth service uses its Docker host bridge address
so the local Knoxx container can connect. Keep that address private.

Run `uv run --frozen knoxx-colab-mcp open-browser` in the graphical session,
then sign in and accept Colab's MCP connection. Keep the tab open.
The installed shortcut is `knoxx-colab-open-browser`.

Run the droplet gateway with `COLAB_BRIDGE_URL` (the private relay),
`COLAB_BRIDGE_TOKEN_FILE`, `COLAB_OAUTH_BASE_URL` and `COLAB_OAUTH_STATE_DIR` set.
Use `knoxx-colab-mcp gateway --port 8024`. No tool accepts an upstream URL.
The gateway returns an actionable error when the bridge or browser is unavailable.
An ambiguous execution timeout must never trigger an automatic mutation retry.

## Knoxx and ChatGPT

Knoxx resources: `contracts/mcp_servers/colab.edn`, `:cap/colab`,
`:role/colab-notebook-operator`, and `colab_notebook_worker`. Give the intended
actor the role. Set `COLAB_MCP_TOKEN` in the backend environment. The connection
adapter refuses missing named credentials. The skill is bundled in
`plugin/skills/colab-notebooks` and installed into the active Knoxx SDK's skill
search path; source presence alone does not establish live hydration.

The private plugin package uses Agent Plugins 1.0 and OAuth with dynamic client
registration. Version 0.4.0 removes the operator-key login and legacy public
bearer fallback. Axxium is the identity authority. Until its shared issuer is
qualified and a confidential Colab client is registered, public authorization
returns HTTP 503 with an Axxium pending page and all public tokens are rejected.
Private local Knoxx bridge connections continue independently.

The prepared relying-party adapter uses FastMCP's OAuth proxy with S256 PKCE,
encrypted persistent token storage and live Axxium grant introspection on every
request. `COLAB_AXXIUM_CLIENT_FILE` names a private regular 0600 JSON file with
`issuer`, `client_id`, `client_secret`, and `allowed_subjects`. The issuer is
fixed to `https://axxium.promethean.rest/oidc`, the registered client is
`knoxx-colab`, and subjects must be explicitly verified stable Axxium actor IDs.
The registered callback is `https://knoxx.promethean.rest/colab/auth/callback`.
The client secret is a service credential, never a human login credential.
No credential file is provisioned until the central identity release is qualified.
Wrong configuration stops startup; absence denies access without a substitute.
Run only one gateway process against an OAuth state directory. Its token-family
lock serializes authorization-code exchanges, refreshes and revocations within
that process; it is not a distributed lock for multiple workers or replicas.
If Axxium revocation is unavailable, the affected family is denied locally and
the caller receives HTTP 503. Retry the same revocation request: the encrypted
pending state survives a gateway restart and is cleared only after Axxium
confirms both upstream credentials have been revoked. Other families are not
revoked. A central logout or disabled actor also denies the next MCP request.
The ChatGPT redirect remains enabled by default. To admit another harness,
optionally add `allowed_client_redirect_uris` to the private client JSON as a
list of exact callback URLs, for example `["http://127.0.0.1:9876/callback"]`.
Each extra URL must use HTTPS or an explicitly configured HTTP `localhost` or
`127.0.0.1` address and port. Wildcards, queries, fragments, percent escapes,
credentials and more than 16 extra callbacks are rejected. A client may authorize
only with a callback it registered and which remains on the operator's current
allowlist. Removing a callback disables its registered clients after the gateway
restarts, but does not itself revoke previously issued tokens; revoke the grant
through Axxium when needed. Harnesses choosing ephemeral loopback ports need a
fixed callback configuration compatible with this exact policy.
Run `.venv/bin/python verify_oauth.py` for read-only identity preflight; exit 2
means the shared issuer is pending. It never submits credentials or approves
human consent. Do not publicly share this single-operator package.

Deployment definitions and rollback instructions belong to the Services repo:
`services/digitalocean/services/colab-mcp/`. The feature verification guide is
`knoxx/docs/verification/colab-mcp.md`.

Live Colab execution requires a human-approved browser connection and an actual
runtime. Fixture transport tests, HTTP health, plugin creation, and capability
validation each prove only their respective layer.

## CLI/API compute (0.2.0)

The same public gateway also exposes six `colab_compute_*` tools through a
separate Stealth process, using official `google-colab-cli==0.7.5`. Install it
with `uv tool install google-colab-cli==0.7.5 --python 3.13`. The process verifies
that version at startup. Google login uses the isolated directory
`~/.local/share/promethean/services/colab-mcp-stealth/gcloud`; use the prepared
`knoxx-colab-cli-login` shortcut. Existing global ADC credentials are not changed
and no Google credential is copied to the droplet or plugin.

`colab_compute_usage` and `colab_compute_sessions` are read-only. Start a bounded
job with `colab_compute_start`, poll `colab_compute_job`, and cancel or retry
owned cleanup with `colab_compute_cancel`. CPU is the default; accelerator enums
are checked before the CLI sees them. Only one job can run at a time, execution
is bounded to 900 seconds plus provisioning/transport overhead, and output is
capped at 10 MiB (the MCP poll returns the last 64 KiB). Source, output and status
are retained in private service state. Arbitrary file export is not exposed yet.

The adapter uses `colab new`, `colab exec`, then `colab stop` and server-session
readback. The official `colab run` convenience command swallows teardown errors,
so a zero code-execution exit status is not treated as cleanup proof. An uncertain
cleanup blocks further allocation. A failed or timed-out job is not retried.
A separate typed capability and `colab-compute` skill are installed in local Knoxx.

Colab compute units are distinct from Google Cloud credits and Google AI product
credits. Read the actual balance and current official subscription terms; never
infer the account's grant from a plan name or from a browser connection.

## Staging identity probe

For an isolated Axxium staging authorization test, the `staging` profile pins
`https://staging.axxium.promethean.rest/oidc` and a local-only gateway at
`http://127.0.0.1:18761`. It requires its own `knoxx-colab-staging` client,
secret, actor allowlist, and exact downstream client callbacks in a private
0600 config. Its state is placed in the `staging` subdirectory of the supplied
private OAuth state directory. Configure the staging Axxium client to accept
exactly `http://127.0.0.1:18761/auth/callback` with loopback explicitly enabled.
The localhost address must be reachable by the browser completing authorization.

Set `COLAB_AUTH_PROFILE=staging`, `COLAB_OAUTH_BASE_URL=http://127.0.0.1:18761`,
`COLAB_OAUTH_STATE_DIR` and `COLAB_AXXIUM_CLIENT_FILE`, then run
`knoxx-colab-mcp gateway --host 127.0.0.1 --port 18761`. The profile refuses
other bind addresses and ports, uses a non-executing fixture backend, and never
reads bridge or compute credentials. It proves only the identity and MCP transport
path; it cannot access an actual Colab notebook or allocate compute. Production
remains the default and retains its existing pinned issuer and callback.
