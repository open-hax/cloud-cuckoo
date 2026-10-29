# Production Axxium binding for Cloud Cuckoo

This is an activation candidate, not evidence that production login or a
ChatGPT tool call has succeeded. It describes how to bind the previously verified
existing human Axxium actor to the existing private Colab bridges. The public
example actor ID `actor_00000000-0000-4000-8000-000000000001` is inert; select
the real, verified actor only in private configuration. Axxium remains the sole
identity authority; its root session and grant must be current on every MCP call.

Two distinct callback hops matter:

| Hop | Exact callback |
| --- | --- |
| Axxium sends its authorization code to Cloud Cuckoo | `https://knoxx.promethean.rest/colab/auth/callback` |
| Cloud Cuckoo sends its authorization code to ChatGPT | `https://chatgpt.com/connector_platform_oauth_redirect` |

The latter is compiled into the production gateway allowlist and was observed
in the user's ChatGPT connection flow. Extra harness callbacks require explicit
review and exact allowlisting; no extras are needed for this connection.

## Private client configuration

[`production-axxium-client.json`](../examples/production-axxium-client.json)
is the `knoxx-colab` entry to add to Axxium's existing private `clients` array.
[`production-gateway-client.json`](../examples/production-gateway-client.json)
is the gateway's complete private client configuration. Both contain an
intentionally invalid `UNSET` secret. Never install these examples directly.

At activation, generate one new high-entropy service-to-service secret for this
client, insert that same value into the two private configurations, and verify
them without printing the value. This is not a human login credential. Use a
different secret from every other Axxium client, existing Google/bridge tokens,
and the Axxium signing and cookie keys. The authority's closed config contract
requires a unique client ID and unique client secret. The Axxium application
accepts a regular, nonsymlink private authority file with mode exactly 0600;
the gateway accepts a private regular file readable by its nonroot user. Parent
directories and the gateway OAuth state directory must remain private. Stage
and atomically install the two files within the relevant Services/receiver lock;
preserve other registered clients and current persistent signing material.

The running Colab Compose file expects the gateway config at
`/srv/open-hax/state/colab-mcp/axxium-client.json`, mounted read-only as
`/run/colab/axxium-client.json`. Its OAuth state is persisted separately under
`/srv/open-hax/state/colab-mcp/oauth`, writable by UID 1000. Existing encrypted
proxy state depends on the client secret: changing that secret invalidates the
gateway's stored credentials and requires a fresh ChatGPT connection.

Before enabling the gateway, use the existing Axxium deployment's actual
private authority directory, exact receiver lock and live user/group mapping;
do not assume the staging paths apply to production. Ensure the configured
issuer is exactly `https://axxium.promethean.rest/oidc`, public TLS discovery
works, S256 and `client_secret_post` are advertised, the real active actor ID
matches the allowlist, and the new confidential client is registered with the
exact gateway callback. Enable refresh for this client only as described in the
example: Axxium limits renewal by the current root session and grants a maximum
of 24 hours. Source code and staging tests do not establish the production
issuer or human login.

## Gateway deployment and verification

Deploy the merged Cloud Cuckoo source containing PR #3's resource-forwarding
fix and PR #4's revocation-retry and authorization-code serialization fixes,
at or descended from `6925402ebe8dbf8c22f9287fa2be1acbb86e7a24`. PR #4 must
be merged and the resulting release qualified before production activation. The
previous 0.4.0 image forwards the downstream MCP `resource` to Axxium and failed
the staging authorization flow. Record the built image digest and prove the
running image's source revision; a reused `candidate` tag is not provenance.
The Services deployment owner is responsible for ingress reconciliation and
activation. Gateway startup must discover the qualified authority before it
advertises working OAuth; missing config must deny access.

The production profile connects the two private backends through the existing
SSH relay:

| Backend | Droplet relay destination | Stealth listener |
| --- | --- | --- |
| Browser notebook | `http://127.0.0.1:18023/mcp` | `172.17.0.1:8023` |
| CLI compute | `http://127.0.0.1:18025/mcp` | `172.17.0.1:8025` |

Both use the existing private bridge service token. The gateway has no Google
credentials; Google authentication stays in the existing Stealth services.
Verify anonymous and incorrect-token refusal, then authenticate as the existing
human actor. The authenticated gateway must advertise ten tools and a read-only
`colab_status` plus `colab_compute_usage` call must reach their respective real
backends. A disconnected notebook is an explicit condition, not a successful
notebook execution. Do not allocate a compute runtime merely to test identity.

Confirm that a different active Axxium actor cannot use the gateway, the
resource and client boundaries reject mismatches, and Axxium logout or grant
revocation causes the previously issued MCP credential to fail. Verify a real
ChatGPT-origin tool call after the user's existing ChatGPT connection completes
the Axxium consent flow. The staging fixture, plugin upload, browser display,
private bridge calls and an unauthenticated HTTP challenge are not substitutes
for that host-origin receipt. Never request the retired gateway key from a human.

Run the relevant Cloud Cuckoo package tests and the deployment owner's actual
image/ingress checks. This worktree's binding examples are deliberately
inert; neither they nor their tests create credentials or change a live service.
