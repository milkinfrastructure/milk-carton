# Milk Carton

Milk Carton is a small, CPU-only OpenAI-compatible proxy. A hosted customer changes only the official OpenAI SDK base URL and API key. No SDK wrapper, custom authentication header, routing header, local model, or local GPU is required.

```python
from openai import OpenAI

client = OpenAI(
    base_url="https://api.example.com/v1",
    api_key="milk_live_...",
)

response = client.chat.completions.create(
    model="zai-org/GLM-5.3-Flash",
    messages=[{"role": "user", "content": "Hello"}],
)
```

The public contract is deliberately narrow:

- The customer supplies one OpenAI-compatible endpoint and one `milk_live_...` key. The official SDK uses Chat Completions or Responses through the standard `Authorization: Bearer` header and receives the normal response.
- The hosted operator owns the gateway and eval configuration, one S3-compatible bucket with process-scoped logical roles, upstream and Baseten credentials, capture policy, and route policy. The hosted deployment uses Cloudflare R2; self-hosters may use another qualified S3-compatible service.

During the pilot, Milk issues, rotates, and revokes `milk_live_...` keys through an atomic config deployment. Baseline-only capture may map keys to distinct scopes; routed and control operation remains single-scope. There is no customer key-management API yet. Milk is the product name; `milk-carton`, `MILK_CARTON_*`, and `milk_live_...` remain the stable binary, environment, and wire identifiers.

The gateway records only completed traffic admitted by the operator's capture policy. It loads one strict startup configuration, reports its SHA-256, and polls signed, revisioned route state while retaining the last verified route after a failed refresh.

Milk Carton is MIT-licensed. The hosted endpoint at `https://carton.milkinfrastructure.com/v1` and a generated-traffic mechanics proof have run. Neither is a production-qualified customer release.

## Product boundary

- `serve`: authenticates, proxies, captures admitted completed requests, and follows verified route state.
- `tick --once`: retains the legacy Carton control loop while its fixed jobs move to Milk Man.
- `status`: reports bounded capture, expiry, and route state without teacher configuration or control-store access.
- Immutable claims, results, launch records, and signed route state in object storage.

The maintained products are this Carton and [`milk-man`](https://github.com/milkinfrastructure/milk-man). Object storage is their durable memory, not a third service. Milk Man invokes fixed one-shot jobs; it cannot publish routes or choose credentials, provider settings, or spend. Carton receives only the scoped key needed to call an admitted winner, while provider management credentials remain outside the data plane.

## Self-hosted configuration

Hosted customers do not manage this configuration. Self-hosters supply one strict JSON document through `--config /path/to/config.json` or `MILK_CARTON_CONFIG_JSON`. Start from [`deploy/milk-carton-config.example.json`](deploy/milk-carton-config.example.json).

The important settings are:

- the upstream OpenAI-compatible URL and model;
- request-key records containing the key UUID, exact key hash, stable scope UUID, and capture authority;
- optional `revocation` metadata, whose presence disables that key without moving its scope history;
- capture, control, and route object-store roles, which may share one physical bucket;
- an operator-assigned scope per request key and its `milk/v1/scopes/<scope_id>/` object namespace; routed and control deployments use one scope;
- immutable teacher, student, and image identities.

Secrets stay in environment variables:

| Process | Required access |
| --- | --- |
| `serve` | upstream API key, capture read/write, routes read-only |
| `tick --once` | capture read/write, control read/write |
| `status` | capture and routes read-only |

All three store configs may name the same S3-compatible bucket. The `MILK_CAPTURE_STORE_*`, `MILK_CONTROL_STORE_*`, and `MILK_ROUTE_STORE_*` bindings remain explicit, and each command opens only the logical roles in the table above. Each remote role uses the same strict config form:

```json
{
  "type": "s3",
  "endpoint": "https://<account-id>.r2.cloudflarestorage.com",
  "region": "auto",
  "bucket": "milk-production"
}
```

Set `<ROLE>_ACCESS_KEY_ID`, `<ROLE>_SECRET_ACCESS_KEY`, and optionally `<ROLE>_SESSION_TOKEN` for each opened role. The endpoint must be an HTTPS origin; HTTP, embedded credentials, and endpoint paths are rejected. Remote startup qualifies create-if-absent, ETag compare-and-swap, immediate read, ordered prefix listing, and deletion before serving or mutating data. A backend that fails those semantics is unsupported even if it exposes an S3 API.

## Run locally

Build the CPU-only Rust binary:

```sh
cargo +1.95.0 build --locked --release --package milk-carton
```

Create a request key without printing it:

```sh
install -d -m 0700 .milk-carton-secrets
deploy/milk-carton-key.sh /usr/bin/openssl /usr/bin/uuidgen \
  "$PWD/.milk-carton-secrets/request.key"
```

Add the key's SHA-256 to your config, set the upstream provider key, then run:

```sh
export MILK_CARTON_OPENAI_API_KEY='...'
export MILK_CAPTURE_SAMPLING_KEY_HEX="$(openssl rand -hex 32)"
export MILK_CAPTURE_SAMPLING_KEY_VERSION='local-v1'
target/release/milk-carton --config "$PWD/milk-carton.json" serve
```

Keep the sampling key stable for a version so session selection remains deterministic. The local path can use one or three owner-only directories. The hosted configuration uses one Cloudflare R2 bucket through the three S3-compatible logical access roles.

## Bounded evaluation loop

`tick --once` reads captured traffic and the current eval configuration. Durable data is isolated under `milk/v1/scopes/<scope_id>/`; eval revisions do not create traffic namespaces. The command acquires one object-store lease, repairs incomplete work, and creates no more than one new launch record. Repeated ticks drain all admitted work; per-job deadlines and resource bounds terminate failed work without imposing a scope-wide quota.

The object store is authoritative. A scheduler, Exo, or a local shell may invoke the command, but none of them can manufacture a claim or authorize provider spend.

```sh
target/release/milk-carton --config "$PWD/milk-carton.json" tick --once
target/release/milk-carton --config "$PWD/milk-carton.json" status
```

## Production deployment

The intended hosted deployment runs an admitted `linux/amd64` image in a Cloudflare Worker and Container. A non-bootstrap deployment uploads code and the reviewed `MILK_CARTON_CONFIG_JSON` in one atomic, versioned Worker deploy, checks one healthy instance on that exact config digest, and runs the official OpenAI SDK smoke. The operator must also supply the exact config bytes already live before the update. A failed update first restores that config and the retained prior Container image, then rolls back the exact prior Worker version and verifies all three states. Before mutation, the tool stages owner-read-only rollback config and secret files and binds them to exact digests. Wrangler resolves the Worker module from the checkout, so recovery ignores Git and unrelated repository drift but refuses if the exact `worker.js` bytes changed after preflight.

Build and verify one private image from a clean published checkout:

```sh
tools/build-private-gateway.sh \
  --registry-token-file /absolute/owner-only/ghcr-token \
  --cache-dir /absolute/owner-only/gateway-buildkit-cache \
  /absolute/new/gateway-release-evidence
```

The cache is optional and affects build speed only; the image remains fixed to `linux/amd64`, and evidence records the cache method without its path or content. Use `--registry-token-stdin` instead of `--registry-token-file` to stream the credential. The scripts do not require GitHub CLI and never place the credential in arguments, logs, or evidence. The private image build and deploy scripts are Milk-operator release tools with fixed Milk registry and Cloudflare contracts. Forks can build the Rust binary locally, but custom hosted deployment is not turnkey.

Bootstrap the first application, or update an existing application, with the same guarded deploy command:

```sh
tools/deploy-private-gateway.sh \
  --registry-token-file /absolute/owner-only/ghcr-token \
  --bootstrap \
  /absolute/gateway-release-evidence \
  /absolute/new/gateway-deploy-evidence \
  /absolute/gateway-credential.json \
  /absolute/bootstrap-secrets.json \
  https://your-domain.example/v1

tools/deploy-private-gateway.sh \
  --registry-token-file /absolute/owner-only/ghcr-token \
  --previous-gateway-config-file /absolute/previous-gateway-config.json \
  /absolute/gateway-release-evidence \
  <cloudflare-application-id> \
  /absolute/new/gateway-deploy-evidence \
  /absolute/gateway-credential.json \
  /absolute/gateway-config.json \
  https://your-domain.example/v1
```

The final argument is the operator-owned public API base URL. It must be a lowercase HTTPS domain ending in `/v1`; the deploy tool writes only that hostname into the temporary Wrangler configuration. The repository does not claim or hard-code a production DNS name.

The bootstrap secret document includes `MILK_CAPTURE_SAMPLING_KEY_HEX` as 64 lowercase hexadecimal characters and a bounded `MILK_CAPTURE_SAMPLING_KEY_VERSION`. Both are passed into the Container on every start.

[`milk-man`](https://github.com/milkinfrastructure/milk-man) invokes the fixed reconciliation job that continues from captured traffic through summary statistics, readiness, eval generation, and an unsigned route proposal. Route signing and publication remain explicit operator actions outside the agent.

The release contract keeps the gateway image CPU-only, with no shell, package manager, Python, Node, GPU runtime, model weights, or local GPU dependency. The verifier rejects a runnable image whose compressed layers total more than 20 MiB.

Release evidence is digest-addressed and content-free. Prompts, model outputs, API keys, and raw build logs are not release artifacts.

See [`crates/milk-carton/README.md`](crates/milk-carton/README.md) for the full command and authority contract.

### Generated-traffic mechanics evidence

The hosted proof sent 320 generated official-SDK requests through the baseline route and persisted 320 traces in isolated scope `f7f88ff0-5947-440c-a661-e4e35f1d04e0`. Milk Man then produced deterministic summary statistics, classification, an eval, and an unsigned route proposal, with one paid teacher inference. It did not train or deploy a candidate, activate a signed route, prove fallback, or verify provider teardown.

Generated traffic proves mechanics only. Carton rejects the known scope `f7f88ff0-5947-440c-a661-e4e35f1d04e0` before legacy tick or route preparation, and rejects that scope or exact eval SHA-256 `26b09c53937d80b07bc49f42beeca8562eaa4b303023d13033777da472c04499` in operator-route preparation and publication. Provider dispatch must independently enforce the same denylist.

The separate production-path workload leaves that proof unchanged. It checks an
invalid key, both official SDK endpoints, then sends 100 deterministic sessions
with four workers. Request starts default to 4.1 seconds apart for Baseten's
15-RPM unverified Basic limit. After the workspace reports the 120-RPM verified
limit, set `MILK_PRODUCTION_PATH_REQUEST_INTERVAL_MS=520`. Pass the fresh
mechanics tenant only through an owner-only gateway credential file:

```sh
node tools/openai-production-path-workload.mjs \
  https://your-domain.example/v1 \
  /absolute/fresh-mechanics-gateway-credential.json
```

Its canonical receipt contains only pinned SDK identity, counts, SHA-256
digests, trace IDs, and status. It never contains the tenant scope, API key,
prompts, or responses.

## Production qualification

The hosted release is production-qualified only after one cloud run proves the complete chain:

1. An official SDK request returns normally and persists its completed trace.
2. Real qualification observes at least 750 independent sessions and passes the declared capture, parse, duplicate, abstention, and represented-class gates. Generated mechanics traffic does not count.
3. One student is trained and merged, then BF16, dynamic FP8, and static FP8 branches are evaluated on the same ordered DEV set.
4. The deterministic winner passes authenticated canary and baseline-fallback checks.
5. A signed zero route becomes active and Baseten is observed at zero compute.

A passing 20-call teacher job qualifies only that teacher/provider path, not the product.

## Development

```sh
RUST_MIN_STACK=16777216 cargo +1.95.0 test --locked --offline --workspace
cargo +1.95.0 clippy --locked --offline --workspace --all-targets -- -D warnings
python3 tools/test_deploy_private_gateway.py
```
