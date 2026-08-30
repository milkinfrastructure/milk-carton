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

During the single-tenant pilot, Milk issues, rotates, and revokes `milk_live_...` keys through an atomic config deployment. There is no customer key-management API yet. Milk is the product name; `milk-carton`, `MILK_CARTON_*`, and `milk_live_...` remain the stable binary, environment, and wire identifiers.

The gateway records only completed traffic admitted by the operator's capture policy. It loads one strict startup configuration, reports its SHA-256, and polls signed, revisioned route state while retaining the last verified route after a failed refresh.

Milk Carton is MIT-licensed. The hosted cloud proof has not run, so there is no production-qualified hosted release or live customer endpoint yet.

## Product boundary

- `serve`: authenticates, proxies, captures admitted completed requests, and follows verified route state.
- `tick --once`: converts captured traffic and eval configuration into at most one safe control-plane action.
- `status`: reports bounded counts without returning prompts, responses, or credentials.
- Immutable claims, results, launch records, and signed route state in object storage.

The maintained products are this Carton and [`milk-man`](https://github.com/milkinfrastructure/milk-man). Object storage is their durable memory, not a third service. Milk Man invokes fixed one-shot jobs; it cannot publish routes or choose credentials, provider settings, or spend. Carton receives only the scoped key needed to call an admitted winner, while provider management credentials remain outside the data plane.

## Self-hosted configuration

Hosted customers do not manage this configuration. Self-hosters supply one strict JSON document through `--config /path/to/config.json` or `MILK_CARTON_CONFIG_JSON`. Start from [`deploy/milk-carton-config.example.json`](deploy/milk-carton-config.example.json).

The important settings are:

- the upstream OpenAI-compatible URL and model;
- accepted request-key hashes and capture authority;
- `capture_allowed` for each request key;
- capture, control, and route object-store roles, which may share one physical bucket;
- one operator-assigned `scope_id`, its `milk/v1/scopes/<scope_id>/` object namespace, and its hard decision/call limits;
- immutable teacher, student, and image identities.

Secrets stay in environment variables:

| Process | Required access |
| --- | --- |
| `serve` | upstream API key, capture read/write, routes read-only |
| `tick --once` | capture read/write, control read/write |
| `status` | capture, control, and routes read-only |

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

`tick --once` reads captured traffic and the current eval configuration. Durable data is isolated under `milk/v1/scopes/<scope_id>/`; eval revisions do not create traffic namespaces. The command acquires one object-store lease, repairs incomplete work, and creates no more than one new launch record. Repeated ticks stop creating teacher work when `teacher.max_decisions` is reached for the scope. Existing reconciliation and teardown continue even after the limit.

The object store is authoritative. A scheduler, Exo, or a local shell may invoke the command, but none of them can manufacture a claim or authorize provider spend.

```sh
target/release/milk-carton --config "$PWD/milk-carton.json" tick --once
target/release/milk-carton --config "$PWD/milk-carton.json" status
```

## Production deployment

The intended hosted deployment runs an admitted `linux/amd64` image in a Cloudflare Worker and Container. A non-bootstrap deployment uploads code and the reviewed `MILK_CARTON_CONFIG_JSON` in one atomic, versioned Worker deploy, checks one healthy instance on that exact config digest, and runs the official OpenAI SDK smoke. A failed update restores the prior Worker version and config binding together, then verifies that live health reports the exact pre-deploy config digest.

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

The release contract keeps the gateway image CPU-only, with no shell, package manager, Python, Node, GPU runtime, model weights, or local GPU dependency.

Release evidence is digest-addressed and content-free. Prompts, model outputs, API keys, and raw build logs are not release artifacts.

See [`crates/milk-carton/README.md`](crates/milk-carton/README.md) for the full command and authority contract.

### Cloud-mechanics proof

The first end-to-end cloud check uses generated SDK traffic and a dedicated eval configured with `capture_basis_points=10000`, `max_decisions=320`, `max_calls=20`, `max_gpu_seconds=3600`, and `max_parallel_runs=1`. It runs on cloud `linux/amd64` capacity; no local GPU participates. The Baseten-only 20-call job must pass the exact admitted teacher profile before any later paid create is authorized. Its separately confirmed all-in envelope is `$175`: `$160` of GPU reservations plus `$15` for the external services used by the proof. The provider ledger's `$1,000` ceiling and `$850` launch cutoff remain additional GPU controls.

This check proves the deployment, capture, Baseten execution, training, short canary, baseline route fallback, signed-zero, teardown, and zero-compute mechanics. Because its traffic is generated, it cannot production-qualify the release or admit the resulting candidate for real application traffic.

Run the pinned official-SDK driver with an owner-only credential for the dedicated capture-enabled mechanics key:

```sh
node tools/openai-production-smoke.mjs \
  "$MILK_CARTON_API_BASE_URL" \
  /absolute/path/to/mechanics-credential.json \
  <expected-gateway-config-sha256> \
  --generated-mechanics
```

The fixed proof model is `zai-org/GLM-5.3-Flash`. The contract SHA-256 is `d9fb8b4daa1754acdbadc3b4028601434b79bf9c2096343c7a790df838bbcc66`.

| Step | SDK calls | Baseline | Candidate | Completion-token cap |
| --- | ---: | ---: | ---: | ---: |
| Deployment baseline | 1 | 1 | 0 | 256 |
| Generated mechanics | 320 | 320 | 0 | 256 |
| Candidate | 1 | 0 | 1 | 256 |
| Saturation fallback | 2 | 1 | 1 | 3,840 |
| **Total** | **324** | **322** | **2** |  |

Every v2 receipt carries that contract hash plus its exact step, model, request count, route split, and token cap. The stateless SDK driver enforces each invocation. Milk Man's fixed job owns the durable one-use mechanics intent and content-free receipt, so an ambiguous run is not replayed.

The verified deployment's `current.json` is v2 and binds the canonical deployment-baseline receipt SHA-256 and the fixed proof-contract SHA-256. Deployment finalization re-reads both records before sealing the evidence manifest.

The generated mechanics driver contributes exactly 320 of those baseline requests with one request in flight, a 4.25-second minimum launch interval, a 60-second timeout per request, and no SDK retries. That interval stays below Baseten's 15-request-per-minute Basic-account rate limit. It uses GLM's supported `low` reasoning effort so the bounded response reaches final content. Its preflight and postflight health checks have 30-second timeouts. It verifies the deployed config digest and capture health before and after the run, plus the exact SDK body bytes, assigned partition, and baseline route revision for every request. Its canonical receipt retains only aggregate hashes, counts, timing, and success state; durable R2 readback remains a separate required gate.

After this mechanics proof reaches the production gate, hosted GLM is the next explicit typed teacher profile. It uses the same eval, capture, and route contracts; it does not add a generic provider layer.

## Production qualification

The hosted release is production-qualified only after one cloud run proves the complete chain:

1. An official SDK request returns normally and persists its completed trace.
2. Real captured traffic produces at least 251 retained teacher results: 50 TRAIN, 73 DEV, and 128 CALIBRATION. Partitioning or skipped traffic can require more requests. Generated traffic does not count.
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
