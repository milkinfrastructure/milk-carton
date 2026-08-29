# Milk Gateway

Milk Gateway is a small OpenAI-compatible proxy that turns real application traffic into bounded, auditable evaluation work.

For the hosted product, an application changes only its official OpenAI SDK base URL and API key. The SDK sends that key through the standard `Authorization: Bearer` header. The gateway forwards the request to the configured upstream model, returns the normal response, and captures only traffic explicitly admitted for evaluation. It does not run a model locally and it does not require a GPU.

```python
from openai import OpenAI

client = OpenAI(
    base_url="https://api.example.com/v1",
    api_key="dt_live_...",
)

response = client.chat.completions.create(
    model="gpt-5.4",
    messages=[{"role": "user", "content": "Hello"}],
)
```

The hosted surface is deliberately narrow: the customer supplies the `base_url` and one `dt_live_...` key, which the SDK sends as `Authorization: Bearer dt_live_...`. Milk Infrastructure owns the hosted eval configuration, object stores, upstream and provider credentials, and route policy. Self-hosters run the same gateway and supply their own JSON configuration and environment secrets.

Milk Gateway is MIT-licensed. Source publication does not imply a live hosted endpoint or a production-qualified release; those require the cloud proof below.

## What it owns

- `serve`: authenticates, proxies, and asynchronously records selected completed requests.
- `tick --once`: converts captured traffic into at most one safe control-plane action.
- `status`: reports bounded counts without returning prompts, responses, or credentials.
- Immutable claims, results, launch records, and signed route state in object storage.

The gateway never holds Modal or Baseten credentials. Provider execution lives in [`milk-harness`](https://github.com/milkinfrastructure/milk-harness), which watches captured traffic and stops new eval generation at the configured per-eval limit.

## Self-hosted configuration

Hosted customers do not manage this configuration. Self-hosters supply one strict JSON document through `--config /path/to/config.json` or `DRAGONTALES_CONFIG_JSON`. Start from [`deploy/dragontales-config.example.json`](deploy/dragontales-config.example.json).

The important settings are:

- the upstream OpenAI-compatible URL and model;
- accepted request-key hashes and stable traffic cohorts;
- `capture_allowed` for each request key;
- capture, control, and route object stores;
- one stable 64-character lowercase `eval_id`, its `dt/v3`-isolated object namespace, and its hard decision/call limits;
- immutable teacher, student, and image identities.

Secrets stay in environment variables:

| Process | Required access |
| --- | --- |
| `serve` | upstream API key, capture read/write, routes read-only |
| `tick --once` | capture read/write, control read/write |
| `status` | capture, control, and routes read-only |

R2 credentials use `MILK_CAPTURE_STORE_*`, `MILK_CONTROL_STORE_*`, and `MILK_ROUTE_STORE_*`. Do not reuse one credential across those roles.

## Run locally

Build the CPU-only Rust binary:

```sh
cargo +1.95.0 build --locked --release --package dragontales-gateway
```

Create a request key without printing it:

```sh
install -d -m 0700 .dragontales-secrets
deploy/dragontales-key.sh /usr/bin/openssl /usr/bin/uuidgen \
  "$PWD/.dragontales-secrets/request.key"
```

Add the key's SHA-256 to your config, set the upstream provider key, then run:

```sh
export DRAGONTALES_OPENAI_API_KEY='...'
target/release/dragontales-gateway --config "$PWD/dragontales.json" serve
```

The local path can use three owner-only directories. The hosted configuration uses three separately credentialed R2 buckets.

## Bounded evaluation loop

`tick --once` reads captured traffic and the current eval configuration. Its required `eval_id` is a stable 64-character lowercase campaign identity. For a Milk-managed campaign, `gateway_config.eval_id` must equal `manifest.campaign_id`. The SHA-256 of the canonical outer `milk.eval.v1` document is separate and is the exact one-use paid-confirmation and pass-receipt value. Durable data is isolated under `dt/v3/<eval_id>/<tenant>/<project>/<environment>/<workload>/...`. The command acquires one object-store lease, repairs incomplete work, and creates no more than one new launch record. Repeated ticks stop creating teacher work when `teacher.max_decisions` is reached for that eval. Existing reconciliation and teardown continue even after the limit.

The object store is authoritative. A scheduler, Exo, or a local shell may invoke the command, but none of them can manufacture a claim or authorize provider spend.

```sh
target/release/dragontales-gateway --config "$PWD/dragontales.json" tick --once
target/release/dragontales-gateway --config "$PWD/dragontales.json" status
```

## Production deployment

The intended hosted deployment runs an admitted `linux/amd64` image in a Cloudflare Worker and Container. A non-bootstrap deployment uploads code and the reviewed `DRAGONTALES_CONFIG_JSON` in one atomic, versioned Worker deploy, checks one healthy instance on that exact config digest, and runs the official OpenAI SDK smoke. A failed update restores the prior Worker version and config binding together, then verifies that live health reports the exact pre-deploy config digest.

The release contract keeps the gateway image CPU-only, with no shell, package manager, Python, Node, GPU runtime, model weights, or local GPU dependency.

Release evidence is digest-addressed and content-free. Prompts, model outputs, API keys, and raw build logs are not release artifacts.

See [`crates/dragontales-gateway/README.md`](crates/dragontales-gateway/README.md) for the full command and authority contract.

### Cloud-mechanics proof

The first end-to-end cloud check uses generated SDK traffic and a dedicated eval configured with `capture_basis_points=10000`, `max_decisions=320`, `max_calls=10`, `max_gpu_seconds=3600`, and `max_parallel_runs=1`. It runs on cloud `linux/amd64` capacity; no local GPU participates. Milk stops scheduling new paid work at $850 of cumulative spend, and $1,000 is the hard ceiling.

This check proves the deployment, capture, provider, training, short canary, fallback, signed-zero, teardown, and zero-compute mechanics. Because its traffic is generated, it cannot production-qualify the release or admit the resulting candidate for real application traffic.

## Production qualification

The hosted release is production-qualified only after one cloud run proves the complete chain:

1. An official SDK request returns normally and persists its completed trace.
2. Real captured traffic produces at least 251 retained teacher results: 50 TRAIN, 73 DEV, and 128 CALIBRATION. Partitioning or skipped traffic can require more requests. Generated traffic does not count.
3. One student is trained and merged, then BF16, dynamic FP8, and static FP8 branches are evaluated on the same ordered DEV set.
4. The deterministic winner passes authenticated canary and baseline-fallback checks.
5. A signed zero route becomes active and Baseten and Modal are both observed at zero compute.

A one-request paid teacher run qualifies only the teacher/provider path, not the product.

## Development

```sh
RUST_MIN_STACK=16777216 cargo +1.95.0 test --locked --offline --workspace
cargo +1.95.0 clippy --locked --offline --workspace --all-targets -- -D warnings
python3 tools/test_deploy_private_gateway.py
```
