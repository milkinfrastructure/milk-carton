# Milk Gateway

Milk Gateway is a small OpenAI-compatible proxy that turns real application traffic into bounded, auditable evaluation work.

For the hosted product, an application changes only its official OpenAI SDK base URL and API key. The gateway forwards the request to the configured upstream model, returns the normal response, and captures only traffic explicitly admitted for evaluation. It does not run a model locally and it does not require a GPU.

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

The customer supplies the `base_url` and one `dt_live_...` key. Milk Infrastructure owns the hosted eval configuration, object stores, upstream/provider credentials, and route policy. Self-hosters run the same gateway and supply their own JSON configuration and environment secrets.

The code is MIT licensed, but this source repository and the production OCI image remain private while the first hosted release is qualified and reviewed. This is not yet a public open-source release.

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
- one strict eval identity, its isolated object namespace, and its hard decision/call limits;
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

The local path can use three private directories. Production uses three separately credentialed R2 buckets.

## Bounded evaluation loop

`tick --once` reads captured traffic and the current eval configuration. Its required `eval_id` is the 64-character lowercase campaign identity admitted with the canonical eval document. That ID is embedded in every durable scope and object key. It acquires one object-store lease, repairs incomplete work, and creates no more than one new launch record. Repeated ticks stop creating teacher work when `teacher.max_decisions` is reached for that eval. Existing reconciliation and teardown continue even after the limit.

The object store is authoritative. A scheduler, Exo, or a local shell may invoke the command, but none of them can manufacture a claim or authorize provider spend.

```sh
target/release/dragontales-gateway --config "$PWD/dragontales.json" tick --once
target/release/dragontales-gateway --config "$PWD/dragontales.json" status
```

## Production deployment

Production deploys an admitted `linux/amd64` image to a Cloudflare Worker and Container. The non-bootstrap deploy includes the reviewed `DRAGONTALES_CONFIG_JSON` in the same versioned Worker deploy, checks one healthy instance on that exact config digest, and runs the official OpenAI SDK smoke. A failed update rolls the Worker version and config binding back together.

The CPU-only gateway release is 12.02 MiB compressed and contains no shell, package manager, Python, Node, GPU runtime, or model weights.

Release evidence is digest-addressed and content-free. Prompts, model outputs, API keys, and raw build logs are not release artifacts.

See [`crates/dragontales-gateway/README.md`](crates/dragontales-gateway/README.md) for the full command and authority contract.

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
cargo +1.95.0 test --locked --offline --workspace
cargo +1.95.0 clippy --locked --offline --workspace --all-targets -- -D warnings
python3 tools/test_deploy_private_gateway.py
```
