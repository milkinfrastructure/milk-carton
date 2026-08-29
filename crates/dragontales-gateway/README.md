# Milk gateway crate

This is the OpenAI Chat Completions data plane and object-authority binary for [`milkinfrastructure/milk-gateway`](https://github.com/milkinfrastructure/milk-gateway). An official SDK changes only its base URL and API key; no SDK wrapper or routing header is required. Startup maps each accepted API-key SHA-256 to one bounded stable cohort ID. Authentication returns that configured cohort, and signed canary sampling uses it. A caller cannot choose or override its routing unit.

## Commands and authority

- `serve`: proxy exact request/response bytes and asynchronously persist selected completed interactions. It has capture read-write and routes read-only access, never control access.
- `tick --once`: derive at most one safe control-plane action and create or reconcile immutable claims, results, frontiers, and GPU launch outbox records. It has capture/control read-write access, never route access or provider credentials.
- `status`: return bounded content-free state with all three stores read-only. It cannot mutate provider or route state.

The config has exactly three stores: `stores.capture`, `stores.control`, and `stores.routes`. R2 credentials use `MILK_CAPTURE_STORE_*`, `MILK_CONTROL_STORE_*`, and `MILK_ROUTE_STORE_*`; do not share one credential across partitions.

Before creating a teacher-run, student train-merge, three-branch fanout, or verified winner deployment claim, the gateway conditionally creates a strict typed `dragontales.gpu-launch-intent.v1`. The intent contains the canonical claim and `dragontales.gpu-launch-outbox.v1`, reserves a slot in the same scope-wide allowance as `frontier/gpu-launch/` pointers, and is compare-and-swap terminalized only after the claim, outbox, and required pointer are verified. A successor tick repairs pending intents independently of the current teacher binding, student reservation, or winner startup authority. Expired or already-terminal work keeps its permanent claim and outbox but no active pointer; the bounded intent record is then removed.

Teacher config names the two student authorities directly: `student_train_runtime_image_reference` is exclusive to train/merge, and `student_branch_runtime_image_reference` is exclusive to the three evaluation branches and winner serving. Both are digest-only references and both enter the student job ID. Train launch outboxes use only the train image; fanout and winner outboxes use only the branch image. The one 7,200 GPU-second total cap remains 1,800 seconds for train plus 1,800 seconds for each of three branches. Stage-tagged GPU evidence prevents the native Prime-RL/CUDA 12.8 train image from claiming the vLLM/CUDA 12.9 FP8 branch runtime.

Before any control mutation, `tick --once` conditionally acquires the scope's fixed `dragontales.tick-lease.v1` record with its writer ID. The tick mutation has a five-minute ceiling, lease I/O is bounded to 30 seconds per operation, and the lease expires after ten minutes; release is compare-and-swap, never deletion. A contender returns the exact hold action. This control-store lease, not workflow scheduling, serializes scheduled, manual, local, and overlapping tick processes.

The union of pending intents and active pointers is capped at 18 launches per scope, with intent storage itself capped at 18 objects. Every tick verifies and retires terminal or expired pointers across the full scope before admitting work, including work from prior teacher bindings or student reservations. Claims and outbox records are permanent; retirement removes only the frontier pointer. Crash recovery materializes the exact canonical chain without replaying provider work.

Provider dispatch is outside this repository. The release contract is a one-shot `milk-harness` jobs process that reads the gateway control store without write authority, consumes only `frontier/gpu-launch/` pointers, verifies the full frontier -> outbox -> claim -> admitted-image chain, records its own immutable acceptance and budget reservation, then makes at most the authorized provider request. Winner deployment claims bind the literal Baseten-primary, Modal-fallback policy, immutable student branch image, route prerequisites, expiry, and one wall/cost ceiling for either provider. Jobs may select Modal only after Baseten preflight fails, must durably freeze one provider before any provider create intent, and must embed the exact canonical `milk.winner-provider-acceptance.v1` object in the deployment result; no cross-provider retry is authorized after create intent. Intent records are gateway-private recovery state. Jobs must not invoke this binary's `tick` command or share its control-store writer credential.

The gateway recomputes the provider-neutral winner run ID from the canonical claim, outbox, winner operation, budget bounds, and private image-evidence digests. Provider selection is deliberately excluded from that ID so Baseten-to-Modal fallback cannot create a second run. Baseten serving identity is its verified team name; training project identity is rejected.

`prepare-route` consumes the stored, strictly verified winner deployment result and derives the fixed 100-basis-point, 900-second canary. It cannot accept an operator-supplied winner receipt, percentage, or duration. `prepare-route --rollback` publishes a zero-percent rollback only from the verified live-route lineage.

Winner admission keeps its GPU launch pointer active. A signed zero publication creates a `dragontales.provider-teardown-authorization.v1` and bounded control frontier containing the exact canary and zero receipts; service expiry creates the same authority without a route receipt. Jobs reads that authority, proves provider zero, archives private logs, and settles the shared budget. Until verified provider billing is part of the contract, settlement must account for the full accepted reservation. A gateway-owned ingest command accepts only the exact evidence-addressed result and then removes both active pointers. Provider credentials never enter the gateway, and jobs never receives control- or route-write access.

For a Modal fallback winner, `prepare-modal-candidate-credential` derives the canonical install, verification, or removal request from the verified winner and current gateway anchor. `ingest-modal-candidate-credential-ack` accepts the helper's canonical acknowledgement and stores it create-only under the winner job. Existing requests without an acknowledgement recover through verification instead of replaying installation. Provider teardown is rejected until the exact `absent` acknowledgement is current in the scope lineage; that release ID becomes the next install anchor. Baseten winners return `ready` without creating Modal state. Neither command accepts a provider credential or makes a provider call.

## Local start

Build with the pinned Rust toolchain:

```sh
cargo +1.95.0 build --locked --release --package dragontales-gateway
```

Copy `deploy/dragontales-config.example.json`, replace the traffic and outcome key hashes, choose a stable non-secret traffic cohort ID, and set three distinct private Local roots. `traffic_keys` contains 1 to 64 strict `{api_key_sha256, capture_allowed, cohort_id}` mappings. Set `capture_allowed: true` only for genuine user traffic with capture rights; production smoke and synthetic test keys must use `false`. Generate one request key without printing it:

```sh
install -d -m 0700 "$PWD/.dragontales-secrets"
deploy/dragontales-key.sh /usr/bin/openssl /usr/bin/uuidgen \
  "$PWD/.dragontales-secrets/request.key"
```

Start the loopback gateway:

```sh
export DRAGONTALES_OPENAI_API_KEY='...'
target/release/dragontales-gateway --config "$PWD/dragontales.json" serve
```

Official Python SDK example:

```python
from openai import OpenAI

client = OpenAI(
    api_key=open(
        ".dragontales-secrets/request.key", encoding="utf-8"
    ).read().strip(),
    base_url="http://127.0.0.1:8080/v1",
)

response = client.chat.completions.create(
    model="gpt-5.4",
    messages=[{"role": "user", "content": "Return the next safe migration step."}],
)
```

The gateway hashes the client bearer key and compares it to every bounded startup mapping with constant-time digest comparisons. It removes client authorization before injecting `DRAGONTALES_OPENAI_API_KEY`; it never persists either key or the cohort ID. `X-Dragontales-Capture-Intent: selected` reports deterministic intent, not completion of the asynchronous object write.

## Availability and restart gate

The explicit first production target is 99.5% monthly gateway-owned request availability with recovery within five minutes after a single container restart. Upstream model-provider errors are measured separately. The deployment intentionally runs one Cloudflare Container instance; there is no unproven failover layer.

A release is not production-qualified until a staging run forces that one instance to restart, observes exactly one replacement instance on the admitted image, and the authenticated official OpenAI Node SDK smoke succeeds within five minutes. The deploy acceptance always runs that bounded SDK smoke and automatically rolls back on failure. The controlled restart itself remains a manual release gate until repeated evidence demonstrates a need for automated failover.

The deploy command requires a new private evidence directory and an absolute owner-only credential file containing canonical one-line JSON plus LF: `{"api_key":"dt_live_...","cohort_id":"deployment-smoke-v1","model":"..."}`. Before any provider mutation, the key hash and cohort must identify exactly one `capture_allowed:false` traffic-key entry. Bootstrap proves this against the exact canonical config installed from `DRAGONTALES_CONFIG_JSON`; a later regular deploy proves it only against the reviewed canonical config file supplied to that command and does not claim Cloudflare secret-value equality. It retains only content-free hashes and immutable private ops-log references; prompt, response, and credential bytes are never written to evidence.

Run offline checks:

```sh
cargo +1.95.0 test --locked --offline --workspace
cargo +1.95.0 clippy --locked --offline --workspace --all-targets -- -D warnings
```

No final private image, hosted deployment, paid GPU proof, canary, rollback, or verified zero-GPU teardown has occurred in the Milk repositories. Standalone Baseten winner and Modal mutation commands are not release entrypoints.
