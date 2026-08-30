# Milk Carton crate

This is the OpenAI-compatible Chat Completions and Responses data plane and object-authority binary for [`milkinfrastructure/milk-carton`](https://github.com/milkinfrastructure/milk-carton). An official SDK changes only its base URL and API key, then sends the `milk_live_...` key through the standard `Authorization: Bearer` header; no SDK wrapper or custom authentication header is required. Deterministic capture and route sampling use an HMAC of the complete session root when available: Responses `conversation`, `X-Milk-Session-Id` on either endpoint, or an explicitly uncertain standalone-request fallback. A Responses request containing only `previous_response_id` retains an opaque HMAC of that linkage but is not content-capture eligible because a stateless gateway cannot prove its session root. Raw session identifiers are never stored and the Milk session header is never forwarded. The hosted operator owns configuration, storage, upstream and provider credentials, and signed route activation.

## Commands and authority

- `serve`: proxy exact request/response bytes and asynchronously persist selected completed interactions. It has capture read-write and routes read-only access, never control access.
- `tick --once`: derive at most one safe control-plane action and create or reconcile immutable claims, results, frontiers, and GPU launch outbox records. It has capture/control read-write access, never route access or provider credentials.
- `status`: return bounded content-free capture, expiry, and route state with capture/routes read-only. It requires neither teacher configuration nor control-store credentials.

The config has exactly three logical store roles: `stores.capture`, `stores.control`, and `stores.routes`. Each is either an owner-only local directory or a strict `{"type":"s3","endpoint":"https://...","region":"...","bucket":"..."}` binding, and all three may name the same physical bucket. The `MILK_CAPTURE_STORE_*`, `MILK_CONTROL_STORE_*`, and `MILK_ROUTE_STORE_*` credentials remain explicit, and each command opens only its declared roles. S3 endpoints must be HTTPS origins. Read-write startup qualifies create-if-absent, ETag compare-and-swap, immediate read, ordered prefix listing, and deletion; read-only startup qualifies listing. Cloudflare R2 is one supported deployment, not a distinct storage type.

Before creating a teacher-run, student train-merge, three-branch fanout, or verified winner deployment claim, the gateway conditionally creates a strict typed `milk.gpu-launch-intent.v1`. The intent contains the canonical claim and `milk.gpu-launch-outbox.v1`, reserves a slot in the same scope-wide allowance as `frontier/gpu-launch/` pointers, and is compare-and-swap terminalized only after the claim, outbox, and required pointer are verified. A successor tick repairs pending intents independently of the current teacher binding, student reservation, or winner startup authority. Expired or already-terminal work keeps its permanent claim and outbox but no active pointer; the bounded intent record is then removed.

Teacher config names the two student authorities directly: `student_train_runtime_image_reference` is exclusive to train/merge, and `student_branch_runtime_image_reference` is exclusive to the three evaluation branches and winner serving. Both are digest-only references and both enter the student job ID. Train launch outboxes use only the train image; fanout and winner outboxes use only the branch image. The one 7,200 GPU-second total cap remains 1,800 seconds for train plus 1,800 seconds for each of three branches. Stage-tagged GPU evidence prevents the native Prime-RL/CUDA 12.8 train image from claiming the vLLM/CUDA 12.9 FP8 branch runtime.

One non-nil operator-assigned `scope_id` is authoritative. Capture, control, and route objects live under `milk/v1/scopes/<scope_id>/`; eval revisions are data within the scope, not traffic namespaces. `teacher.max_decisions` is required and must be between 1 and 4,096. It limits permanent teacher decision reservations within that scope, including skipped, failed, expired, and prior-provider work. At the limit, ticks stop creating teacher claims but continue repair, reconciliation, terminalization, and teardown.

Before any control mutation, `tick --once` conditionally acquires the scope's fixed `milk.tick-lease.v1` record with its writer ID. The tick mutation has a five-minute ceiling, lease I/O is bounded to 30 seconds per operation, and the lease expires after ten minutes; release is compare-and-swap, never deletion. A contender returns the exact hold action. This control-store lease, not workflow scheduling, serializes scheduled, manual, local, and overlapping tick processes.

The union of pending intents and active pointers is capped at 18 launches per scope, with intent storage itself capped at 18 objects. Every tick verifies and retires terminal or expired pointers across the full scope before admitting work, including work from prior teacher bindings or student reservations. Claims and outbox records are permanent; retirement removes only the frontier pointer. Crash recovery materializes the exact canonical chain without replaying provider work.

Provider dispatch is outside this repository. Milk Man invokes a fixed one-shot jobs process that reads the Carton control store without write authority, consumes only `frontier/gpu-launch/` pointers, verifies the full frontier -> outbox -> claim -> admitted-image chain, records its own immutable acceptance and budget reservation, then makes at most the authorized Baseten request. Winner deployment claims bind `milk.winner-deployment-authority.v3` with the exact `{"only":"baseten"}` provider policy, immutable student branch image, route prerequisites, expiry, and one wall/cost ceiling. The job must embed the exact canonical Baseten-only `milk.winner-provider-acceptance.v1` object in the deployment result. Intent records are Carton-internal recovery state. Jobs must not invoke this binary's `tick` command or share its control-store writer credential.

The gateway recomputes the winner run ID from the canonical claim, outbox, winner operation, budget bounds, and admitted image-evidence digests. Baseten serving identity is its verified team name; training project identity is rejected.

`prepare-route` consumes the stored, strictly verified winner deployment result and derives the fixed 100-basis-point, 900-second canary. It cannot accept an operator-supplied winner receipt, percentage, or duration. `prepare-route --rollback` publishes a zero-percent rollback only from the verified live-route lineage.

`prepare-route-proposal --proposal <json> --manifest <output>` consumes key-sorted compact `milk.unsigned-route-proposal.v2` JSON plus one trailing LF from the deterministic harness. Before emitting canonical `milk.route.v1` for external Ed25519 signing, Carton re-reads the content-addressed source, summary, readiness, eval, accepted validation, qualified candidate score, proposal, and current proposal pointer; it rejects any scope, profile, series, code, config, digest, candidate, budget, or live-predecessor mismatch. Generic proposals route Chat Completions and streaming only; Responses stays on baseline until separately qualified. `--zero` requires the verified live operator candidate for the exact same proposal and emits a baseline-only successor with no candidate or route-secret digest. `publish-route` verifies the signature and activates either route through the existing object-store CAS pointer; the harness never receives the signing key.

Generic operator routes require only `signing_public_key_hex`, `signing_key_id`, `allow_private_candidate_http`, and `candidate_max_in_flight` in `route`. The legacy winner authorization fields are optional and are required only by the student winner route commands.

Winner admission keeps its GPU launch pointer active. A signed zero publication creates a `milk.provider-teardown-authorization.v1` and bounded control frontier containing the exact canary and zero receipts; service expiry creates the same authority without a route receipt. The jobs process reads that authority, proves Baseten is at zero compute, archives private logs, and settles the shared budget. Until verified billing is part of the contract, settlement must account for the full accepted reservation. A gateway-owned ingest command accepts only the exact evidence-addressed result and then removes both active pointers. Only the scoped admitted-winner key enters the gateway; Baseten management and training credentials do not. The jobs process never receives control- or route-write access.

## Local start

Build with the pinned Rust toolchain:

```sh
cargo +1.95.0 build --locked --release --package milk-carton
```

Copy `deploy/milk-carton-config.example.json`, replace the traffic and outcome key hashes, assign one non-nil `scope_id`, and set one or three owner-only Local roots. `traffic_keys` contains 1 to 64 strict `{api_key_sha256, capture_allowed}` mappings. Set `capture_allowed: true` only for inputs admitted to that scope. Deployment, canary, and ordinary synthetic test keys use `false`. Generate one request key without printing it:

```sh
install -d -m 0700 "$PWD/.milk-carton-secrets"
deploy/milk-carton-key.sh /usr/bin/openssl /usr/bin/uuidgen \
  "$PWD/.milk-carton-secrets/request.key"
```

Start the loopback gateway:

```sh
export MILK_CARTON_OPENAI_API_KEY='...'
export MILK_CAPTURE_SAMPLING_KEY_HEX="$(openssl rand -hex 32)"
export MILK_CAPTURE_SAMPLING_KEY_VERSION='local-v1'
target/release/milk-carton --config "$PWD/milk-carton.json" serve
```

Keep the sampling key stable for a version so the same session root remains in the same capture and route cohort.

Official Python SDK example:

```python
from openai import OpenAI

client = OpenAI(
    api_key=open(
        ".milk-carton-secrets/request.key", encoding="utf-8"
    ).read().strip(),
    base_url="http://127.0.0.1:8080/v1",
)

response = client.chat.completions.create(
    model="zai-org/GLM-5.3-Flash",
    messages=[{"role": "user", "content": "Return the next safe migration step."}],
)
```

The gateway hashes the client bearer key and compares it to every bounded startup mapping with constant-time digest comparisons. It removes client authorization before injecting `MILK_CARTON_OPENAI_API_KEY`; it never persists either key or a raw session identifier. `X-Milk-Capture-Intent: selected` reports deterministic intent, not completion of the asynchronous object write.

## Availability and restart gate

The explicit first production target is 99.5% monthly gateway-owned request availability with recovery within five minutes after a single container restart. Upstream model-provider errors are measured separately. The deployment contract uses one Cloudflare `lite` Container instance; there is no unproven failover layer. The checked-in hosted example bounds four concurrent requests plus one outcome to 76 MiB of active bodies, admits at most 80 MiB, and reserves a separate 48 MiB capture queue within the 256 MiB instance.

A release is not production-qualified until a staging run forces that one instance to restart, observes exactly one replacement instance on the admitted image, and the authenticated official OpenAI Node SDK smoke succeeds within five minutes. The deploy acceptance always runs that bounded SDK smoke and automatically rolls back on failure. The controlled restart itself remains a manual release gate until repeated evidence demonstrates a need for automated failover.

The deploy command requires a new owner-only evidence directory, the reviewed canonical gateway config, and an absolute owner-only credential file containing canonical one-line JSON plus LF: `{"api_key":"milk_live_...","cohort_id":"deployment-smoke-v1","model":"..."}`. The cohort identifier names the smoke run and is not gateway configuration. Before any provider mutation, the key hash must identify exactly one `capture_allowed:false` traffic-key entry. For a non-bootstrap deploy, the tool passes only `MILK_CARTON_CONFIG_JSON` through Wrangler's private secrets file so code, image, and config-key mappings enter one atomic, versioned Worker deploy; omitted secrets remain bound to that version. Acceptance requires the running gateway health digest to equal the supplied config bytes before the official SDK smoke. Failure rolls back the prior Worker version and binding together, then requires live health to report the exact pre-deploy config digest.

This is deliberately a full single-tenant deploy, not a live config plane: config or customer-key hash changes restart the sole Container on the admitted image. Bootstrap passes the ten required initial bindings, including the stable capture-sampling key and its version, through an owner-only scratch file on the first strict Worker deploy. The file is unlinked immediately after deploy and on every failure path. Evidence contains immutable hashes and receipts, never config, credential, prompt, or response bytes.

Run offline checks:

```sh
RUST_MIN_STACK=16777216 cargo +1.95.0 test --locked --offline --workspace
cargo +1.95.0 clippy --locked --offline --workspace --all-targets -- -D warnings
```

A hosted gateway and controlled production-infrastructure mechanics runs have proved a signed canary, bounded fallback, signed-zero baseline restoration, and candidate credential removal. Generated traffic does not qualify a customer tenant or real-traffic eval, and this repository does not claim a production-qualified trained candidate or verified provider teardown. Source and image publication remain separate from production qualification.
