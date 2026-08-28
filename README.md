# Milk Gateway

Private Milk Infrastructure repository for the blue path in the directly inspected architecture whiteboard: official SDK, OpenAI-compatible Rust gateway, sampled traffic, and object-store authority.

Milk has exactly two private repositories:

- [`milkinfrastructure/milk-gateway`](https://github.com/milkinfrastructure/milk-gateway): request data plane, immutable claims/results/routes, GPU launch outbox, and worker contracts.
- [`milkinfrastructure/milk-harness`](https://github.com/milkinfrastructure/milk-harness): self-iteration harness, one-shot jobs executor, and purple/teal GPU worker source.

It owns:

- public request proxying and bounded traffic capture;
- three separately credentialed Local/R2 stores: capture, control, and routes;
- immutable claims, results, routes, and content-addressed GPU launch outbox records;
- exact worker contracts and conformance fixtures;
- signed canary, rollback, and retirement rules;
- the private `milk-gateway` OCI image and Cloudflare deployment.

`serve` opens capture read-write and routes read-only; it cannot open control. `tick --once` opens capture and control read-write; it cannot open routes. `status` opens all three read-only. The credential prefixes are `MILK_CAPTURE_STORE_*`, `MILK_CONTROL_STORE_*`, and `MILK_ROUTE_STORE_*`.

Every teacher-run, student train-merge, three-branch fanout, or verified winner deployment launch first creates a bounded typed `dragontales.gpu-launch-intent.v1`, then its immutable claim, `dragontales.gpu-launch-outbox.v1`, and hashed `dragontales.gpu-launch-frontier.v1` pointer. Pending intents reserve the same scope-wide 18-launch allowance as frontier pointers. A successor tick materializes the exact canonical chain from an intent even after teacher-provider, student-reservation, or winner-authority rotation; an expired or already-terminal intent preserves the claim and outbox without an active pointer. The intent is compare-and-swap terminalized only after that chain is verified, then removed.

Each student claim binds two immutable digests: `student_train_runtime_image_reference` runs only train/merge, while `student_branch_runtime_image_reference` runs all three evaluation branches and the admitted winner server. The fixed 7,200 GPU-second authorization still covers the complete train-plus-three-branch job. Train evidence is Prime-RL/CUDA 12.8 only; branch evidence is the pinned vLLM/CUDA 12.9 FP8 runtime and exactly one candidate kernel. A train image can never satisfy a branch launch or route authority, and vice versa.

Every tick first holds the scope's fixed `dragontales.tick-lease.v1` control-store record. Conditional create or compare-and-swap binds ownership to that process's writer ID; a five-minute mutation ceiling and two bounded lease operations remain below the ten-minute lease TTL. An overlapping tick returns `{"action":"hold"}`. Terminal and expired pointers are reconciled scope-wide before new work, making the 18-launch cap hard across gateway tick processes. Workflow concurrency is defense in depth only: scheduled, manual, and local execution must all use `tick --once` and its store lease.

The release boundary is a separate one-shot `milk-harness` jobs process with read-only control-store access. It consumes only `frontier/gpu-launch/` pointers, not intent records, and must verify the frontier, outbox hash, canonical claim, expiry, and admitted image before its own durable evidence and budget reservation can authorize a provider create. A winner claim binds the literal Baseten-primary, Modal-fallback policy and one total wall/cost ceiling; jobs may select Modal only after Baseten preflight fails and must durably freeze one provider before any create intent. The gateway accepts only a strictly verified winner deployment result embedding the canonical `milk.winner-provider-acceptance.v1` object; it recomputes the claim and outbox bindings before `prepare-route` derives the fixed 1%/15-minute canary. The gateway never holds provider credentials; jobs must not run `tick`, write gateway control state, or share a process with the gateway.

The winner run ID is provider-neutral and binds the claim, outbox, operation, budget bounds, and private image-evidence digests. Baseten serving identity is team-scoped; a training-project identity is not accepted.

A winner admission does not free its GPU launch slot. Publishing the signed zero route creates one durable provider-teardown authorization and control frontier; expiry creates the same authority when no route rollback arrived. The route-triggered authority embeds the exact verified canary and zero receipts, so jobs needs no route-store credential. Jobs tears the provider down and writes content-free evidence in its private store; a gateway-owned scheduler pass ingests the exact evidence-addressed result. Until verified provider billing is part of the contract, the teardown result must conservatively account for the full accepted reservation. Only that verified zero result removes the teardown frontier and the original GPU launch pointer. Jobs never writes control or routes.

This repository does not own GPU worker implementations, autonomous planning, image release credentials, provider credentials, or a standing manager service.

Release policy:

- repository visibility is private;
- images are built from this local checkout for `linux/amd64`;
- the canonical image is private `ghcr.io/milkinfrastructure/milk-gateway@sha256:...`;
- the exact local image is copied to Cloudflare's private registry for deployment, never rebuilt there;
- no tag is admitted as runtime authority; every claim and route binds an immutable digest.

Traffic authentication is a bounded startup list of API-key SHA-256 to stable cohort-ID mappings. Official SDK requests use the normal bearer API key; clients cannot supply a routing-unit header. Candidate transport failure, 408, 429, or any 5xx opens a fuse held by that verified route runtime. The failed request is never replayed, and later requests use baseline until a different signed route runtime is loaded.

The first availability target is 99.5% monthly gateway-owned request success and recovery within five minutes after a single container restart. Cloudflare intentionally runs one instance. Production qualification requires a controlled staging restart followed by the bounded authenticated official SDK acceptance; no speculative failover service is added before evidence shows that target is insufficient.

Build and deploy receipts contain no command output. They bind content-free log hashes to immutable references inside the private release or deploy evidence set. Deployment additionally runs a pinned official OpenAI Node SDK smoke from an explicit owner-only credential file and rolls back automatically if that smoke fails.

Baseten winner admission uses the transient gateway-owned `tools/manage-candidate-credential.py serve-baseten` process. Its required `--socket-path` must be absolute, absent, and directly inside an existing non-symlink directory owned by the helper's effective UID with exact mode 0700. The workflow mounts that socket into the jobs container at its fixed `/run/milk-candidate-key.sock` path under the same UID. The helper accepts one canonical install, recovery-verify, or authorized-remove request, returns one hash-only acknowledgement, removes the exact socket inode, and exits. The candidate key exists only in socket/process memory and the Cloudflare secret binding. `DRAGONTALES_CONTAINER_ADMIN_KEY` is a permanent Worker-only secret supplied to the helper on a separate pipe or socket descriptor; it is never forwarded to the container. `DRAGONTALES_CANDIDATE_API_KEY` is helper-managed and optional outside an admitted winner interval. Wrangler is pinned to 4.126.0, and its dedicated API token may manage only this Worker's secrets and read the exact Worker/container identity. Neither key may enter arguments, environment variables, files, stdout, deployment evidence, logs, or R2.

Qualification status on 2026-08-28: the private repository is published and Actions remain disabled. A prior gateway revision has a verified private image admission, but this split train/branch contract revision has not been rebuilt or deployed. Offline gateway, provider-handoff, and teardown tests pass; no hosted end-to-end proof has run. This repository is not production-qualified.

See the [crate operator notes](crates/dragontales-gateway/README.md).
