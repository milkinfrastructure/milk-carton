import assert from "node:assert/strict";

import {
  PRODUCTION_PROOF,
  ROUTE_PROOF,
  candidateRequest,
  generatedMechanicsPlan,
  runBaselineSmoke,
  runCandidateSmoke,
  runGeneratedMechanics,
  runSaturationFallbackSmoke,
  runZeroRouteSmoke,
  saturationRequest,
} from "./openai-production-smoke.mjs";

const digest = (byte) => byte.repeat(64);
const credential = {
  api_key: "milk_live_00000000-0000-4000-8000-000000000001_test_secret_123456789",
  cohort_id: "paid-proof-selected-cohort-v1",
  model: "zai-org/GLM-5.3-Flash",
  reasoning_effort: "high",
};

assert.deepEqual(PRODUCTION_PROOF, {
  baseline_requests: 322,
  candidate_requests: 2,
  generated_concurrency: 1,
  generated_health_timeout_ms: 30_000,
  generated_minimum_request_interval_ms: 4_250,
  generated_mechanics_requests: 320,
  generated_reasoning_effort: "low",
  generated_request_timeout_ms: 60_000,
  max_sdk_requests: 324,
  model: "zai-org/GLM-5.3-Flash",
  saturation_max_completion_tokens: 3_840,
  short_max_completion_tokens: 256,
});
const productionProofSha256 =
  "d9fb8b4daa1754acdbadc3b4028601434b79bf9c2096343c7a790df838bbcc66";
assert.deepEqual(ROUTE_PROOF, {
  candidate_session_search_limit: 256,
  fallback_launch_delay_ms: 10,
  model: PRODUCTION_PROOF.model,
  saturation_max_completion_tokens: 64,
  short_max_completion_tokens: 256,
});
const routeProofSha256 =
  "1e6ad1bf01b7c6b0bfefeaa81e391677092ccdec7af82f6a0b5e41aa71634987";
const revision = digest("1");
const data = {
  choices: [{ finish_reason: "stop", message: { content: "OK", role: "assistant" } }],
};

function client(routeRevision = revision, routeTarget = "candidate", includeReasoning = true) {
  return {
    chat: {
      completions: {
        create(request, options) {
          const selection = request.max_completion_tokens === 1;
          const expected = {
            max_completion_tokens: selection ? 1 : 256,
            messages: [{ role: "user", content: "Reply with only OK." }],
            model: credential.model,
          };
          if (includeReasoning) expected.reasoning_effort = "high";
          assert.deepEqual(request, expected);
          if (includeReasoning) {
            assert.match(
              options?.headers?.["x-milk-session-id"] ?? "",
              /^milk-route-proof-[0-9a-f]{16}-[0-9]{3}$/,
            );
          }
          const index = Number(
            options?.headers?.["x-milk-session-id"]?.slice(-3),
          );
          const target = selection && routeTarget === "candidate"
            ? (index === 2 ? "candidate" : "openai")
            : routeTarget;
          return {
            async withResponse() {
              return {
                data,
                response: {
                  headers: new Headers({
                    "x-milk-artifact-sha256": digest("2"),
                    "x-milk-candidate-sha256": digest("3"),
                    "x-milk-deployment-sha256": digest("4"),
                    "x-milk-route-revision": routeRevision,
                    "x-milk-route-target": target,
                  }),
                  status: 200,
                },
              };
            },
          };
        },
      },
    },
  };
}

assert.deepEqual(candidateRequest({ ...credential, reasoning_effort: null }), {
  max_completion_tokens: 256,
  messages: [{ role: "user", content: "Reply with only OK." }],
  model: credential.model,
});
assert.throws(() => candidateRequest({ ...credential, model: "another-model" }));
const receipt = await runCandidateSmoke(
  client(),
  new URL("https://carton.example/v1"),
  credential,
  revision,
);
assert.equal(receipt.schema_version, "milk.official-openai-sdk-route-smoke.v3");
assert.equal(receipt.proof_step, "candidate");
assert.equal(receipt.model, PRODUCTION_PROOF.model);
assert.equal(receipt.sdk_request_count, 4);
assert.equal(receipt.baseline_request_count, 2);
assert.equal(receipt.candidate_request_count, 2);
assert.equal(receipt.candidate_session_index, 2);
assert.equal(receipt.selection_probe_count, 3);
assert.equal(receipt.sticky_candidate_request_count, 2);
assert.equal(receipt.max_completion_tokens, 256);
assert.equal(receipt.proof_contract_sha256, routeProofSha256);
assert.equal(receipt.route_revision, revision);
assert.equal(receipt.route_target, "candidate");
assert.equal(receipt.candidate_sha256, digest("3"));
assert.equal(receipt.artifact_sha256, digest("2"));
assert.equal(receipt.deployment_sha256, digest("4"));
assert.match(receipt.traffic_key_sha256, /^[0-9a-f]{64}$/);
assert.match(receipt.traffic_cohort_sha256, /^[0-9a-f]{64}$/);
assert.match(receipt.routing_session_sha256, /^[0-9a-f]{64}$/);

const baseline = await runBaselineSmoke(
  client(revision, "candidate", false),
  new URL("https://carton.example/v1"),
  { api_key: credential.api_key, cohort_id: credential.cohort_id, model: credential.model },
);
assert.equal(baseline.schema_version, "milk.official-openai-sdk-smoke.v2");
assert.equal(baseline.proof_step, "deployment_baseline");
assert.equal(baseline.model, PRODUCTION_PROOF.model);
assert.equal(baseline.sdk_request_count, 1);
assert.equal(baseline.baseline_request_count, 1);
assert.equal(baseline.candidate_request_count, 0);
assert.equal(baseline.max_completion_tokens, 256);
assert.equal(baseline.proof_contract_sha256, productionProofSha256);
assert.equal(baseline.authenticated, true);
assert.equal(baseline.content_retained, false);
assert.match(baseline.traffic_key_sha256, /^[0-9a-f]{64}$/);
assert.match(baseline.traffic_cohort_sha256, /^[0-9a-f]{64}$/);
await assert.rejects(
  runBaselineSmoke(
    null,
    new URL("https://carton.example/v1"),
    { ...credential, model: "another-model" },
  ),
);

await assert.rejects(
  runCandidateSmoke(
    client(digest("5")),
    new URL("https://carton.example/v1"),
    credential,
    revision,
  ),
);
await assert.rejects(
  runCandidateSmoke(
    client(revision, "openai"),
    new URL("https://carton.example/v1"),
    credential,
    revision,
  ),
);

function zeroRouteClient({
  identityHeader = null,
  routeRevision = revision,
  routeTarget = "openai",
  status = 200,
} = {}) {
  return {
    chat: {
      completions: {
        create(request, options) {
          assert.deepEqual(request, candidateRequest(credential));
          assert.equal(options, undefined);
          const headers = new Headers({
            "x-milk-route-revision": routeRevision,
            "x-milk-route-target": routeTarget,
          });
          if (identityHeader !== null) headers.set(identityHeader, digest("2"));
          return {
            async withResponse() {
              return { data, response: { headers, status } };
            },
          };
        },
      },
    },
  };
}

const zeroRoute = await runZeroRouteSmoke(
  zeroRouteClient(),
  new URL("https://carton.example/v1"),
  credential,
  revision,
);
assert.equal(zeroRoute.schema_version, "milk.official-openai-sdk-zero-route-smoke.v1");
assert.equal(zeroRoute.proof_step, "zero_route");
assert.equal(zeroRoute.model, PRODUCTION_PROOF.model);
assert.equal(zeroRoute.sdk_request_count, 1);
assert.equal(zeroRoute.baseline_request_count, 1);
assert.equal(zeroRoute.candidate_request_count, 0);
assert.equal(zeroRoute.max_completion_tokens, 256);
assert.equal(zeroRoute.proof_contract_sha256, routeProofSha256);
assert.equal(zeroRoute.route_revision, revision);
assert.equal(zeroRoute.route_target, "openai");
assert.equal(zeroRoute.baseline_only, true);
assert.equal(zeroRoute.candidate_identity_headers_absent, true);
assert.equal(zeroRoute.authenticated, true);
assert.equal(zeroRoute.content_retained, false);
assert.match(zeroRoute.response_sha256, /^[0-9a-f]{64}$/);
for (const identityHeader of [
  "x-milk-artifact-sha256",
  "x-milk-candidate-sha256",
  "x-milk-deployment-sha256",
]) {
  await assert.rejects(
    runZeroRouteSmoke(
      zeroRouteClient({ identityHeader }),
      new URL("https://carton.example/v1"),
      credential,
      revision,
    ),
  );
}
for (const invalidClient of [
  zeroRouteClient({ routeRevision: digest("5") }),
  zeroRouteClient({ routeTarget: "candidate" }),
  zeroRouteClient({ status: 503 }),
]) {
  await assert.rejects(
    runZeroRouteSmoke(
      invalidClient,
      new URL("https://carton.example/v1"),
      credential,
      revision,
    ),
  );
}

assert.deepEqual(saturationRequest(credential), {
  max_completion_tokens: 64,
  messages: [
    {
      role: "user",
      content: "Write OK on 32 separate lines. Do not summarize or stop early.",
    },
  ],
  model: credential.model,
  reasoning_effort: "high",
  stream: true,
});
assert.throws(() => saturationRequest({ ...credential, model: "another-model" }));
let saturationCall = 0;
const aborted = [];
const saturationClient = {
  chat: {
    completions: {
      create(request, options) {
        assert.deepEqual(request, saturationRequest(credential));
        assert.match(
          options?.headers?.["x-milk-session-id"] ?? "",
          /^milk-route-proof-[0-9a-f]{16}-002$/,
        );
        const call = saturationCall++;
        assert.ok(call < 2);
        return {
          async withResponse() {
            return {
              data: {
                controller: {
                  abort() {
                    aborted.push(call);
                  },
                },
              },
              response: {
                headers: new Headers({
                  "x-milk-artifact-sha256": digest("2"),
                  "x-milk-candidate-sha256": digest("3"),
                  "x-milk-deployment-sha256": digest("4"),
                  "x-milk-route-revision": revision,
                  "x-milk-route-target": call === 0 ? "candidate" : "openai",
                }),
                status: 200,
              },
            };
          },
        };
      },
    },
  },
};
const saturation = await runSaturationFallbackSmoke(
  saturationClient,
  new URL("https://carton.example/v1"),
  credential,
  revision,
  receipt.candidate_session_index,
);
assert.equal(saturation.schema_version, "milk.official-openai-sdk-saturation-fallback-smoke.v3");
assert.equal(saturation.proof_step, "saturation_fallback");
assert.equal(saturation.model, PRODUCTION_PROOF.model);
assert.equal(saturation.sdk_request_count, 2);
assert.equal(saturation.baseline_request_count, 1);
assert.equal(saturation.candidate_request_count, 1);
assert.equal(saturation.candidate_session_index, receipt.candidate_session_index);
assert.equal(saturation.selection_probe_count, 0);
assert.equal(saturation.max_completion_tokens, 64);
assert.equal(saturation.proof_contract_sha256, receipt.proof_contract_sha256);
assert.equal(saturation.candidate_route_target, "candidate");
assert.equal(saturation.fallback_route_target, "openai");
assert.equal(saturation.content_retained, false);
assert.equal(saturation.routing_session_sha256, receipt.routing_session_sha256);
assert.equal(saturation.streaming_candidate_held_during_fallback, true);
assert.deepEqual(aborted.sort(), [0, 1]);

function mechanicsResponse(call, omitRouteRevision = false) {
  const headers = {
    "content-type": "application/json",
    "x-milk-capture-intent": "selected",
    "x-milk-route-revision": "openai-baseline-v1",
    "x-milk-route-target": "openai",
    "x-milk-trace-id": `00000000-0000-7000-8000-${String(call).padStart(12, "0")}`,
  };
  if (omitRouteRevision) delete headers["x-milk-route-revision"];
  return new Response(
    JSON.stringify({
      choices: [
        { finish_reason: "stop", index: 0, message: { content: "OK", role: "assistant" } },
      ],
      created: 1,
      id: `mechanics-${call}`,
      model: PRODUCTION_PROOF.model,
      object: "chat.completion",
    }),
    { status: 200, headers },
  );
}

function mechanicsHealthResponse(configSha256 = "a".repeat(64)) {
  return new Response(
    JSON.stringify({
      candidate: "disabled",
      capture: "available",
      config_sha256: configSha256,
      recent_persist_failure: false,
      status: "ok",
      writer_alive: true,
    }),
    {
      status: 200,
      headers: {
        "cache-control": "no-store",
        "content-type": "application/json",
        "x-milk-config-sha256": configSha256,
      },
    },
  );
}

assert.throws(() => generatedMechanicsPlan("another-model"));
let wrongModelTransportCalls = 0;
await assert.rejects(
  runGeneratedMechanics(
    new URL("https://carton.example/v1"),
    { api_key: credential.api_key, cohort_id: "generated-mechanics-v1", model: "another-model" },
    "a".repeat(64),
    async () => {
      wrongModelTransportCalls += 1;
      return mechanicsHealthResponse();
    },
  ),
);
assert.equal(wrongModelTransportCalls, 0);
const mechanicsPlan = generatedMechanicsPlan(PRODUCTION_PROOF.model);
assert.equal(mechanicsPlan.length, 320);
assert.equal(mechanicsPlan[0].request.max_completion_tokens, 256);
assert.equal(mechanicsPlan[0].request.reasoning_effort, "low");
assert.equal(new Set(mechanicsPlan.map((row) => row.sessionId)).size, 320);
assert.match(mechanicsPlan[0].sessionId, /^milk-mechanics-[0-9]{4}$/);
assert.deepEqual(
  mechanicsPlan.slice(0, 251).reduce(
    (counts, row) => ({ ...counts, [row.partition]: counts[row.partition] + 1 }),
    { train: 0, dev: 0, calibration: 0 },
  ),
  { train: 50, dev: 73, calibration: 128 },
);
let mechanicsCalls = 0;
let mechanicsHealthCalls = 0;
const mechanicsSessions = new Set();
const mechanicsLaunches = [];
const mechanics = await runGeneratedMechanics(
  new URL("https://carton.example/v1"),
  {
    api_key: credential.api_key,
    cohort_id: "generated-mechanics-v1",
    model: PRODUCTION_PROOF.model,
  },
  "a".repeat(64),
  async (request) => {
    if (request.url.endsWith("/healthz")) {
      mechanicsHealthCalls += 1;
      return mechanicsHealthResponse();
    }
    const call = mechanicsCalls;
    mechanicsCalls += 1;
    mechanicsLaunches.push(performance.now());
    if (call === 0) {
      const blockedUntil = performance.now() + 30;
      while (performance.now() < blockedUntil) {}
    }
    assert.equal(request.url, "https://carton.example/v1/chat/completions");
    assert.match(
      request.headers.get("x-milk-session-id") ?? "",
      /^milk-mechanics-[0-9]{4}$/,
    );
    mechanicsSessions.add(request.headers.get("x-milk-session-id"));
    return mechanicsResponse(call);
  },
  5,
);
assert.equal(mechanicsCalls, 320);
assert.equal(mechanicsHealthCalls, 2);
assert.equal(mechanicsSessions.size, 320);
assert.equal(mechanics.schema_version, "milk.official-openai-sdk-generated-mechanics.v2");
assert.equal(mechanics.proof_step, "generated_mechanics");
assert.equal(mechanics.model, PRODUCTION_PROOF.model);
assert.equal(mechanics.request_timeout_ms, 60_000);
assert.equal(mechanics.minimum_request_interval_ms, 5);
assert.equal(mechanics.reasoning_effort, "low");
assert.equal(mechanics.concurrency, 1);
assert.equal(mechanics.sdk_request_count, 320);
assert.equal(mechanics.baseline_request_count, 320);
assert.equal(mechanics.candidate_request_count, 0);
assert.equal(mechanics.max_completion_tokens, 256);
assert.equal(mechanics.proof_contract_sha256, productionProofSha256);
assert.equal(mechanics.planned, 320);
assert.equal(mechanics.attempted, 320);
assert.equal(mechanics.successful, 320);
assert.equal(mechanics.failed, 0);
assert.equal(mechanics.transported, 320);
assert.equal(mechanics.unique_trace_ids, 320);
assert.deepEqual(mechanics.first_partition_counts, { train: 50, dev: 73, calibration: 128 });
assert.deepEqual(mechanics.retry_partition_counts, { train: 13, dev: 18, calibration: 38 });
assert.deepEqual(mechanics.total_partition_counts, { train: 63, dev: 91, calibration: 166 });
assert.deepEqual(mechanics.http_status_counts, { 200: 320 });
assert.match(mechanics.request_set_sha256, /^[0-9a-f]{64}$/);
assert.match(mechanics.response_set_sha256, /^[0-9a-f]{64}$/);
assert.match(mechanics.trace_set_sha256, /^[0-9a-f]{64}$/);
assert.match(mechanics.preflight_health_sha256, /^[0-9a-f]{64}$/);
assert.match(mechanics.postflight_health_sha256, /^[0-9a-f]{64}$/);
assert.equal(mechanics.postflight_health_succeeded, true);
assert.match(mechanics.tool_sha256, /^[0-9a-f]{64}$/);
assert.equal(mechanics.gateway_config_sha256, "a".repeat(64));
assert.equal(mechanics.route_revision, "openai-baseline-v1");
assert.equal(mechanics.content_retained, false);
assert.equal(mechanics.succeeded, true);
const mechanicsLaunchGaps = mechanicsLaunches.slice(1).map(
  (launchedAt, index) => launchedAt - mechanicsLaunches[index],
);
assert.ok(
  mechanicsLaunchGaps.every((gap) => gap >= 3),
  `minimum launch gap ${Math.min(...mechanicsLaunchGaps)}`,
);
assert.equal(
  receipt.sdk_request_count,
  receipt.baseline_request_count + receipt.candidate_request_count,
);
assert.equal(
  saturation.sdk_request_count,
  saturation.baseline_request_count + saturation.candidate_request_count,
);

let drainedCalls = 0;
let drainedHealthCalls = 0;
const drained = await runGeneratedMechanics(
  new URL("https://carton.example/v1"),
  {
    api_key: credential.api_key,
    cohort_id: "generated-mechanics-v1",
    model: PRODUCTION_PROOF.model,
  },
  "a".repeat(64),
  async (request) => {
    if (request.url.endsWith("/healthz")) {
      drainedHealthCalls += 1;
      return mechanicsHealthResponse();
    }
    const call = drainedCalls;
    drainedCalls += 1;
    return mechanicsResponse(call, call === 17);
  },
  0,
);
assert.equal(drainedCalls, 320);
assert.equal(drainedHealthCalls, 2);
assert.equal(drained.attempted, 320);
assert.equal(drained.transported, 320);
assert.equal(drained.successful, 319);
assert.equal(drained.failed, 1);
assert.deepEqual(drained.http_status_counts, { 200: 320 });
assert.equal(drained.succeeded, false);

let rejectedChats = 0;
await assert.rejects(
  runGeneratedMechanics(
    new URL("https://carton.example/v1"),
    {
      api_key: credential.api_key,
      cohort_id: "generated-mechanics-v1",
      model: PRODUCTION_PROOF.model,
    },
    "a".repeat(64),
    async (request) => {
      if (request.url.endsWith("/healthz")) return mechanicsHealthResponse("b".repeat(64));
      rejectedChats += 1;
      return mechanicsResponse(rejectedChats);
    },
    0,
  ),
);
assert.equal(rejectedChats, 0);

process.stdout.write("official OpenAI SDK candidate route smoke: ok\n");
