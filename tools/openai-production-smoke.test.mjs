import assert from "node:assert/strict";

import {
  candidateRequest,
  generatedMechanicsPlan,
  runBaselineSmoke,
  runCandidateSmoke,
  runGeneratedMechanics,
  runSaturationFallbackSmoke,
  saturationRequest,
} from "./openai-production-smoke.mjs";

const digest = (byte) => byte.repeat(64);
const credential = {
  api_key: "dt_live_00000000-0000-4000-8000-000000000001_test_secret_123456789",
  cohort_id: "paid-proof-selected-cohort-v1",
  model: "milk-student-v1",
  reasoning_effort: "high",
};
const revision = digest("1");
const data = {
  choices: [{ finish_reason: "stop", message: { content: "OK", role: "assistant" } }],
};

function client(routeRevision = revision, routeTarget = "candidate", includeReasoning = true) {
  return {
    chat: {
      completions: {
        create(request) {
          const expected = {
            messages: [{ role: "user", content: "Reply with only OK." }],
            model: credential.model,
          };
          if (includeReasoning) expected.reasoning_effort = "high";
          assert.deepEqual(request, expected);
          return {
            async withResponse() {
              return {
                data,
                response: {
                  headers: new Headers({
                    "x-dragontales-artifact-sha256": digest("2"),
                    "x-dragontales-candidate-sha256": digest("3"),
                    "x-dragontales-deployment-sha256": digest("4"),
                    "x-dragontales-route-revision": routeRevision,
                    "x-dragontales-route-target": routeTarget,
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
  messages: [{ role: "user", content: "Reply with only OK." }],
  model: credential.model,
});
const receipt = await runCandidateSmoke(
  client(),
  new URL("https://api.dragontales.milkinfrastructure.com/v1"),
  credential,
  revision,
);
assert.equal(receipt.schema_version, "milk.official-openai-sdk-route-smoke.v1");
assert.equal(receipt.route_revision, revision);
assert.equal(receipt.route_target, "candidate");
assert.equal(receipt.candidate_sha256, digest("3"));
assert.equal(receipt.artifact_sha256, digest("2"));
assert.equal(receipt.deployment_sha256, digest("4"));
assert.match(receipt.traffic_key_sha256, /^[0-9a-f]{64}$/);
assert.match(receipt.traffic_cohort_sha256, /^[0-9a-f]{64}$/);

const baseline = await runBaselineSmoke(
  client(revision, "candidate", false),
  new URL("https://api.dragontales.milkinfrastructure.com/v1"),
  { api_key: credential.api_key, cohort_id: credential.cohort_id, model: credential.model },
);
assert.equal(baseline.schema_version, "milk.official-openai-sdk-smoke.v1");
assert.equal(baseline.authenticated, true);
assert.equal(baseline.content_retained, false);
assert.match(baseline.traffic_key_sha256, /^[0-9a-f]{64}$/);
assert.match(baseline.traffic_cohort_sha256, /^[0-9a-f]{64}$/);

await assert.rejects(
  runCandidateSmoke(
    client(digest("5")),
    new URL("https://api.dragontales.milkinfrastructure.com/v1"),
    credential,
    revision,
  ),
);
await assert.rejects(
  runCandidateSmoke(
    client(revision, "openai"),
    new URL("https://api.dragontales.milkinfrastructure.com/v1"),
    credential,
    revision,
  ),
);

assert.deepEqual(saturationRequest(credential), {
  messages: [
    {
      role: "user",
      content: "Write OK on 4096 separate lines. Do not summarize or stop early.",
    },
  ],
  model: credential.model,
  reasoning_effort: "high",
  stream: true,
});
let saturationCall = 0;
const aborted = [];
const saturationClient = {
  chat: {
    completions: {
      create(request) {
        assert.deepEqual(request, saturationRequest(credential));
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
                  "x-dragontales-artifact-sha256": digest("2"),
                  "x-dragontales-candidate-sha256": digest("3"),
                  "x-dragontales-deployment-sha256": digest("4"),
                  "x-dragontales-route-revision": revision,
                  "x-dragontales-route-target": call === 0 ? "candidate" : "openai",
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
  new URL("https://api.dragontales.milkinfrastructure.com/v1"),
  credential,
  revision,
);
assert.equal(saturation.schema_version, "milk.official-openai-sdk-saturation-fallback-smoke.v1");
assert.equal(saturation.candidate_route_target, "candidate");
assert.equal(saturation.fallback_route_target, "openai");
assert.equal(saturation.content_retained, false);
assert.deepEqual(aborted.sort(), [0, 1]);

function mechanicsResponse(call, omitRouteRevision = false) {
  const headers = {
    "content-type": "application/json",
    "x-dragontales-capture-intent": "selected",
    "x-dragontales-route-revision": "openai-baseline-v1",
    "x-dragontales-route-target": "openai",
    "x-dragontales-trace-id": `00000000-0000-7000-8000-${String(call).padStart(12, "0")}`,
  };
  if (omitRouteRevision) delete headers["x-dragontales-route-revision"];
  return new Response(
    JSON.stringify({
      choices: [
        { finish_reason: "stop", index: 0, message: { content: "OK", role: "assistant" } },
      ],
      created: 1,
      id: `mechanics-${call}`,
      model: "baseline-model",
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
        "x-dragontales-config-sha256": configSha256,
      },
    },
  );
}

const mechanicsPlan = generatedMechanicsPlan("baseline-model");
assert.equal(mechanicsPlan.length, 320);
assert.equal(mechanicsPlan[0].request.max_completion_tokens, 128);
assert.deepEqual(
  mechanicsPlan.slice(0, 251).reduce(
    (counts, row) => ({ ...counts, [row.partition]: counts[row.partition] + 1 }),
    { train: 0, dev: 0, calibration: 0 },
  ),
  { train: 50, dev: 73, calibration: 128 },
);
let mechanicsCalls = 0;
let mechanicsHealthCalls = 0;
const mechanics = await runGeneratedMechanics(
  new URL("https://api.dragontales.milkinfrastructure.com/v1"),
  {
    api_key: credential.api_key,
    cohort_id: "generated-mechanics-v1",
    model: "baseline-model",
  },
  "a".repeat(64),
  async (request) => {
    if (request.url.endsWith("/healthz")) {
      mechanicsHealthCalls += 1;
      return mechanicsHealthResponse();
    }
    const call = mechanicsCalls;
    mechanicsCalls += 1;
    assert.equal(request.url, "https://api.dragontales.milkinfrastructure.com/v1/chat/completions");
    return mechanicsResponse(call);
  },
);
assert.equal(mechanicsCalls, 320);
assert.equal(mechanicsHealthCalls, 2);
assert.equal(mechanics.schema_version, "milk.official-openai-sdk-generated-mechanics.v1");
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

let drainedCalls = 0;
let drainedHealthCalls = 0;
const drained = await runGeneratedMechanics(
  new URL("https://api.dragontales.milkinfrastructure.com/v1"),
  {
    api_key: credential.api_key,
    cohort_id: "generated-mechanics-v1",
    model: "baseline-model",
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
    new URL("https://api.dragontales.milkinfrastructure.com/v1"),
    {
      api_key: credential.api_key,
      cohort_id: "generated-mechanics-v1",
      model: "baseline-model",
    },
    "a".repeat(64),
    async (request) => {
      if (request.url.endsWith("/healthz")) return mechanicsHealthResponse("b".repeat(64));
      rejectedChats += 1;
      return mechanicsResponse(rejectedChats);
    },
  ),
);
assert.equal(rejectedChats, 0);

process.stdout.write("official OpenAI SDK candidate route smoke: ok\n");
