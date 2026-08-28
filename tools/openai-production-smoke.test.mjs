import assert from "node:assert/strict";

import {
  candidateRequest,
  runBaselineSmoke,
  runCandidateSmoke,
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
  { api_key: credential.api_key, model: credential.model },
);
assert.equal(baseline.schema_version, "milk.official-openai-sdk-smoke.v1");
assert.equal(baseline.authenticated, true);
assert.equal(baseline.content_retained, false);

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

process.stdout.write("official OpenAI SDK candidate route smoke: ok\n");
