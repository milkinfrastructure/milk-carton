import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  productionPathPlan,
  readCredential,
  runProductionPath,
} from "./openai-production-path-workload.mjs";

const credential = {
  api_key: "milk_live_00000000-0000-4000-8000-000000000001_fresh_secret_1234567890",
  cohort_id: "fresh-production-path-mechanics",
  model: "zai-org/GLM-5.3-Flash",
};

const plan = productionPathPlan(credential.model);
assert.equal(plan.length, 100);
assert.equal(new Set(plan.map((row) => row.sessionId)).size, 100);
assert.equal(new Set(plan.map((row) => row.requestSha256)).size, 100);
assert.equal(plan.filter((row) => row.endpoint === "chat_completions").length, 50);
assert.equal(plan.filter((row) => row.endpoint === "responses").length, 50);
assert.ok(plan.every((row) => (
  row.request.max_completion_tokens ?? row.request.max_output_tokens
) === 64));
assert.deepEqual(plan, productionPathPlan(credential.model));

const temporary = await mkdtemp(join(tmpdir(), "milk-production-path-"));
try {
  const credentialPath = join(temporary, "credential.json");
  await writeFile(credentialPath, `${JSON.stringify(credential)}\n`, { mode: 0o400 });
  assert.deepEqual(await readCredential(credentialPath), credential);
} finally {
  await rm(temporary, { recursive: true });
}

let active = 0;
let maximumActive = 0;
let validRequests = 0;
let invalidRequests = 0;
let chatRequests = 0;
let responsesRequests = 0;
const sessions = new Set();

const server = createServer(async (request, response) => {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  const authorization = request.headers.authorization;
  if (authorization !== `Bearer ${credential.api_key}`) {
    invalidRequests += 1;
    assert.equal(authorization, "Bearer invalid-production-path-key");
    response.writeHead(401, { "content-type": "application/json" });
    response.end(JSON.stringify({
      error: {
        code: "invalid_api_key",
        message: "invalid API key",
        type: "invalid_request_error",
      },
    }));
    return;
  }

  validRequests += 1;
  active += 1;
  maximumActive = Math.max(maximumActive, active);
  const session = request.headers["x-milk-session-id"];
  assert.equal(typeof session, "string");
  assert.equal(sessions.has(session), false);
  sessions.add(session);
  const traceId = `00000000-0000-7000-8000-${String(validRequests).padStart(12, "0")}`;
  const headers = {
    "content-type": "application/json",
    "x-milk-capture-intent": "selected",
    "x-milk-trace-id": traceId,
  };

  const finish = () => {
    if (request.url === "/v1/chat/completions") {
      chatRequests += 1;
      assert.ok(Array.isArray(body.messages));
      response.writeHead(200, headers);
      response.end(JSON.stringify({
        choices: [{
          finish_reason: "stop",
          index: 0,
          message: { content: "private-response-sentinel", role: "assistant" },
        }],
        created: 1,
        id: `chat-${validRequests}`,
        model: credential.model,
        object: "chat.completion",
      }));
    } else {
      assert.equal(request.url, "/v1/responses");
      responsesRequests += 1;
      assert.equal(typeof body.input, "string");
      response.writeHead(200, headers);
      response.end(JSON.stringify({
        created_at: 1,
        id: `resp-${validRequests}`,
        model: credential.model,
        object: "response",
        output: [{
          content: [{ annotations: [], text: "private-response-sentinel", type: "output_text" }],
          id: `msg-${validRequests}`,
          role: "assistant",
          status: "completed",
          type: "message",
        }],
        status: "completed",
      }));
    }
    active -= 1;
  };
  setTimeout(finish, session.startsWith("milk-production-path-smoke-") ? 1 : 10);
});

await new Promise((resolve, reject) => {
  server.once("error", reject);
  server.listen(0, "127.0.0.1", resolve);
});

let receipt;
try {
  const address = server.address();
  assert.equal(typeof address, "object");
  receipt = await runProductionPath(
    new URL(`http://127.0.0.1:${address.port}/v1`),
    credential,
  );
} finally {
  await new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}

assert.equal(invalidRequests, 1);
assert.equal(validRequests, 102);
assert.equal(chatRequests, 51);
assert.equal(responsesRequests, 51);
assert.equal(sessions.size, 102);
assert.equal(maximumActive, 4);
assert.equal(receipt.schema_version, "milk.official-openai-sdk-production-path.v1");
assert.equal(receipt.status, "succeeded");
assert.deepEqual(receipt.counts, {
  captured_requests: 102,
  chat_completions_requests: 52,
  concurrency: 4,
  failed_workload_sessions: 0,
  invalid_key_requests: 1,
  planned_sessions: 100,
  responses_requests: 51,
  sdk_requests: 103,
  successful_workload_sessions: 100,
  unique_trace_ids: 102,
  valid_smoke_requests: 2,
  workload_sessions: 100,
});
assert.deepEqual(receipt.http_status_counts, { 200: 102, 401: 1 });
assert.deepEqual(Object.keys(receipt.hashes).sort(), [
  "request_set_sha256",
  "response_set_sha256",
  "tool_sha256",
  "trace_set_sha256",
]);
for (const value of Object.values(receipt.hashes)) {
  assert.match(value, /^[0-9a-f]{64}$/);
}
assert.equal(receipt.trace_ids.length, 102);
assert.equal(new Set(receipt.trace_ids).size, 102);
const serialized = JSON.stringify(receipt);
for (const forbidden of [
  credential.api_key,
  credential.cohort_id,
  credential.model,
  "private-response-sentinel",
  "authentication check",
  "Return only READY",
]) {
  assert.equal(serialized.includes(forbidden), false);
}

process.stdout.write("official OpenAI SDK production-path workload: ok\n");
