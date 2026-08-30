import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open, readFile } from "node:fs/promises";
import { isAbsolute } from "node:path";
import { pathToFileURL } from "node:url";

import OpenAI from "openai";

const CONCURRENCY = 4;
const MAX_CREDENTIAL_BYTES = 8_192;
const MAX_RESPONSE_BYTES = 65_536;
const SESSION_COUNT = 100;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

export async function readCredential(path) {
  assert.equal(isAbsolute(path), true);
  const descriptor = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  let raw;
  try {
    const metadata = await descriptor.stat();
    assert.equal(metadata.isFile(), true);
    assert.equal(metadata.nlink, 1);
    assert.equal(metadata.uid, process.getuid());
    assert.equal(metadata.mode & 0o077, 0);
    assert.ok(metadata.size > 0 && metadata.size <= MAX_CREDENTIAL_BYTES);
    raw = await descriptor.readFile();
    assert.equal(raw.length, metadata.size);
  } finally {
    await descriptor.close();
  }
  assert.equal(raw.at(-1), 0x0a);
  const value = JSON.parse(raw.subarray(0, -1).toString("utf8"));
  assert.deepEqual(Object.keys(value).sort(), ["api_key", "cohort_id", "model"]);
  assert.match(
    value.api_key,
    /^milk_live_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}_[A-Za-z0-9._~-]{16,256}$/,
  );
  assert.match(value.cohort_id, /^[A-Za-z0-9._~-]{1,128}$/);
  assert.equal(typeof value.model, "string");
  assert.ok(value.model.length > 0 && value.model.length <= 256);
  return value;
}

const PROMPTS = [
  (index) => `Return only the integer result of ${index + 17} plus ${index + 29}.`,
  (index) => `Summarize in one sentence: Batch ${index} shipped after inspection and arrived intact.`,
  (index) => `Extract only the order code from: region=west; order=MILK-${String(index).padStart(3, "0")}; state=ready.`,
  (index) => `Classify as positive, neutral, or negative only: The delivery window ${index} was confirmed.`,
  (index) => `Rewrite formally in one sentence: carton ${index} got here on time.`,
  (index) => `Write a five-word reminder to inspect batch ${index}.`,
  (index) => `Return only a JavaScript expression that doubles the integer ${index}.`,
  (index) => `List exactly two ordered steps for verifying package ${index}.`,
  (index) => `Answer only yes or no: is ${index * 2} an even integer?`,
  (index) => `Choose only smaller or larger: compare ${index + 3} with ${index + 8}.`,
];

export function productionPathPlan(model) {
  assert.equal(typeof model, "string");
  assert.ok(model.length > 0 && model.length <= 256);
  return Array.from({ length: SESSION_COUNT }, (_, index) => {
    const endpoint = index % 2 === 0 ? "chat_completions" : "responses";
    const prompt = PROMPTS[index % PROMPTS.length](index);
    const request = endpoint === "chat_completions"
      ? {
          max_completion_tokens: 64,
          messages: [{ role: "user", content: prompt }],
          model,
        }
      : { input: prompt, max_output_tokens: 64, model };
    const sessionId = `milk-production-path-${String(index).padStart(3, "0")}`;
    return {
      endpoint,
      request,
      requestSha256: sha256(canonical({ endpoint, request, sessionId })),
      sessionId,
    };
  });
}

function responseObservation(data, response, requestSha256) {
  const responseRaw = canonical(data);
  assert.ok(Buffer.byteLength(responseRaw) > 0);
  assert.ok(Buffer.byteLength(responseRaw) <= MAX_RESPONSE_BYTES);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("x-milk-capture-intent"), "selected");
  const traceId = response.headers.get("x-milk-trace-id");
  assert.match(traceId ?? "", UUID);
  return {
    requestSha256,
    responseSha256: sha256(responseRaw),
    traceId,
  };
}

async function runRequest(client, row) {
  const options = { headers: { "x-milk-session-id": row.sessionId } };
  const result = row.endpoint === "chat_completions"
    ? await client.chat.completions.create(row.request, options).withResponse()
    : await client.responses.create(row.request, options).withResponse();
  return responseObservation(result.data, result.response, row.requestSha256);
}

export async function runProductionPath(endpoint, credential, fetch = globalThis.fetch) {
  const options = {
    baseURL: endpoint.href,
    fetch,
    maxRetries: 0,
    timeout: 60_000,
  };
  const invalidClient = new OpenAI({ ...options, apiKey: "invalid-production-path-key" });
  const invalidRequest = {
    max_completion_tokens: 1,
    messages: [{ role: "user", content: "authentication check" }],
    model: credential.model,
  };
  let invalidStatus = null;
  try {
    await invalidClient.chat.completions.create(invalidRequest);
  } catch (error) {
    assert.ok(error instanceof OpenAI.AuthenticationError);
    invalidStatus = error.status;
  }
  assert.equal(invalidStatus, 401);

  const client = new OpenAI({ ...options, apiKey: credential.api_key });
  const smoke = [
    {
      endpoint: "chat_completions",
      request: {
        max_completion_tokens: 16,
        messages: [{ role: "user", content: "Return only READY." }],
        model: credential.model,
      },
      sessionId: "milk-production-path-smoke-chat",
    },
    {
      endpoint: "responses",
      request: {
        input: "Return only READY.",
        max_output_tokens: 16,
        model: credential.model,
      },
      sessionId: "milk-production-path-smoke-responses",
    },
  ].map((row) => ({
    ...row,
    requestSha256: sha256(canonical(row)),
  }));
  const observations = [
    await runRequest(client, smoke[0]),
    await runRequest(client, smoke[1]),
  ];

  const plan = productionPathPlan(credential.model);
  const workload = new Array(plan.length);
  let cursor = 0;
  async function worker() {
    while (cursor < plan.length) {
      const index = cursor;
      cursor += 1;
      workload[index] = await runRequest(client, plan[index]);
    }
  }
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));
  observations.push(...workload);

  const traceIds = observations.map((row) => row.traceId).sort();
  assert.equal(new Set(traceIds).size, observations.length);
  const requestSet = [
    sha256(canonical({ endpoint: "chat_completions", request: invalidRequest })),
    ...smoke.map((row) => row.requestSha256),
    ...plan.map((row) => row.requestSha256),
  ];
  const responseSet = observations
    .map((row) => ({
      request_sha256: row.requestSha256,
      response_sha256: row.responseSha256,
    }))
    .sort((left, right) => left.request_sha256.localeCompare(right.request_sha256));
  return {
    counts: {
      captured_requests: observations.length,
      chat_completions_requests: 52,
      concurrency: CONCURRENCY,
      failed_workload_sessions: 0,
      invalid_key_requests: 1,
      planned_sessions: plan.length,
      responses_requests: 51,
      sdk_requests: 103,
      successful_workload_sessions: workload.length,
      unique_trace_ids: new Set(traceIds).size,
      valid_smoke_requests: smoke.length,
      workload_sessions: workload.length,
    },
    hashes: {
      request_set_sha256: sha256(canonical(requestSet)),
      response_set_sha256: sha256(canonical(responseSet)),
      tool_sha256: sha256(await readFile(new URL(import.meta.url))),
      trace_set_sha256: sha256(canonical(traceIds)),
    },
    http_status_counts: { 200: observations.length, 401: 1 },
    schema_version: "milk.official-openai-sdk-production-path.v1",
    status: "succeeded",
    trace_ids: traceIds,
  };
}

function productionEndpoint(value) {
  const endpoint = new URL(value);
  assert.equal(endpoint.protocol, "https:");
  assert.match(endpoint.hostname, HOSTNAME);
  assert.equal(endpoint.host, endpoint.hostname);
  assert.equal(endpoint.pathname, "/v1");
  assert.equal(endpoint.search, "");
  assert.equal(endpoint.hash, "");
  assert.equal(endpoint.username, "");
  assert.equal(endpoint.password, "");
  return endpoint;
}

async function main() {
  assert.equal(process.argv.length, 4);
  const endpoint = productionEndpoint(process.argv[2]);
  const credential = await readCredential(process.argv[3]);
  const receipt = await runProductionPath(endpoint, credential);
  process.stdout.write(`${canonical(receipt)}\n`);
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main().catch(() => {
    process.stderr.write("openai-production-path-workload: failed\n");
    process.exitCode = 70;
  });
}
