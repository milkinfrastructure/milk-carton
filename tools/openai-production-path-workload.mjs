import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open, readFile } from "node:fs/promises";
import { isAbsolute } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { pathToFileURL } from "node:url";

import OpenAI from "openai";

const CONCURRENCY = 2;
const DEFAULT_MINIMUM_REQUEST_INTERVAL_MS = 4_100;
const MAXIMUM_REQUEST_INTERVAL_MS = 10_000;
const MAX_CREDENTIAL_BYTES = 8_192;
const MAX_RESPONSE_BYTES = 65_536;
const MAX_STREAM_CHUNKS = 512;
const SESSION_COUNT = 100;
const SDK_VERSION = "6.33.0";
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

export function productionPathRequestInterval(value = DEFAULT_MINIMUM_REQUEST_INTERVAL_MS) {
  const raw = String(value);
  assert.match(raw, /^(?:0|[1-9][0-9]{0,4})$/);
  const interval = Number(raw);
  assert.ok(interval <= MAXIMUM_REQUEST_INTERVAL_MS);
  return interval;
}

function launchScheduler(interval, { now = Date.now, sleep = delay } = {}) {
  let lastStart = null;
  let pending = Promise.resolve();
  return () => {
    pending = pending.then(async () => {
      if (lastStart !== null) {
        const waitMs = lastStart + interval - now();
        if (waitMs > 0) await sleep(waitMs);
      }
      lastStart = now();
    });
    return pending;
  };
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

function responseObservation(response) {
  assert.equal(response.status, 200);
  const intent = response.headers.get("x-milk-capture-intent");
  assert.ok(intent === "selected" || intent === "not_selected");
  const traceId = response.headers.get("x-milk-trace-id");
  assert.match(traceId ?? "", UUID);
  return { intent, traceId };
}

async function runRequest(client, row) {
  try {
    const options = { headers: { "x-milk-session-id": row.sessionId } };
    const result = row.endpoint === "chat_completions"
      ? await client.chat.completions.create(row.request, options).withResponse()
      : await client.responses.create(row.request, options).withResponse();
    assert.notEqual(result.data, null);
    assert.equal(typeof result.data, "object");
    const responseRaw = canonical(result.data);
    const responseBytes = Buffer.byteLength(responseRaw);
    assert.ok(responseBytes > 0 && responseBytes <= MAX_RESPONSE_BYTES);
    return {
      ...responseObservation(result.response),
      requestSha256: row.requestSha256,
      responseSha256: sha256(responseRaw),
    };
  } catch (error) {
    if (error && typeof error === "object") {
      error.milkStage = `${row.endpoint}:${row.sessionId}`;
    }
    throw error;
  }
}

async function runStreamingRequest(client, row) {
  try {
    const result = await client.chat.completions.create(row.request, {
      headers: { "x-milk-session-id": row.sessionId },
    }).withResponse();
    let chunks = 0;
    let responseBytes = 0;
    let usageChunks = 0;
    const chunkDigest = createHash("sha256");
    for await (const chunk of result.data) {
      assert.notEqual(chunk, null);
      assert.equal(typeof chunk, "object");
      if (chunk.usage !== undefined && chunk.usage !== null) {
        assert.equal(typeof chunk.usage, "object");
        usageChunks += 1;
      }
      const encoded = Buffer.from(canonical(chunk), "utf8");
      responseBytes += encoded.length;
      assert.ok(responseBytes <= MAX_RESPONSE_BYTES);
      const length = Buffer.alloc(4);
      length.writeUInt32BE(encoded.length);
      chunkDigest.update(length);
      chunkDigest.update(encoded);
      chunks += 1;
      assert.ok(chunks <= MAX_STREAM_CHUNKS);
    }
    assert.ok(chunks > 0);
    assert.ok(usageChunks > 0 && usageChunks <= chunks);
    return {
      chunkSha256: chunkDigest.digest("hex"),
      chunks,
      fullyConsumed: true,
      requestSha256: row.requestSha256,
      responseBytes,
      usageChunks,
      ...responseObservation(result.response),
    };
  } catch (error) {
    if (error && typeof error === "object") {
      error.milkStage = `stream:${row.sessionId}`;
    }
    throw error;
  }
}

export async function runProductionPath(
  endpoint,
  credential,
  fetch = globalThis.fetch,
  minimumRequestIntervalMs = DEFAULT_MINIMUM_REQUEST_INTERVAL_MS,
  timing,
) {
  minimumRequestIntervalMs = productionPathRequestInterval(minimumRequestIntervalMs);
  const packageMetadata = JSON.parse(
    await readFile(new URL("../node_modules/openai/package.json", import.meta.url), "utf8"),
  );
  assert.equal(packageMetadata.version, SDK_VERSION);
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
  let invalidTraceId = null;
  try {
    await invalidClient.chat.completions.create(invalidRequest);
  } catch (error) {
    assert.ok(error instanceof OpenAI.AuthenticationError);
    invalidStatus = error.status;
    invalidTraceId = error.headers?.get("x-milk-trace-id") ?? null;
  }
  assert.equal(invalidStatus, 401);
  assert.match(invalidTraceId ?? "", UUID);

  const waitForLaunch = launchScheduler(minimumRequestIntervalMs, timing);
  const client = new OpenAI({
    ...options,
    apiKey: credential.api_key,
    fetch: async (input, init) => {
      await waitForLaunch();
      return fetch(input, init);
    },
  });
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
  const smokeObservations = [
    await runRequest(client, smoke[0]),
    await runRequest(client, smoke[1]),
  ];
  const plan = productionPathPlan(credential.model);
  const workload = new Array(plan.length);
  let cursor = 0;
  let failure = null;
  async function worker() {
    while (failure === null && cursor < plan.length) {
      const index = cursor;
      cursor += 1;
      try {
        workload[index] = await runRequest(client, plan[index]);
      } catch (error) {
        failure ??= error;
      }
    }
  }
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));
  if (failure !== null) throw failure;
  const initial = [
    ...smokeObservations.map((row, index) => ({ ...row, sessionId: smoke[index].sessionId })),
    ...workload.map((row, index) => ({ ...row, sessionId: plan[index].sessionId })),
  ];
  const selectedInitial = initial.find((row) => row.intent === "selected");
  assert.ok(selectedInitial);
  const streamRow = {
    endpoint: "chat_completions",
    request: {
      max_completion_tokens: 64,
      messages: [{ role: "user", content: "Reply with only STREAMED." }],
      model: credential.model,
      stream: true,
      stream_options: { include_usage: true },
    },
    sessionId: selectedInitial.sessionId,
  };
  streamRow.requestSha256 = sha256(canonical(streamRow));
  const streamed = await runStreamingRequest(client, streamRow);
  assert.equal(streamed.intent, "selected");
  const observations = [...initial, streamed];

  const traceIds = observations.map((row) => row.traceId).sort();
  assert.equal(new Set(traceIds).size, observations.length);
  const selectedTraceIds = observations
    .filter((row) => row.intent === "selected")
    .map((row) => row.traceId)
    .sort();
  const notSelectedTraceIds = observations
    .filter((row) => row.intent === "not_selected")
    .map((row) => row.traceId)
    .sort();
  assert.ok(selectedTraceIds.includes(streamed.traceId));
  const requestSet = [
    sha256(canonical({ endpoint: "chat_completions", request: invalidRequest })),
    ...smoke.map((row) => row.requestSha256),
    streamRow.requestSha256,
    ...plan.map((row) => row.requestSha256),
  ];
  const responseSet = observations
    .map((row) => ({
      request_sha256: row.requestSha256,
      response_sha256: row.responseSha256 ?? row.chunkSha256,
    }))
    .sort((left, right) => left.request_sha256.localeCompare(right.request_sha256));
  const chatCompletionsRequests = [streamRow, ...smoke, ...plan]
    .filter((row) => row.endpoint === "chat_completions").length;
  const responsesRequests = [...smoke, ...plan]
    .filter((row) => row.endpoint === "responses").length;
  return {
    counts: {
      chat_completions_requests: chatCompletionsRequests,
      concurrency: CONCURRENCY,
      failed_workload_sessions: 0,
      invalid_key_requests: 1,
      minimum_request_interval_ms: minimumRequestIntervalMs,
      not_selected: notSelectedTraceIds.length,
      observed_requests: observations.length,
      planned_sessions: plan.length,
      responses_requests: responsesRequests,
      sdk_requests: observations.length + 1,
      selected: selectedTraceIds.length,
      streaming_requests: 1,
      successful_workload_sessions: workload.length,
      unique_trace_ids: new Set(traceIds).size,
      valid_smoke_requests: smoke.length,
      workload_sessions: workload.length,
    },
    hashes: {
      endpoint_sha256: sha256(endpoint.href),
      request_set_sha256: sha256(canonical(requestSet)),
      response_set_sha256: sha256(canonical(responseSet)),
      not_selected_trace_set_sha256: sha256(canonical(notSelectedTraceIds)),
      selected_trace_set_sha256: sha256(canonical(selectedTraceIds)),
      tool_sha256: sha256(await readFile(new URL(import.meta.url))),
      trace_set_sha256: sha256(canonical(traceIds)),
    },
    http_status_counts: { 200: observations.length, 401: 1 },
    invalid_auth: { http_status: invalidStatus, trace_id: invalidTraceId },
    not_selected_trace_ids: notSelectedTraceIds,
    selected_trace_ids: selectedTraceIds,
    schema_version: "milk.official-openai-sdk-production-path.v3",
    sdk: "openai-node",
    sdk_version: SDK_VERSION,
    status: "succeeded",
    streaming: {
      response_bytes: streamed.responseBytes,
      chunk_count: streamed.chunks,
      chunk_sha256: streamed.chunkSha256,
      fully_consumed: streamed.fullyConsumed,
      requests: 1,
      trace_id: streamed.traceId,
      usage_chunks: streamed.usageChunks,
    },
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
  const interval = productionPathRequestInterval(
    process.env.MILK_PRODUCTION_PATH_REQUEST_INTERVAL_MS,
  );
  const receipt = await runProductionPath(
    endpoint,
    credential,
    globalThis.fetch,
    interval,
  );
  process.stdout.write(`${canonical(receipt)}\n`);
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main().catch((error) => {
    const status = Number.isInteger(error?.status) ? ` status=${error.status}` : "";
    process.stderr.write(`openai-production-path-workload: failed${status}\n`);
    process.exitCode = 70;
  });
}
