import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open, readFile } from "node:fs/promises";
import { isAbsolute } from "node:path";
import { pathToFileURL } from "node:url";

import OpenAI from "openai";

const SDK_VERSION = "6.33.0";
const MAX_CREDENTIAL_BYTES = 8_192;
const MAX_HEALTH_BYTES = 16_384;
const MAX_RESPONSE_BYTES = 65_536;
const SHA256 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MECHANICS_EVAL_ID =
  "959caacb397004bf3e60f13613da50f4ed3160a65d18b178c3d996398e29b5a0";
const MECHANICS_PARTITION_DOMAIN = Buffer.from(
  "dragontales.teacher-partition.v1\0",
);
const MECHANICS_PHASES = [
  { train: 50, dev: 73, calibration: 128 },
  { train: 13, dev: 18, calibration: 38 },
];
const MECHANICS_CONCURRENCY = 4;
const MECHANICS_MAX_CANDIDATES = 10_000;
const MECHANICS_ROUTE_REVISION = "openai-baseline-v1";
const SATURATION_LINE_COUNT = 4_096;
export const PRODUCTION_PROOF = Object.freeze({
  baseline_requests: 322,
  candidate_requests: 2,
  generated_health_timeout_ms: 30_000,
  generated_mechanics_requests: 320,
  generated_request_timeout_ms: 30_000,
  max_sdk_requests: 324,
  model: "gpt-5.4",
  saturation_max_completion_tokens: 3_840,
  short_max_completion_tokens: 128,
});

function assertProofModel(model) {
  assert.equal(model, PRODUCTION_PROOF.model);
}

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

const PRODUCTION_PROOF_SHA256 = sha256(canonical(PRODUCTION_PROOF));

function mechanicsPartition(raw) {
  const requestSha256 = sha256(raw);
  const digest = createHash("sha256")
    .update(MECHANICS_PARTITION_DOMAIN)
    .update(Buffer.from(requestSha256, "hex"))
    .digest();
  const bucket = digest.readUInt16BE(0) % 10;
  return {
    partition: bucket < 8 ? "train" : bucket === 8 ? "dev" : "calibration",
    requestSha256,
  };
}

function partitionCounts(rows) {
  const counts = { train: 0, dev: 0, calibration: 0 };
  for (const row of rows) counts[row.partition] += 1;
  return counts;
}

export function generatedMechanicsPlan(model) {
  assertProofModel(model);
  const plan = [];
  let nonce = 0;
  for (const target of MECHANICS_PHASES) {
    const counts = { train: 0, dev: 0, calibration: 0 };
    const targetCount = Object.values(target).reduce((total, value) => total + value, 0);
    while (Object.values(counts).reduce((total, value) => total + value, 0) < targetCount) {
      assert.ok(nonce < MECHANICS_MAX_CANDIDATES);
      const request = {
        model,
        max_completion_tokens: PRODUCTION_PROOF.short_max_completion_tokens,
        messages: [
          {
            role: "user",
            content: `Milk cloud mechanics request ${String(nonce).padStart(4, "0")}. Reply with only OK.`,
          },
        ],
      };
      const raw = Buffer.from(JSON.stringify(request));
      const { partition, requestSha256 } = mechanicsPartition(raw);
      const currentNonce = nonce;
      nonce += 1;
      if (counts[partition] >= target[partition]) continue;
      counts[partition] += 1;
      plan.push({ partition, request, requestSha256, raw, nonce: currentNonce });
    }
    assert.deepEqual(counts, target);
  }
  assert.equal(plan.length, PRODUCTION_PROOF.generated_mechanics_requests);
  assert.equal(new Set(plan.map((row) => row.requestSha256)).size, plan.length);
  assert.deepEqual(partitionCounts(plan.slice(0, 251)), MECHANICS_PHASES[0]);
  assert.deepEqual(partitionCounts(plan.slice(251)), MECHANICS_PHASES[1]);
  assert.deepEqual(partitionCounts(plan), { train: 63, dev: 91, calibration: 166 });
  return plan;
}

async function generatedMechanicsHealth(endpoint, expectedConfigSha256, transport) {
  try {
    const response = await transport(
      new Request(new URL("/healthz", endpoint), {
        headers: { accept: "application/json" },
        signal: AbortSignal.timeout(PRODUCTION_PROOF.generated_health_timeout_ms),
      }),
    );
    const raw = Buffer.from(await response.arrayBuffer());
    assert.ok(raw.length > 0 && raw.length <= MAX_HEALTH_BYTES);
    const value = JSON.parse(raw.toString("utf8"));
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.equal(
      response.headers.get("x-dragontales-config-sha256"),
      expectedConfigSha256,
    );
    assert.equal(value.config_sha256, expectedConfigSha256);
    assert.equal(value.status, "ok");
    assert.equal(value.capture, "available");
    assert.equal(value.candidate, "disabled");
    assert.equal(value.writer_alive, true);
    assert.equal(value.recent_persist_failure, false);
    return { responseSha256: sha256(raw), succeeded: true };
  } catch {
    return { responseSha256: null, succeeded: false };
  }
}

async function privateCredential(path, route) {
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
  const text = raw.subarray(0, -1).toString("utf8");
  const value = JSON.parse(text);
  assert.deepEqual(
    Object.keys(value).sort(),
    route
      ? ["api_key", "cohort_id", "model", "reasoning_effort"]
      : ["api_key", "cohort_id", "model"],
  );
  assert.match(
    value.api_key,
    /^dt_live_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}_[A-Za-z0-9._~-]{16,256}$/,
  );
  assertProofModel(value.model);
  assert.match(value.cohort_id, /^[A-Za-z0-9._~-]{1,128}$/);
  if (route) {
    assert.ok(
      value.reasoning_effort === null ||
        ["low", "medium", "high", "max"].includes(value.reasoning_effort),
    );
  }
  return value;
}

export function candidateRequest(credential) {
  assertProofModel(credential.model);
  const request = {
    max_completion_tokens: PRODUCTION_PROOF.short_max_completion_tokens,
    messages: [{ role: "user", content: "Reply with only OK." }],
    model: credential.model,
  };
  if (credential.reasoning_effort !== null) {
    request.reasoning_effort = credential.reasoning_effort;
  }
  return request;
}

export function saturationRequest(credential) {
  assertProofModel(credential.model);
  const request = {
    max_completion_tokens: PRODUCTION_PROOF.saturation_max_completion_tokens,
    messages: [
      {
        role: "user",
        content: `Write OK on ${SATURATION_LINE_COUNT} separate lines. Do not summarize or stop early.`,
      },
    ],
    model: credential.model,
    stream: true,
  };
  if (credential.reasoning_effort !== null) {
    request.reasoning_effort = credential.reasoning_effort;
  }
  return request;
}

export async function runBaselineSmoke(client, endpoint, credential) {
  assertProofModel(credential.model);
  const request = {
    max_completion_tokens: PRODUCTION_PROOF.short_max_completion_tokens,
    messages: [{ role: "user", content: "Reply with only OK." }],
    model: credential.model,
  };
  const { data, response } = await client.chat.completions.create(request).withResponse();
  const responseRaw = JSON.stringify(data);
  assert.ok(responseRaw.length > 0 && responseRaw.length <= MAX_RESPONSE_BYTES);
  assert.equal(response.status, 200);
  assert.equal(data.choices.length, 1);
  assert.equal(typeof data.choices[0]?.message?.content, "string");
  assert.ok(data.choices[0].message.content.length > 0);
  return {
    authenticated: true,
    baseline_request_count: 1,
    candidate_request_count: 0,
    choice_count: data.choices.length,
    content_retained: false,
    endpoint_sha256: sha256(endpoint.href),
    finish_reason: data.choices[0].finish_reason,
    http_status: response.status,
    max_completion_tokens: PRODUCTION_PROOF.short_max_completion_tokens,
    model: PRODUCTION_PROOF.model,
    proof_contract_sha256: PRODUCTION_PROOF_SHA256,
    proof_step: "deployment_baseline",
    request_sha256: sha256(canonical(request)),
    response_bytes: Buffer.byteLength(responseRaw),
    response_sha256: sha256(responseRaw),
    schema_version: "milk.official-openai-sdk-smoke.v2",
    sdk: "openai-node",
    sdk_request_count: 1,
    sdk_version: SDK_VERSION,
    succeeded: true,
    traffic_cohort_sha256: sha256(credential.cohort_id),
    traffic_key_sha256: sha256(credential.api_key),
  };
}

export async function runCandidateSmoke(client, endpoint, credential, expectedRouteRevision) {
  assert.match(expectedRouteRevision, SHA256);
  const request = candidateRequest(credential);
  const { data, response } = await client.chat.completions.create(request).withResponse();
  const responseRaw = JSON.stringify(data);
  assert.ok(responseRaw.length > 0 && responseRaw.length <= MAX_RESPONSE_BYTES);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("x-dragontales-route-revision"), expectedRouteRevision);
  assert.equal(response.headers.get("x-dragontales-route-target"), "candidate");
  const candidateSha256 = response.headers.get("x-dragontales-candidate-sha256");
  const artifactSha256 = response.headers.get("x-dragontales-artifact-sha256");
  const deploymentSha256 = response.headers.get("x-dragontales-deployment-sha256");
  assert.match(candidateSha256 ?? "", SHA256);
  assert.match(artifactSha256 ?? "", SHA256);
  assert.match(deploymentSha256 ?? "", SHA256);
  assert.equal(data.choices.length, 1);
  assert.equal(typeof data.choices[0]?.message?.content, "string");
  assert.ok(data.choices[0].message.content.length > 0);
  return {
    artifact_sha256: artifactSha256,
    authenticated: true,
    baseline_request_count: 0,
    candidate_request_count: 1,
    candidate_sha256: candidateSha256,
    choice_count: data.choices.length,
    content_retained: false,
    deployment_sha256: deploymentSha256,
    endpoint_sha256: sha256(endpoint.href),
    finish_reason: data.choices[0].finish_reason,
    http_status: response.status,
    max_completion_tokens: PRODUCTION_PROOF.short_max_completion_tokens,
    model: PRODUCTION_PROOF.model,
    proof_contract_sha256: PRODUCTION_PROOF_SHA256,
    proof_step: "candidate",
    request_sha256: sha256(canonical(request)),
    response_bytes: Buffer.byteLength(responseRaw),
    response_sha256: sha256(responseRaw),
    route_revision: expectedRouteRevision,
    route_target: "candidate",
    schema_version: "milk.official-openai-sdk-route-smoke.v2",
    sdk: "openai-node",
    sdk_request_count: 1,
    sdk_version: SDK_VERSION,
    succeeded: true,
    traffic_cohort_sha256: sha256(credential.cohort_id),
    traffic_key_sha256: sha256(credential.api_key),
  };
}

export async function runSaturationFallbackSmoke(
  client,
  endpoint,
  credential,
  expectedRouteRevision,
) {
  assert.match(expectedRouteRevision, SHA256);
  const request = saturationRequest(credential);
  let candidate;
  let fallback;
  try {
    candidate = await client.chat.completions.create(request).withResponse();
    assert.equal(candidate.response.status, 200);
    assert.equal(
      candidate.response.headers.get("x-dragontales-route-revision"),
      expectedRouteRevision,
    );
    assert.equal(candidate.response.headers.get("x-dragontales-route-target"), "candidate");
    const candidateSha256 = candidate.response.headers.get(
      "x-dragontales-candidate-sha256",
    );
    const artifactSha256 = candidate.response.headers.get(
      "x-dragontales-artifact-sha256",
    );
    const deploymentSha256 = candidate.response.headers.get(
      "x-dragontales-deployment-sha256",
    );
    assert.match(candidateSha256 ?? "", SHA256);
    assert.match(artifactSha256 ?? "", SHA256);
    assert.match(deploymentSha256 ?? "", SHA256);
    assert.equal(typeof candidate.data?.controller?.abort, "function");

    fallback = await client.chat.completions.create(request).withResponse();
    assert.equal(fallback.response.status, 200);
    assert.equal(
      fallback.response.headers.get("x-dragontales-route-revision"),
      expectedRouteRevision,
    );
    assert.equal(fallback.response.headers.get("x-dragontales-route-target"), "openai");
    assert.equal(typeof fallback.data?.controller?.abort, "function");

    return {
      artifact_sha256: artifactSha256,
      authenticated: true,
      baseline_request_count: 1,
      candidate_http_status: candidate.response.status,
      candidate_request_count: 1,
      candidate_route_target: "candidate",
      candidate_sha256: candidateSha256,
      content_retained: false,
      deployment_sha256: deploymentSha256,
      endpoint_sha256: sha256(endpoint.href),
      fallback_http_status: fallback.response.status,
      fallback_route_target: "openai",
      max_completion_tokens: PRODUCTION_PROOF.saturation_max_completion_tokens,
      model: PRODUCTION_PROOF.model,
      proof_contract_sha256: PRODUCTION_PROOF_SHA256,
      proof_step: "saturation_fallback",
      request_sha256: sha256(canonical(request)),
      route_revision: expectedRouteRevision,
      schema_version: "milk.official-openai-sdk-saturation-fallback-smoke.v2",
      sdk: "openai-node",
      sdk_request_count: 2,
      sdk_version: SDK_VERSION,
      succeeded: true,
      traffic_cohort_sha256: sha256(credential.cohort_id),
      traffic_key_sha256: sha256(credential.api_key),
    };
  } finally {
    fallback?.data?.controller?.abort();
    candidate?.data?.controller?.abort();
  }
}

export async function runGeneratedMechanics(
  endpoint,
  credential,
  expectedConfigSha256,
  transport = globalThis.fetch,
) {
  assert.match(expectedConfigSha256, SHA256);
  assertProofModel(credential.model);
  const toolSha256 = sha256(await readFile(new URL(import.meta.url)));
  const preflightHealth = await generatedMechanicsHealth(
    endpoint,
    expectedConfigSha256,
    transport,
  );
  assert.equal(preflightHealth.succeeded, true);
  const plan = generatedMechanicsPlan(credential.model);
  const expected = new Map(plan.map((row) => [row.requestSha256, row]));
  const transported = new Set();
  const client = new OpenAI({
    apiKey: credential.api_key,
    baseURL: endpoint.href,
    maxRetries: 0,
    timeout: PRODUCTION_PROOF.generated_request_timeout_ms,
    fetch: async (input, init) => {
      const outgoing = new Request(input, init);
      const raw = Buffer.from(await outgoing.clone().arrayBuffer());
      const { partition, requestSha256 } = mechanicsPartition(raw);
      const planned = expected.get(requestSha256);
      assert.ok(planned);
      assert.equal(raw.equals(planned.raw), true);
      assert.equal(partition, planned.partition);
      assert.equal(transported.has(requestSha256), false);
      const response = await transport(outgoing);
      transported.add(requestSha256);
      return response;
    },
  });
  const observations = new Array(plan.length);
  let next = 0;
  const startedAt = new Date().toISOString();
  async function worker() {
    while (next < plan.length) {
      const index = next;
      next += 1;
      const planned = plan[index];
      let httpStatus = null;
      try {
        const { data, response } = await client.chat.completions
          .create(planned.request)
          .withResponse();
        const responseRaw = JSON.stringify(data);
        httpStatus = response.status;
        assert.ok(
          Buffer.byteLength(responseRaw) > 0 &&
            Buffer.byteLength(responseRaw) <= MAX_RESPONSE_BYTES,
        );
        assert.equal(response.status, 200);
        assert.equal(response.headers.get("x-dragontales-capture-intent"), "selected");
        assert.equal(
          response.headers.get("x-dragontales-route-revision"),
          MECHANICS_ROUTE_REVISION,
        );
        assert.equal(response.headers.get("x-dragontales-route-target"), "openai");
        const traceId = response.headers.get("x-dragontales-trace-id");
        assert.match(traceId ?? "", UUID);
        assert.equal(data.choices.length, 1);
        assert.equal(typeof data.choices[0]?.message?.content, "string");
        assert.ok(data.choices[0].message.content.length > 0);
        observations[index] = {
          httpStatus: response.status,
          partition: planned.partition,
          requestSha256: planned.requestSha256,
          responseSha256: sha256(responseRaw),
          traceId,
        };
      } catch (error) {
        observations[index] = {
          httpStatus: httpStatus ?? (Number.isInteger(error?.status) ? error.status : null),
          partition: planned.partition,
          requestSha256: planned.requestSha256,
        };
      }
    }
  }
  await Promise.all(Array.from({ length: MECHANICS_CONCURRENCY }, worker));
  const successful = observations.filter((value) => value.responseSha256);
  const traceIds = successful.map((value) => value.traceId);
  const statusCounts = {};
  for (const observation of observations) {
    const status = observation.httpStatus === null ? "none" : String(observation.httpStatus);
    statusCounts[status] = (statusCounts[status] ?? 0) + 1;
  }
  const requestSet = plan.map((row) => ({
    partition: row.partition,
    request_sha256: row.requestSha256,
  }));
  const responseSet = successful
    .map((row) => ({
      request_sha256: row.requestSha256,
      response_sha256: row.responseSha256,
    }))
    .sort((left, right) => left.request_sha256.localeCompare(right.request_sha256));
  const uniqueTraceCount = new Set(traceIds).size;
  const postflightHealth = await generatedMechanicsHealth(
    endpoint,
    expectedConfigSha256,
    transport,
  );
  const succeeded =
    successful.length === plan.length &&
    transported.size === plan.length &&
    uniqueTraceCount === plan.length &&
    postflightHealth.succeeded;
  return {
    schema_version: "milk.official-openai-sdk-generated-mechanics.v2",
    eval_id: MECHANICS_EVAL_ID,
    gateway_config_sha256: expectedConfigSha256,
    tool_sha256: toolSha256,
    sdk: "openai-node",
    sdk_version: SDK_VERSION,
    endpoint_sha256: sha256(endpoint.href),
    model: PRODUCTION_PROOF.model,
    model_sha256: sha256(credential.model),
    proof_contract_sha256: PRODUCTION_PROOF_SHA256,
    proof_step: "generated_mechanics",
    request_timeout_ms: PRODUCTION_PROOF.generated_request_timeout_ms,
    traffic_cohort_sha256: sha256(credential.cohort_id),
    concurrency: MECHANICS_CONCURRENCY,
    candidates_scanned: plan.at(-1).nonce + 1,
    planned: plan.length,
    attempted: observations.length,
    sdk_request_count: observations.length,
    baseline_request_count: observations.length,
    candidate_request_count: 0,
    max_completion_tokens: PRODUCTION_PROOF.short_max_completion_tokens,
    successful: successful.length,
    failed: observations.length - successful.length,
    transported: transported.size,
    unique_trace_ids: uniqueTraceCount,
    first_partition_counts: partitionCounts(plan.slice(0, 251)),
    retry_partition_counts: partitionCounts(plan.slice(251)),
    total_partition_counts: partitionCounts(plan),
    http_status_counts: statusCounts,
    request_set_sha256: sha256(canonical(requestSet)),
    response_set_sha256: sha256(canonical(responseSet)),
    trace_set_sha256: sha256(canonical(traceIds.slice().sort())),
    route_revision: MECHANICS_ROUTE_REVISION,
    preflight_health_sha256: preflightHealth.responseSha256,
    postflight_health_sha256: postflightHealth.responseSha256,
    postflight_health_succeeded: postflightHealth.succeeded,
    content_retained: false,
    started_at: startedAt,
    completed_at: new Date().toISOString(),
    succeeded,
  };
}

async function main() {
  assert.ok(
    process.argv.length === 4 ||
      process.argv.length === 5 ||
      process.argv.length === 6,
  );
  const generatedMechanics =
    process.argv.length === 6 && process.argv[5] === "--generated-mechanics";
  const saturationFallback =
    process.argv.length === 6 && process.argv[5] === "--saturation-fallback";
  if (process.argv.length === 6) assert.ok(generatedMechanics || saturationFallback);
  const route = process.argv.length >= 5 && !generatedMechanics;
  const endpoint = new URL(process.argv[2]);
  assert.equal(endpoint.protocol, "https:");
  assert.equal(endpoint.hostname, "api.dragontales.milkinfrastructure.com");
  assert.equal(endpoint.pathname, "/v1");
  assert.equal(endpoint.search, "");
  assert.equal(endpoint.hash, "");
  assert.equal(endpoint.username, "");
  assert.equal(endpoint.password, "");

  const packageMetadata = JSON.parse(
    await readFile(new URL("../node_modules/openai/package.json", import.meta.url), "utf8"),
  );
  assert.equal(packageMetadata.version, SDK_VERSION);
  const credential = await privateCredential(process.argv[3], route);
  if (generatedMechanics) {
    const receipt = await runGeneratedMechanics(
      endpoint,
      credential,
      process.argv[4],
    );
    process.stdout.write(`${canonical(receipt)}\n`);
    if (!receipt.succeeded) process.exitCode = 70;
    return;
  }
  const client = new OpenAI({
    apiKey: credential.api_key,
    baseURL: endpoint.href,
    maxRetries: 0,
    timeout: 120_000,
  });
  const receipt = saturationFallback
    ? await runSaturationFallbackSmoke(client, endpoint, credential, process.argv[4])
    : route
      ? await runCandidateSmoke(client, endpoint, credential, process.argv[4])
      : await runBaselineSmoke(client, endpoint, credential);
  process.stdout.write(`${canonical(receipt)}\n`);
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main().catch(() => {
    process.stderr.write("openai-production-smoke: failed\n");
    process.exitCode = 70;
  });
}
