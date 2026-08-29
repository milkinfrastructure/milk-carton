import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open, readFile } from "node:fs/promises";
import { isAbsolute } from "node:path";
import { pathToFileURL } from "node:url";

import OpenAI from "openai";

const SDK_VERSION = "6.33.0";
const MAX_CREDENTIAL_BYTES = 8_192;
const MAX_RESPONSE_BYTES = 65_536;
const SHA256 = /^[0-9a-f]{64}$/;

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
  assert.match(value.model, /^[A-Za-z0-9][A-Za-z0-9._/:~-]{0,255}$/);
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
  const request = {
    messages: [{ role: "user", content: "Reply with only OK." }],
    model: credential.model,
  };
  if (credential.reasoning_effort !== null) {
    request.reasoning_effort = credential.reasoning_effort;
  }
  return request;
}

export function saturationRequest(credential) {
  const request = {
    messages: [
      {
        role: "user",
        content: "Write OK on 4096 separate lines. Do not summarize or stop early.",
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
  const request = {
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
    choice_count: data.choices.length,
    content_retained: false,
    endpoint_sha256: sha256(endpoint.href),
    finish_reason: data.choices[0].finish_reason,
    http_status: response.status,
    request_sha256: sha256(canonical(request)),
    response_bytes: Buffer.byteLength(responseRaw),
    response_sha256: sha256(responseRaw),
    schema_version: "milk.official-openai-sdk-smoke.v1",
    sdk: "openai-node",
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
    candidate_sha256: candidateSha256,
    choice_count: data.choices.length,
    content_retained: false,
    deployment_sha256: deploymentSha256,
    endpoint_sha256: sha256(endpoint.href),
    finish_reason: data.choices[0].finish_reason,
    http_status: response.status,
    request_sha256: sha256(canonical(request)),
    response_bytes: Buffer.byteLength(responseRaw),
    response_sha256: sha256(responseRaw),
    route_revision: expectedRouteRevision,
    route_target: "candidate",
    schema_version: "milk.official-openai-sdk-route-smoke.v1",
    sdk: "openai-node",
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
      candidate_http_status: candidate.response.status,
      candidate_route_target: "candidate",
      candidate_sha256: candidateSha256,
      content_retained: false,
      deployment_sha256: deploymentSha256,
      endpoint_sha256: sha256(endpoint.href),
      fallback_http_status: fallback.response.status,
      fallback_route_target: "openai",
      request_sha256: sha256(canonical(request)),
      route_revision: expectedRouteRevision,
      schema_version: "milk.official-openai-sdk-saturation-fallback-smoke.v1",
      sdk: "openai-node",
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

async function main() {
  assert.ok(
    process.argv.length === 4 ||
      process.argv.length === 5 ||
      process.argv.length === 6,
  );
  const saturationFallback = process.argv.length === 6;
  if (saturationFallback) assert.equal(process.argv[5], "--saturation-fallback");
  const route = process.argv.length >= 5;
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
  const client = new OpenAI({
    apiKey: credential.api_key,
    baseURL: endpoint.href,
    maxRetries: 0,
    timeout: 15_000,
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
