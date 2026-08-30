import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";
import OpenAI from "openai";
import { readCredential, runProductionPath } from "./openai-production-path-workload.mjs";
const execute = promisify(execFile);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const EXPECTED = Object.freeze({
  observed: 102, chat_completions: 51, responses: 51, request_parse_success: 102,
  eligible: 102, selected: 102, captured: 102, queued: 102, traces_persisted: 102,
  request_parse_failure: 0, oversized: 0, interrupted: 0, capture_failed: 0, dropped: 0,
  not_selected: 0, trace_persist_failures: 0, stats_persist_failures: 0, status_2xx: 102, status_4xx: 0, status_5xx: 0, status_other: 0, status_missing: 0,
});
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => (
      `${JSON.stringify(key)}:${canonical(value[key])}`
    )).join(",")}}`;
  }
  return JSON.stringify(value);
}
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
function scope(value) {
  assert.match(value, UUID);
  assert.notEqual(value, "00000000-0000-0000-0000-000000000000");
  return value;
}
const prefix = (value) => `milk/v1/scopes/${scope(value)}/`;
const manifest = (rows) => ({ count: rows.length, sha256: sha256(canonical(rows)) });
function normalize(rows, root) {
  assert.ok(Array.isArray(rows) && rows.length <= 100_000);
  const result = rows.map((row) => ({
    etag: row.etag ?? row.ETag,
    key: row.key ?? row.Key,
    last_modified: row.last_modified ?? row.LastModified,
    size: row.size ?? row.Size,
  })).sort((a, b) => a.key < b.key ? -1 : Number(a.key > b.key));
  for (const row of result) {
    assert.ok(row.key.startsWith(root) && typeof row.etag === "string");
    assert.ok(Number.isSafeInteger(row.size) && row.size >= 0);
    assert.equal(Number.isNaN(Date.parse(row.last_modified)), false);
  }
  assert.equal(new Set(result.map((row) => row.key)).size, result.length);
  return result;
}
function additions(before, after) {
  const current = new Map(after.map((row) => [row.key, row]));
  for (const row of before) assert.deepEqual(current.get(row.key), row);
  const prior = new Set(before.map((row) => row.key));
  return after.filter((row) => !prior.has(row.key));
}
function trafficKey(scopeId, traceId) {
  assert.match(traceId, UUID);
  assert.equal(traceId[14], "7");
  const milliseconds = Number(BigInt(`0x${traceId.replaceAll("-", "").slice(0, 12)}`));
  const hour = new Date(milliseconds).toISOString().slice(0, 13)
    .replaceAll("-", "/").replace("T", "/");
  return `${prefix(scopeId)}traffic/${hour}/${traceId}.json.zst`;
}
async function isolated401(endpoint, model, fetch) {
  const client = new OpenAI({
    apiKey: "invalid-production-path-key", baseURL: endpoint.href,
    fetch, maxRetries: 0, timeout: 60_000,
  });
  try {
    await client.chat.completions.create({
      max_completion_tokens: 1,
      messages: [{ role: "user", content: "authentication check" }], model,
    });
  } catch (error) {
    assert.ok(error instanceof OpenAI.AuthenticationError);
    assert.equal(error.status, 401);
    return 401;
  }
  assert.fail("invalid key was accepted");
}
async function inspectStats(scopeId, rows, readStats) {
  const delta = Object.fromEntries(Object.keys(EXPECTED).map((key) => [key, 0]));
  const objects = [];
  for (const row of rows) {
    assert.ok(row.key.startsWith(`${prefix(scopeId)}stats/`) && row.size <= 1024 * 1024);
    const raw = await readStats(row);
    assert.ok(Buffer.isBuffer(raw) && raw.length === row.size);
    const shard = JSON.parse(raw.toString("utf8"));
    assert.equal(shard.schema_version, "milk.stats-shard.v1");
    assert.equal(shard.scope_id, scopeId);
    for (const key of Object.keys(EXPECTED)) {
      assert.ok(Number.isSafeInteger(shard.values[key]) && shard.values[key] >= 0);
      delta[key] += shard.values[key];
    }
    objects.push({ ...row, body_sha256: sha256(raw) });
  }
  return { delta, objects };
}
export async function runCaptureProof(options) {
  let { targetScopeId, sentinelScopeIds } = options;
  const {
    endpoint, credential, listScope, readStats, fetch = globalThis.fetch,
    interval, timing, invalidRequest = isolated401, workload = runProductionPath,
    waitAfter401 = () => sleep(65_000), waitForStats = () => sleep(5_000),
  } = options;
  targetScopeId = scope(targetScopeId);
  sentinelScopeIds = sentinelScopeIds.map(scope).sort();
  assert.ok(sentinelScopeIds.length > 0 && new Set(sentinelScopeIds).size === sentinelScopeIds.length);
  assert.equal(sentinelScopeIds.includes(targetScopeId), false);
  const scopes = [targetScopeId, ...sentinelScopeIds];
  const snapshot = async () => new Map(await Promise.all(scopes.map(async (id) => (
    [id, normalize(await listScope(id), prefix(id))]
  ))));
  const before = await snapshot();
  assert.equal(await invalidRequest(endpoint, credential.model, fetch), 401);
  await waitAfter401();
  const after401 = await snapshot();
  for (const id of scopes) assert.deepEqual(after401.get(id), before.get(id));
  const workloadReceipt = await workload(endpoint, credential, fetch, interval, timing);
  assert.equal(workloadReceipt.schema_version, "milk.official-openai-sdk-production-path.v1");
  assert.equal(workloadReceipt.status, "succeeded");
  assert.equal(workloadReceipt.counts.invalid_key_requests, 1);
  const traceIds = [...workloadReceipt.trace_ids].sort();
  assert.equal(traceIds.length, 102);
  assert.equal(new Set(traceIds).size, 102);
  assert.equal(workloadReceipt.hashes.trace_set_sha256, sha256(canonical(traceIds)));
  const expectedTraffic = traceIds.map((id) => trafficKey(targetScopeId, id)).sort();
  let complete;
  for (let attempt = 0; attempt < 25 && !complete; attempt += 1) {
    await waitForStats(attempt);
    const current = await snapshot();
    for (const id of sentinelScopeIds) assert.deepEqual(current.get(id), after401.get(id));
    const added = additions(after401.get(targetScopeId), current.get(targetScopeId));
    const traffic = added.filter((row) => row.key.startsWith(`${prefix(targetScopeId)}traffic/`));
    const stats = added.filter((row) => row.key.startsWith(`${prefix(targetScopeId)}stats/`));
    const keys = traffic.map((row) => row.key).sort();
    assert.deepEqual(keys.filter((key) => !expectedTraffic.includes(key)), []);
    if (keys.length !== 102 || stats.length === 0) continue;
    assert.deepEqual(keys, expectedTraffic);
    const inspected = await inspectStats(targetScopeId, stats, readStats);
    let pending = false;
    for (const [key, expected] of Object.entries(EXPECTED)) {
      assert.ok(inspected.delta[key] <= expected);
      pending ||= inspected.delta[key] < expected;
    }
    if (!pending) complete = { current, inspected, stats, traffic };
  }
  assert.ok(complete);
  const receipt = {
    schema_version: "milk.production-capture-proof.v1", status: "succeeded",
    scope_id: targetScopeId,
    invalid_auth: {
      http_status: 401, object_changes: 0,
      before: manifest(before.get(targetScopeId)), after: manifest(after401.get(targetScopeId)),
    },
    traffic: { objects: complete.traffic, ...manifest(complete.traffic) },
    stats: { delta: complete.inspected.delta, objects: complete.inspected.objects,
      ...manifest(complete.inspected.objects) },
    sentinels: sentinelScopeIds.map((id) => ({
      scope_id: id, before: manifest(before.get(id)), after_401: manifest(after401.get(id)),
      after_workload: manifest(complete.current.get(id)),
    })),
    hashes: {
      workload_receipt_sha256: sha256(canonical(workloadReceipt)),
      trace_set_sha256: workloadReceipt.hashes.trace_set_sha256,
      tool_sha256: sha256(await readFile(new URL(import.meta.url))),
    },
    evidence: { traffic_bodies_read: false, prompt_bytes_retained: false,
      response_bytes_retained: false, secret_values_retained: false },
  };
  const raw = canonical(receipt);
  for (const value of [credential.api_key, credential.cohort_id, credential.model]) {
    assert.equal(raw.includes(value), false);
  }
  return receipt;
}
function r2(environment) {
  const required = (name) => {
    const value = environment[`MILK_CAPTURE_PROOF_R2_${name}`];
    assert.ok(value && !/\s/.test(value));
    return value;
  };
  const account = required("ACCOUNT_ID");
  assert.match(account, /^[0-9a-f]{32}$/);
  const aws = environment.MILK_CAPTURE_PROOF_AWS || "aws";
  const bucket = required("BUCKET");
  const endpoint = `https://${account}.r2.cloudflarestorage.com`;
  const env = {
    ...environment, AWS_ACCESS_KEY_ID: required("ACCESS_KEY_ID"), AWS_SECRET_ACCESS_KEY: required("SECRET_ACCESS_KEY"),
    AWS_SESSION_TOKEN: environment.MILK_CAPTURE_PROOF_R2_SESSION_TOKEN || "",
    AWS_REGION: "auto", AWS_EC2_METADATA_DISABLED: "true",
  };
  const command = async (args, maxBuffer = 64 * 1024 * 1024) => {
    try {
      return await execute(aws, [
        "--no-cli-pager", "--endpoint-url", endpoint, "--region", "auto", ...args,
      ], { encoding: "utf8", env, maxBuffer, timeout: 60_000 });
    } catch {
      throw new Error("R2 read failed");
    }
  };
  return {
    async list(scopeId) {
      const result = await command([
        "s3api", "list-objects-v2", "--bucket", bucket,
        "--prefix", prefix(scopeId), "--output", "json",
      ]);
      return JSON.parse(result.stdout).Contents ?? [];
    },
    async stats(row) {
      assert.ok(row.key.includes("/stats/"));
      const directory = await mkdtemp(join(tmpdir(), "milk-capture-proof-"));
      const output = join(directory, "stats.json");
      try {
        await command([
          "s3api", "get-object", "--bucket", bucket, "--key", row.key,
          "--output", "json", output,
        ], 1024 * 1024);
        return await readFile(output);
      } finally {
        await rm(directory, { force: true, recursive: true });
      }
    },
  };
}
async function main() {
  assert.ok(process.argv.length >= 6);
  const endpoint = new URL(process.argv[2]);
  assert.equal(endpoint.protocol, "https:"); assert.equal(endpoint.pathname, "/v1");
  assert.equal(endpoint.host, endpoint.hostname);
  assert.equal(endpoint.search + endpoint.hash + endpoint.username + endpoint.password, "");
  const credential = await readCredential(process.argv[3]);
  const store = r2(process.env);
  const receipt = await runCaptureProof({
    endpoint, credential, targetScopeId: process.argv[4],
    sentinelScopeIds: process.argv.slice(5),
    listScope: (id) => store.list(id), readStats: (row) => store.stats(row),
    interval: process.env.MILK_PRODUCTION_PATH_REQUEST_INTERVAL_MS,
  });
  process.stdout.write(`${canonical(receipt)}\n`);
}
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main().catch(() => {
    process.stderr.write("openai-production-capture-proof: failed\n");
    process.exitCode = 70;
  });
}
