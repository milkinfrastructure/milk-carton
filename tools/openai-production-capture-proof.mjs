import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";
import { readCredential, runProductionPath } from "./openai-production-path-workload.mjs";
const execute = promisify(execFile);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256 = /^[0-9a-f]{64}$/;
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
async function inspectStats(scopeId, rows, readStats, keys) {
  const delta = Object.fromEntries(keys.map((key) => [key, 0]));
  const objects = [];
  for (const row of rows) {
    assert.ok(row.key.startsWith(`${prefix(scopeId)}stats/`) && row.size <= 1024 * 1024);
    const raw = await readStats(row);
    assert.ok(Buffer.isBuffer(raw) && raw.length === row.size);
    const shard = JSON.parse(raw.toString("utf8"));
    assert.equal(shard.schema_version, "milk.stats-shard.v1");
    assert.equal(shard.scope_id, scopeId);
    assert.equal(shard.inclusion_probability_basis_points, 1000);
    for (const key of keys) {
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
    interval, timing, workload = runProductionPath,
    waitForStats = () => sleep(5_000),
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
  const workloadReceipt = await workload(endpoint, credential, fetch, interval, timing);
  assert.equal(workloadReceipt.schema_version, "milk.official-openai-sdk-production-path.v3");
  assert.equal(workloadReceipt.status, "succeeded");
  assert.equal(workloadReceipt.counts.invalid_key_requests, 1);
  assert.equal(workloadReceipt.counts.observed_requests, 103);
  assert.equal(workloadReceipt.counts.chat_completions_requests, 52);
  assert.equal(workloadReceipt.counts.responses_requests, 51);
  assert.equal(workloadReceipt.counts.streaming_requests, 1);
  assert.equal(workloadReceipt.counts.sdk_requests, 104);
  assert.equal(workloadReceipt.invalid_auth.http_status, 401);
  assert.match(workloadReceipt.invalid_auth.trace_id, UUID);
  const invalidTraceId = workloadReceipt.invalid_auth.trace_id;
  const validateTraces = (values) => {
    assert.ok(Array.isArray(values) && values.length <= 103);
    for (const value of values) assert.match(value, UUID);
    assert.deepEqual(values, [...values].sort());
    assert.equal(new Set(values).size, values.length);
    return values;
  };
  const selectedTraces = validateTraces(workloadReceipt.selected_trace_ids);
  const unselectedTraces = validateTraces(workloadReceipt.not_selected_trace_ids);
  assert.equal(selectedTraces.length, workloadReceipt.counts.selected);
  assert.equal(unselectedTraces.length, workloadReceipt.counts.not_selected);
  assert.ok(selectedTraces.length > 0);
  assert.equal(selectedTraces.length + unselectedTraces.length, 103);
  const traceIds = [...selectedTraces, ...unselectedTraces].sort();
  assert.equal(new Set(traceIds).size, 103);
  assert.equal(traceIds.includes(invalidTraceId), false);
  assert.equal(workloadReceipt.counts.unique_trace_ids, 103);
  assert.equal(workloadReceipt.hashes.trace_set_sha256, sha256(canonical(traceIds)));
  assert.equal(
    workloadReceipt.hashes.selected_trace_set_sha256,
    sha256(canonical(selectedTraces)),
  );
  assert.equal(
    workloadReceipt.hashes.not_selected_trace_set_sha256,
    sha256(canonical(unselectedTraces)),
  );
  assert.equal(workloadReceipt.streaming.requests, 1);
  assert.ok(Number.isSafeInteger(workloadReceipt.streaming.chunk_count));
  assert.ok(workloadReceipt.streaming.chunk_count > 0 && workloadReceipt.streaming.chunk_count <= 512);
  assert.ok(Number.isSafeInteger(workloadReceipt.streaming.usage_chunks));
  assert.ok(workloadReceipt.streaming.usage_chunks > 0);
  assert.ok(workloadReceipt.streaming.usage_chunks <= workloadReceipt.streaming.chunk_count);
  assert.ok(Number.isSafeInteger(workloadReceipt.streaming.response_bytes));
  assert.ok(workloadReceipt.streaming.response_bytes > 0 && workloadReceipt.streaming.response_bytes <= 65_536);
  assert.match(workloadReceipt.streaming.chunk_sha256, SHA256);
  assert.equal(workloadReceipt.streaming.fully_consumed, true);
  assert.match(workloadReceipt.streaming.trace_id, UUID);
  assert.ok(selectedTraces.includes(workloadReceipt.streaming.trace_id));
  const minimumDelta = {
    observed: 103,
    chat_completions: 52,
    responses: 51,
    streaming: 1,
    request_parse_success: 103,
    eligible: 103,
    selected: selectedTraces.length,
    captured: selectedTraces.length,
    queued: 103,
    traces_persisted: selectedTraces.length,
    not_selected: unselectedTraces.length,
    status_2xx: 103,
  };
  const expectedTraffic = selectedTraces.map((id) => trafficKey(targetScopeId, id)).sort();
  const forbiddenTargetTraces = [invalidTraceId, ...unselectedTraces];
  const ownedTraces = [invalidTraceId, ...traceIds];
  let complete;
  for (let attempt = 0; attempt < 25 && !complete; attempt += 1) {
    await waitForStats(attempt);
    const current = await snapshot();
    for (const id of sentinelScopeIds) {
      for (const row of current.get(id)) {
        assert.equal(ownedTraces.some((traceId) => row.key.includes(traceId)), false);
      }
    }
    const target = current.get(targetScopeId);
    for (const row of target) {
      assert.equal(forbiddenTargetTraces.some((traceId) => row.key.includes(traceId)), false);
    }
    const targetByKey = new Map(target.map((row) => [row.key, row]));
    const traffic = expectedTraffic.map((key) => targetByKey.get(key)).filter(Boolean);
    const added = additions(before.get(targetScopeId), target);
    const stats = added.filter((row) => row.key.startsWith(`${prefix(targetScopeId)}stats/`));
    if (traffic.length !== expectedTraffic.length || stats.length === 0) continue;
    assert.deepEqual(traffic.map((row) => row.key).sort(), expectedTraffic);
    const inspected = await inspectStats(
      targetScopeId, stats, readStats, Object.keys(minimumDelta),
    );
    let pending = false;
    for (const [key, minimum] of Object.entries(minimumDelta)) {
      pending ||= inspected.delta[key] < minimum;
    }
    if (!pending) complete = { current, inspected, stats, traffic };
  }
  assert.ok(complete);
  const streamingTrafficKey = trafficKey(targetScopeId, workloadReceipt.streaming.trace_id);
  assert.ok(complete.traffic.some((row) => row.key === streamingTrafficKey));
  const receipt = {
    schema_version: "milk.production-capture-proof.v3", status: "succeeded",
    scope_id: targetScopeId,
    intents: {
      observed: 103,
      selected: selectedTraces.length,
      not_selected: unselectedTraces.length,
    },
    sdk: {
      counts: workloadReceipt.counts,
      http_status_counts: workloadReceipt.http_status_counts,
      name: workloadReceipt.sdk,
      version: workloadReceipt.sdk_version,
    },
    selected_traces: selectedTraces,
    not_selected_traces: unselectedTraces,
    streaming: { ...workloadReceipt.streaming, traffic_key: streamingTrafficKey },
    invalid_auth: {
      http_status: 401, trace_id: invalidTraceId,
      owned_trace_objects_written: 0,
    },
    traffic: { objects: complete.traffic, ...manifest(complete.traffic) },
    stats: { attribution: "scope_aggregate_lower_bound", minimum: minimumDelta,
      inclusion_probability_basis_points: 1000,
      delta: complete.inspected.delta, objects: complete.inspected.objects,
      ...manifest(complete.inspected.objects) },
    sentinels: sentinelScopeIds.map((id) => ({
      scope_id: id, owned_trace_objects_written: 0,
      before: manifest(before.get(id)), after_workload: manifest(complete.current.get(id)),
    })),
    background: {
      target_before: manifest(before.get(targetScopeId)),
      target_after: manifest(complete.current.get(targetScopeId)),
    },
    hashes: {
      workload_receipt_sha256: sha256(canonical(workloadReceipt)),
      trace_set_sha256: workloadReceipt.hashes.trace_set_sha256,
      selected_trace_set_sha256: workloadReceipt.hashes.selected_trace_set_sha256,
      not_selected_trace_set_sha256: workloadReceipt.hashes.not_selected_trace_set_sha256,
      request_set_sha256: workloadReceipt.hashes.request_set_sha256,
      response_set_sha256: workloadReceipt.hashes.response_set_sha256,
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
  main().catch((error) => {
    const status = Number.isInteger(error?.status) ? ` status=${error.status}` : "";
    const kind = /^[A-Za-z][A-Za-z0-9]*$/.test(error?.name ?? "")
      ? ` kind=${error.name}` : "";
    const stage = /^[a-z0-9:_-]{1,128}$/.test(error?.milkStage ?? "")
      ? ` stage=${error.milkStage}` : "";
    process.stderr.write(`openai-production-capture-proof: failed${status}${kind}${stage}\n`);
    process.exitCode = 70;
  });
}
