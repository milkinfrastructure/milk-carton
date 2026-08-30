import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { runCaptureProof } from "./openai-production-capture-proof.mjs";

const target = "10000000-0000-4000-8000-000000000001";
const sentinel = "20000000-0000-4000-8000-000000000002";
const credential = {
  api_key: "milk_live_00000000-0000-4000-8000-000000000001_private_secret_123456",
  cohort_id: "private-proof-cohort",
  model: "private-proof-model",
};
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") return `{${Object.keys(value).sort()
    .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const started = Date.parse("2026-08-30T12:00:00.000Z");
function traceId(index) {
  const time = BigInt(started + index).toString(16).padStart(12, "0");
  return `${time.slice(0, 8)}-${time.slice(8)}-7000-8000-${index.toString(16).padStart(12, "0")}`;
}
const traces = Array.from({ length: 102 }, (_, index) => traceId(index)).sort();
function metadata(key, size = 1) {
  return { etag: `"${sha256(key)}"`, key, last_modified: "2026-08-30T12:02:00Z", size };
}
const base = [metadata(`milk/v1/scopes/${target}/control/existing.json`)];
const sentinelRows = [metadata(`milk/v1/scopes/${sentinel}/control/existing.json`)];
const traffic = traces.map((id) => metadata(
  `milk/v1/scopes/${target}/traffic/2026/08/30/12/${id}.json.zst`, 256,
));
const values = {
  observed: 102, chat_completions: 51, responses: 51, request_parse_success: 102,
  eligible: 102, selected: 102, captured: 102, queued: 102, traces_persisted: 102,
  request_parse_failure: 0, oversized: 0, interrupted: 0, capture_failed: 0,
  dropped: 0, not_selected: 0, trace_persist_failures: 0, stats_persist_failures: 0,
  status_2xx: 102, status_4xx: 0, status_5xx: 0, status_other: 0, status_missing: 0,
};
const statsKey = `milk/v1/scopes/${target}/stats/2026/08/30/12/30000000-0000-4000-8000-000000000003/40000000-0000-7000-8000-000000000004.json`;
const statsBody = Buffer.from(JSON.stringify({
  schema_version: "milk.stats-shard.v1", scope_id: target, values,
}));
const stats = metadata(statsKey, statsBody.length);
const events = [];
let phase = "before";
const listScope = async (scope) => {
  events.push(`list:${phase}:${scope}`);
  if (scope === sentinel) return sentinelRows;
  return phase === "valid" ? [...base, ...traffic, stats] : base;
};
const readStats = async (row) => {
  events.push(`read:${row.key}`);
  assert.equal(row.key, statsKey);
  return statsBody;
};
const invalidRequest = async () => {
  events.push("invalid");
  return 401;
};
const workload = async () => {
  events.push("workload");
  return {
    schema_version: "milk.official-openai-sdk-production-path.v1",
    status: "succeeded",
    counts: { invalid_key_requests: 1 },
    hashes: { trace_set_sha256: sha256(canonical(traces)) },
    trace_ids: traces,
  };
};

const receipt = await runCaptureProof({
  endpoint: new URL("http://127.0.0.1:1/v1"), credential,
  targetScopeId: target, sentinelScopeIds: [sentinel], listScope, readStats,
  invalidRequest, workload,
  waitBeforeBaseline: async () => { events.push("waitBaseline"); },
  waitAfter401: async () => { events.push("wait401"); phase = "after401"; },
  waitForStats: async () => { events.push("waitStats"); phase = "valid"; },
});
assert.ok(events.indexOf("waitBaseline") < events.findIndex((event) => event.startsWith("list:")));
assert.ok(events.indexOf("invalid") < events.indexOf("wait401"));
assert.ok(events.indexOf("wait401") < events.indexOf("workload"));
assert.ok(events.indexOf("workload") < events.indexOf("waitStats"));
assert.equal(receipt.schema_version, "milk.production-capture-proof.v1");
assert.equal(receipt.invalid_auth.http_status, 401);
assert.equal(receipt.invalid_auth.object_changes, 0);
assert.deepEqual(receipt.invalid_auth.before, receipt.invalid_auth.after);
assert.equal(receipt.traffic.count, 102);
assert.deepEqual(receipt.stats.delta, values);
assert.equal(receipt.stats.objects.length, 1);
assert.equal(receipt.sentinels[0].before.sha256, receipt.sentinels[0].after_workload.sha256);
assert.deepEqual(receipt.evidence, {
  traffic_bodies_read: false, prompt_bytes_retained: false,
  response_bytes_retained: false, secret_values_retained: false,
});
assert.equal(events.filter((event) => event.startsWith("read:")).length, 1);
const serialized = JSON.stringify(receipt);
for (const forbidden of [credential.api_key, credential.cohort_id, credential.model]) {
  assert.equal(serialized.includes(forbidden), false);
}
process.stdout.write("official OpenAI SDK production capture proof: ok\n");
