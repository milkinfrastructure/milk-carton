import assert from "node:assert/strict";

import OpenAI from "openai";

const [gatewayURL] = process.argv.slice(2);
const endpoint = new URL(gatewayURL);
assert.equal(endpoint.protocol, "http:");
assert.equal(endpoint.hostname, "127.0.0.1");

const client = new OpenAI({
  apiKey:
    "milk_live_018f3f54-7a5b-7cc0-8000-000000000001_test-secret-0001",
  baseURL: `${gatewayURL}/v1`,
  maxRetries: 0,
  timeout: 2_000,
});

const completion = await client.chat.completions.create({
  model: "capture-smoke-baseline",
  messages: [
    { role: "system", content: "Answer directly." },
    { role: "developer", content: "Keep the result short." },
    { role: "user", content: "Count to one." },
    { role: "assistant", content: "One." },
    { role: "user", content: "Confirm." },
  ],
});
assert.equal(completion.choices[0]?.message.content, "Confirmed.");
console.log('{"content_retained":false,"succeeded":true}');
