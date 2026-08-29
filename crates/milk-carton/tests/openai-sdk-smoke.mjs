import assert from "node:assert/strict";

import OpenAI from "openai";

const [gatewayURL, controlURL] = process.argv.slice(2);

for (const value of [gatewayURL, controlURL]) {
  const url = new URL(value);
  assert.equal(url.protocol, "http:");
  assert.equal(url.hostname, "127.0.0.1");
}

async function within(promise, label) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(
          () => reject(new Error(`${label} timed out`)),
          1_000,
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

const clientOptions = {
  apiKey:
    "milk_live_018f3f54-7a5b-7cc0-8000-000000000001_test-secret-0001",
  baseURL: `${gatewayURL}/v1`,
  maxRetries: 0,
  timeout: 2_000,
};
const client = new OpenAI({
  ...clientOptions,
});

const advancedRequest = {
  model: "sdk-nonstream",
  messages: [{ role: "user", content: "Return a typed result." }],
  tools: [
    {
      type: "function",
      function: {
        name: "lookup",
        description: "Look up a record.",
        strict: true,
        parameters: {
          type: "object",
          properties: { id: { type: "string" } },
          required: ["id"],
          additionalProperties: false,
        },
      },
    },
  ],
  tool_choice: { type: "function", function: { name: "lookup" } },
  response_format: {
    type: "json_schema",
    json_schema: {
      name: "typed_result",
      strict: true,
      schema: {
        type: "object",
        properties: { ok: { type: "boolean" } },
        required: ["ok"],
        additionalProperties: false,
      },
    },
  },
};
const completion = await client.chat.completions.create(advancedRequest);
assert.equal(completion.choices[0]?.message.content, '{"ok":true}');

const multimodalRequest = {
  model: "sdk-multimodal",
  messages: [
    {
      role: "user",
      content: [
        { type: "text", text: "Read this image." },
        {
          type: "image_url",
          image_url: {
            url: "data:image/png;base64,aGVsbG8=",
            detail: "high",
          },
        },
      ],
    },
  ],
};
const multimodal = await client.chat.completions.create(multimodalRequest);
assert.equal(multimodal.choices[0]?.message.content, "hello");

const streamed = await client.chat.completions.create({
  model: "sdk-stream",
  messages: [{ role: "user", content: "Stream." }],
  stream: true,
});
const streamedIterator = streamed[Symbol.asyncIterator]();
const first = await within(streamedIterator.next(), "first stream chunk");
assert.equal(first.done, false);
assert.equal(first.value.choices[0]?.delta.content, "hel");
const released = await fetch(`${controlURL}/release-stream`, {
  method: "POST",
});
assert.equal(released.status, 204);

let streamText = first.value.choices[0]?.delta.content ?? "";
for (;;) {
  const next = await within(streamedIterator.next(), "remaining stream chunks");
  if (next.done) break;
  streamText += next.value.choices[0]?.delta.content ?? "";
}
assert.equal(streamText, "hello");

const responsesRequest = {
  model: "sdk-responses-nonstream",
  input: [
    {
      role: "user",
      content: [{ type: "input_text", text: "Return a Responses result." }],
    },
  ],
  metadata: { smoke: "official-node-sdk" },
  safety_identifier: "sdk-smoke-user",
  unknown_extension: { keep: true },
};
const responsesResult = await client.responses.create(responsesRequest);
assert.equal(responsesResult.output_text, "responses-ok");

const responsesStreamRequest = {
  model: "sdk-responses-stream",
  input: "Stream a Responses result.",
  stream: true,
  unknown_extension: { keep: true },
};
const responsesStream = await client.responses.create(responsesStreamRequest);
let responsesStreamText = "";
let responsesStreamTerminal;
for await (const event of responsesStream) {
  if (event.type === "response.output_text.delta") {
    responsesStreamText += event.delta;
  }
  if (event.type === "response.completed") {
    responsesStreamTerminal = event.type;
    assert.equal(event.response.status, "completed");
  }
}
assert.equal(responsesStreamText, "responses-stream-ok");
assert.equal(responsesStreamTerminal, "response.completed");

const unkeyed = new OpenAI({ ...clientOptions, apiKey: "wrong" });
let missingKeyStatus;
await assert.rejects(
  unkeyed.chat.completions.create({
    model: "sdk-missing-key",
    messages: [{ role: "user", content: "Reject." }],
  }),
  (error) => {
    assert.ok(error instanceof OpenAI.AuthenticationError);
    assert.equal(error.code, "invalid_milk_api_key");
    missingKeyStatus = error.status;
    return true;
  },
);

let rateLimitStatus;
await assert.rejects(
  client.chat.completions.create({
    model: "sdk-rate-limit",
    messages: [{ role: "user", content: "Rate limit." }],
  }),
  (error) => {
    assert.ok(error instanceof OpenAI.RateLimitError);
    assert.equal(error.requestID, "req-rate-limit");
    rateLimitStatus = error.status;
    return true;
  },
);

const abortController = new AbortController();
const cancellable = await client.chat.completions.create(
  {
    model: "sdk-cancel",
    messages: [{ role: "user", content: "Cancel." }],
    stream: true,
  },
  { signal: abortController.signal },
);
const cancelIterator = cancellable[Symbol.asyncIterator]();
const cancelFirst = await within(
  cancelIterator.next(),
  "cancellable first chunk",
);
assert.equal(cancelFirst.done, false);
abortController.abort();
assert.equal(
  (await within(cancelIterator.next(), "stream cancellation")).done,
  true,
);

console.log(
  JSON.stringify({
    advanced_request: JSON.stringify(advancedRequest),
    multimodal_request: JSON.stringify(multimodalRequest),
    multimodal_content: multimodal.choices[0]?.message.content,
    nonstream_content: completion.choices[0]?.message.content,
    responses_nonstream_text: responsesResult.output_text,
    responses_request: JSON.stringify(responsesRequest),
    responses_stream_request: JSON.stringify(responsesStreamRequest),
    responses_stream_terminal: responsesStreamTerminal,
    responses_stream_text: responsesStreamText,
    stream_text: streamText,
    missing_key_status: missingKeyStatus,
    rate_limit_status: rateLimitStatus,
    cancelled: abortController.signal.aborted,
  }),
);
