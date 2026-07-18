import assert from "node:assert/strict";
import test from "node:test";
import {
  DEFAULT_TOOL_CONTEXT_MAX_CHARS,
  guardContextSize,
  isOversizedContext,
  isTransient,
  resilientDetails,
  runResilient,
} from "../src/agent/tools/resilient-tool.js";

test("isOversizedContext detects model prompt-too-long error", () => {
  assert.equal(isOversizedContext(new Error("prompt is too long: 1645422 tokens > 1000000 maximum")), true);
  assert.equal(isOversizedContext(new Error("Input payload too large for model")), true);
  assert.equal(isOversizedContext(new Error("context window exceeds")), true);
  assert.equal(isOversizedContext(new Error("503 service unavailable")), false);
});

test("isTransient does not classify oversized-context errors as transient", () => {
  assert.equal(isTransient(new Error("prompt is too long: 2M tokens > 1M maximum")), false);
  assert.equal(isTransient(new Error("nats: no response from stream")), true);
});

test("runResilient surfaces oversized-context errors immediately without retry", async () => {
  let calls = 0;
  const result = await runResilient<Record<string, unknown>>({
    name: "test_oversized",
    run: async () => {
      calls += 1;
      throw new Error("prompt is too long: 2000000 tokens > 1000000 maximum");
    },
    retries: 4,
    backoffMs: 0,
  });
  assert.equal(calls, 1);
  assert.equal(result.ok, false);
  assert.equal(result.via, "primary:oversized_context");
  assert.match(String(result.error), /prompt is too long/);
});

test("guardContextSize leaves small payloads alone", () => {
  const payload = { findings: [{ id: "f-1", status: "open" }] };
  const guarded = guardContextSize(payload);
  assert.equal(guarded.truncated, false);
  assert.deepEqual(guarded.value, payload);
  assert.equal(guarded.limit, DEFAULT_TOOL_CONTEXT_MAX_CHARS);
});

test("guardContextSize shrinks oversized array payloads and flags context_truncated", () => {
  const bigRows = Array.from({ length: 5000 }, (_, index) => ({
    id: `row-${index}`,
    blob: "x".repeat(200),
  }));
  const guarded = guardContextSize({ rows: bigRows }, { maxChars: 8000 });
  assert.equal(guarded.truncated, true);
  assert.ok(guarded.size > guarded.limit);
  const value = guarded.value as { rows: unknown[] };
  assert.ok(Array.isArray(value.rows));
  assert.ok(value.rows.length < bigRows.length);
  const marker = value.rows.find((item): item is Record<string, unknown> => typeof item === "object" && item !== null && (item as Record<string, unknown>).context_truncated === true);
  assert.ok(marker, "expected context_truncated marker in shrunken array");
});

test("resilientDetails attaches context_truncated annotations when shrinking oversized successes", async () => {
  const bigData = { rows: Array.from({ length: 4000 }, (_, index) => ({ id: `r-${index}`, blob: "y".repeat(200) })) };
  const result = await runResilient<Record<string, unknown>>({
    name: "test_big",
    run: async () => bigData,
  });
  const details = resilientDetails(result, undefined, { maxContextChars: 6000 });
  assert.equal(details.context_truncated, true);
  assert.equal(typeof details.context_size_bytes, "number");
  assert.equal(typeof details.context_limit_bytes, "number");
  assert.match(String(details.via), /:context_truncated$/);
});
