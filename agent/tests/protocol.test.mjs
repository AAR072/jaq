import assert from "node:assert/strict";
import test from "node:test";

import {
  BudgetGuard,
  compactToolResult,
  HarnessLimitError,
  parseModelSelector,
  relaxedTerminalSchema,
  sanitizeError,
} from "../protocol.mjs";

test("compactToolResult keeps IDs and bounds model-visible output", () => {
  const raw = { observation_id: "obs-result", stdout: "x".repeat(20_000) };
  const text = compactToolResult("run_static_command", raw, 900);
  const value = JSON.parse(text);
  assert.ok(text.length <= 900);
  assert.deepEqual(value.evidence_ids, ["obs-result"]);
  assert.equal(value.data.truncated, true);
  assert.match(value.data.sha256, /^[a-f0-9]{64}$/);
  assert.ok(!text.includes("x".repeat(1000)));
});

test("BudgetGuard blocks before excess provider and tool calls", () => {
  let stats = { tokens: { total: 10 }, cost: 0.01 };
  const guard = new BudgetGuard({
    max_model_calls: 2,
    max_tool_calls: 1,
    max_total_tokens: 100,
    max_cost_usd: 0.1,
  }, () => stats);
  guard.beforeProviderCall();
  guard.beforeProviderCall();
  assert.throws(() => guard.beforeProviderCall(), HarnessLimitError);
  guard.beforeToolCall();
  assert.throws(() => guard.beforeToolCall(), /tool-call budget/);
  stats = { tokens: { total: 101 }, cost: 0.01 };
  const tokenGuard = new BudgetGuard({
    max_model_calls: 3, max_tool_calls: 3, max_total_tokens: 100, max_cost_usd: 0.1,
  }, () => stats);
  assert.throws(() => tokenGuard.beforeProviderCall(), /token budget/);
});

test("BudgetGuard permits unlimited calls when only cost is configured", () => {
  let stats = { tokens: { total: 10_000_000 }, cost: 0.01 };
  const guard = new BudgetGuard({
    max_model_calls: null,
    max_tool_calls: null,
    max_total_tokens: null,
    max_cost_usd: 0.1,
  }, () => stats);
  for (let index = 0; index < 1000; index += 1) {
    guard.beforeProviderCall();
    guard.beforeToolCall();
  }
  assert.equal(guard.nearCost(0.70), false);
  stats = { tokens: { total: 10_000_000 }, cost: 0.071 };
  assert.equal(guard.nearCost(0.70), true);
  stats = { tokens: { total: 10_000_000 }, cost: 0.1 };
  assert.throws(() => guard.beforeProviderCall(), /cost budget/);
});

test("model selectors and diagnostics remain bounded", () => {
  assert.deepEqual(parseModelSelector("deepseek/deepseek-v4-flash"), {
    provider: "deepseek", model: "deepseek-v4-flash",
  });
  assert.throws(() => parseModelSelector("deepseek"));
  assert.equal(sanitizeError(new Error("Bearer sk-secret-value-123456")), "Bearer [redacted]");
});

test("terminal transport schema defers formatting limits to local canonicalization", () => {
  const strict = {
    type: "object", additionalProperties: false, maxProperties: 2,
    properties: {
      name: { type: "string", maxLength: 300 },
      records: {
        type: "array", maxItems: 10,
        items: { type: "object", additionalProperties: false, properties: {} },
      },
    },
  };
  const relaxed = relaxedTerminalSchema(strict);
  assert.equal(relaxed.additionalProperties, true);
  assert.equal("maxProperties" in relaxed, false);
  assert.equal("maxLength" in relaxed.properties.name, false);
  assert.equal("maxItems" in relaxed.properties.records, false);
  assert.equal(relaxed.properties.records.items.additionalProperties, true);
  assert.equal(strict.additionalProperties, false);
});
