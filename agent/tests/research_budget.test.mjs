import assert from "node:assert/strict";
import test from "node:test";

import { BudgetGuard, HarnessLimitError } from "../protocol.mjs";
import {
  budgetedModelRuntime,
  FINAL_FINDING_FLUSH_INSTRUCTION,
  FINAL_RESEARCH_SUMMARY_INSTRUCTION,
} from "../research_budget.mjs";

function context(systemPrompt = "JAQ research") {
  return {
    systemPrompt,
    messages: [{ role: "user", content: [{ type: "text", text: "investigate" }], timestamp: 1 }],
    tools: [
      { name: "static_tool", description: "fixture", parameters: { type: "object" } },
      { name: "record_finding", description: "record", parameters: { type: "object" } },
    ],
  };
}

function fakeRuntime(calls) {
  return {
    stream(...args) { calls.push(args); return { kind: "stream" }; },
    streamSimple(...args) { calls.push(args); return { kind: "streamSimple" }; },
  };
}

function wrap(mode, guard, calls, state) {
  return budgetedModelRuntime(
    fakeRuntime(calls), guard, mode, () => state.stage,
    () => { state.stage = mode === "report" ? "findings" : "summary"; },
    () => { state.stage = "summary"; }, 512, () => {},
  );
}

test("research cap uses one bounded tool-free summary call without reporting tools", () => {
  const calls = [];
  const guard = new BudgetGuard({
    max_model_calls: 1, max_tool_calls: null, max_total_tokens: null, max_cost_usd: 1,
  }, () => ({ tokens: { total: 1 }, cost: 0 }));
  const state = { stage: null };
  const runtime = wrap("research", guard, calls, state);
  const model = { maxTokens: 32_768 };
  runtime.stream(model, context(), { maxTokens: 32_768 });
  runtime.stream(model, context(), { maxTokens: 32_768 });

  assert.equal(state.stage, "summary");
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[1][1].tools, []);
  assert.equal(calls[1][0].maxTokens, 512);
  assert.equal(calls[1][1].messages.at(-1).content[0].text, FINAL_RESEARCH_SUMMARY_INSTRUCTION);
  assert.equal(guard.snapshot().finding_flush_provider_calls, 0);
  assert.equal(guard.snapshot().summary_provider_calls, 1);
  assert.throws(() => runtime.stream(model, context(), {}), HarnessLimitError);
});

test("reporter cap preserves incremental finding flushes before its summary", () => {
  const calls = [];
  const guard = new BudgetGuard({
    max_model_calls: 1, max_tool_calls: null, max_total_tokens: null, max_cost_usd: 1,
  }, () => ({ tokens: { total: 1 }, cost: 0 }));
  const state = { stage: null };
  const runtime = wrap("report", guard, calls, state);
  const model = { maxTokens: 32_768 };
  runtime.stream(model, context(), { maxTokens: 32_768 });
  runtime.stream(model, context(), { maxTokens: 32_768 });
  runtime.stream(model, context(), { maxTokens: 32_768 });
  runtime.stream(model, context(), { maxTokens: 32_768 });

  assert.equal(calls.length, 4);
  assert.deepEqual(calls[1][1].tools.map((tool) => tool.name), ["record_finding"]);
  assert.equal(calls[1][1].messages.at(-1).content[0].text, FINAL_FINDING_FLUSH_INSTRUCTION);
  assert.deepEqual(calls[3][1].tools, []);
  assert.equal(guard.snapshot().finding_flush_provider_calls, 2);
  assert.equal(guard.snapshot().summary_provider_calls, 1);
});

test("reporting compaction cannot consume the reporter summary slot", () => {
  const calls = [];
  const guard = new BudgetGuard({
    max_model_calls: null, max_tool_calls: null, max_total_tokens: null, max_cost_usd: 0.1,
  }, () => ({ tokens: { total: 100 }, cost: 0.1 }));
  const state = { stage: null };
  const runtime = wrap("report", guard, calls, state);
  const model = { maxTokens: 32_768 };
  runtime.streamSimple(model, context("You are a context summarization assistant. Compact."), { maxTokens: 1000 });
  runtime.stream(model, context(), { maxTokens: 1000 });
  runtime.stream(model, context(), { maxTokens: 1000 });
  runtime.stream(model, context(), { maxTokens: 1000 });

  assert.equal(calls.length, 4);
  assert.equal(guard.snapshot().reporting_auxiliary_provider_calls, 1);
  assert.equal(guard.snapshot().summary_provider_calls, 1);
  assert.equal(calls[0][1].messages.length, 1);
  assert.deepEqual(calls[3][1].tools, []);
});
