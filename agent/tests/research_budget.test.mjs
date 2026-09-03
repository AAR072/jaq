import assert from "node:assert/strict";
import test from "node:test";

import { BudgetGuard, HarnessLimitError } from "../protocol.mjs";
import {
  budgetedModelRuntime,
  FindingCadence,
  FINAL_FINDING_FLUSH_INSTRUCTION,
  FINAL_RESEARCH_SUMMARY_INSTRUCTION,
} from "../research_budget.mjs";

test("finding cadence blocks more analysis until a finding is successfully recorded", () => {
  const cadence = new FindingCadence(2);
  assert.equal(cadence.blocks("r2_analyze"), false);
  cadence.recordSuccess("r2_analyze");
  cadence.recordSuccess("run_static_command");
  assert.equal(cadence.blocks("r2_disassemble"), true);
  assert.equal(cadence.blocks("record_finding"), false);
  cadence.recordSuccess("record_finding");
  assert.equal(cadence.blocks("r2_disassemble"), false);
});

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

test("research cap preserves one bounded tool-free final summary call", () => {
  const calls = [];
  const guard = new BudgetGuard({
    max_model_calls: 1, max_tool_calls: null, max_total_tokens: null, max_cost_usd: 1,
  }, () => ({ tokens: { total: 1 }, cost: 0 }));
  let stage = null;
  const runtime = budgetedModelRuntime(
    fakeRuntime(calls), guard, true, () => stage, () => { stage = "findings"; },
    () => { stage = "summary"; }, () => false, 512, () => {},
  );
  const model = { maxTokens: 32_768 };
  runtime.stream(model, context(), { maxTokens: 32_768 });
  runtime.stream(model, context(), { maxTokens: 32_768 });
  runtime.stream(model, context(), { maxTokens: 32_768 });
  runtime.stream(model, context(), { maxTokens: 32_768 });

  assert.equal(stage, "summary");
  assert.equal(calls.length, 4);
  assert.deepEqual(calls[1][1].tools.map((tool) => tool.name), ["record_finding"]);
  assert.equal(calls[1][2].toolChoice, undefined);
  assert.equal(calls[1][1].messages.at(-1).content[0].text, FINAL_FINDING_FLUSH_INSTRUCTION);
  assert.equal(calls[3][0].maxTokens, 512);
  assert.equal(calls[3][2].maxTokens, 512);
  assert.equal(calls[3][1].messages.at(-1).content[0].text, FINAL_RESEARCH_SUMMARY_INSTRUCTION);
  assert.equal(guard.snapshot().finding_flush_provider_calls, 2);
  assert.equal(guard.snapshot().summary_provider_calls, 1);
  assert.throws(() => runtime.stream(model, context(), {}), HarnessLimitError);
});

test("reporting compaction cannot consume the final summary slot", () => {
  const calls = [];
  const guard = new BudgetGuard({
    max_model_calls: null, max_tool_calls: null, max_total_tokens: null, max_cost_usd: 0.1,
  }, () => ({ tokens: { total: 100 }, cost: 0.1 }));
  let stage = null;
  const runtime = budgetedModelRuntime(
    fakeRuntime(calls), guard, true, () => stage, () => { stage = "findings"; },
    () => { stage = "summary"; }, () => false, 256, () => {},
  );
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
