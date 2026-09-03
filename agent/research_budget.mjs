import { HarnessLimitError } from "./protocol.mjs";

export const FINAL_RESEARCH_SUMMARY_INSTRUCTION = "The investigation budget is exhausted. Do not use tools. Return only a concise final research summary of the strongest recovered behavior, assets, deobfuscation work, artifacts, exact evidence IDs, and unresolved gaps.";
export const FINAL_FINDING_FLUSH_INSTRUCTION = "The investigation budget is exhausted. Analysis tools are closed. Before summarizing, call record_finding now for every supported behavior, credential, token, C2 endpoint, URL, payload, persistence mechanism, configuration value, recovery request, and unresolved conclusion not already recorded. Use multiple record_finding calls in this response when needed. Do not claim a finding was persisted unless you actually call the tool.";

export class FindingCadence {
  constructor(interval = 8) {
    this.interval = interval;
    this.analysisCallsSinceFinding = 0;
  }

  blocks(toolName) {
    return toolName !== "record_finding" && this.analysisCallsSinceFinding >= this.interval;
  }

  recordSuccess(toolName) {
    if (toolName === "record_finding") this.analysisCallsSinceFinding = 0;
    else this.analysisCallsSinceFinding += 1;
  }
}

export function budgetReason(error) {
  if (error?.code === "MODEL_CALL_BUDGET") return "the model-call investigation budget is exhausted";
  if (error?.code === "TOKEN_BUDGET") return "the token investigation budget is exhausted";
  if (error?.code === "COST_BUDGET") return "the cost investigation budget is exhausted";
  return "the investigation budget is exhausted";
}

export function isCompactionCall(args) {
  return typeof args[1]?.systemPrompt === "string"
    && args[1].systemPrompt.startsWith("You are a context summarization assistant.");
}

export function forceSummaryArguments(args, maxOutputTokens) {
  const [model, context, options, ...rest] = args;
  const summaryMessage = {
    role: "user",
    content: [{ type: "text", text: FINAL_RESEARCH_SUMMARY_INSTRUCTION }],
    timestamp: Date.now(),
  };
  return [
    { ...model, maxTokens: Math.min(model.maxTokens, maxOutputTokens) },
    { ...context, tools: [], messages: [...context.messages, summaryMessage] },
    { ...options, maxTokens: Math.min(options?.maxTokens ?? maxOutputTokens, maxOutputTokens) },
    ...rest,
  ];
}

export function forceFindingFlushArguments(args, maxOutputTokens) {
  const [model, context, options, ...rest] = args;
  const findingTools = (context.tools ?? []).filter((tool) => tool.name === "record_finding");
  const instruction = {
    role: "user",
    content: [{ type: "text", text: FINAL_FINDING_FLUSH_INSTRUCTION }],
    timestamp: Date.now(),
  };
  return [
    { ...model, maxTokens: Math.min(model.maxTokens, maxOutputTokens) },
    { ...context, tools: findingTools, messages: [...context.messages, instruction] },
    {
      ...options,
      maxTokens: Math.min(options?.maxTokens ?? maxOutputTokens, maxOutputTokens),
    },
    ...rest,
  ];
}

export function budgetedModelRuntime(runtime, guard, researchMode, finalizationStage, enterFinalization, enterSummary, shouldFinalizeForCost, summaryMaxOutputTokens, onProviderCall) {
  for (const method of ["stream", "streamSimple"]) {
    const original = runtime[method].bind(runtime);
    runtime[method] = (...args) => {
      let requestArgs = args;
      if (researchMode) {
        const compaction = isCompactionCall(args);
        let stage = finalizationStage();
        if (stage && compaction) {
          guard.beforeReportingAuxiliaryProviderCall();
        } else if (stage === "findings" && guard.findingFlushProviderCalls < 2) {
          guard.beforeFindingFlushProviderCall();
          requestArgs = forceFindingFlushArguments(args, summaryMaxOutputTokens);
        } else if (stage === "findings") {
          enterSummary();
          guard.beforeSummaryProviderCall();
          requestArgs = forceSummaryArguments(args, summaryMaxOutputTokens);
        } else if (stage === "summary") {
          guard.beforeSummaryProviderCall();
          requestArgs = forceSummaryArguments(args, summaryMaxOutputTokens);
        } else {
          try {
            guard.beforeProviderCall();
          } catch (error) {
            if (!(error instanceof HarnessLimitError)) throw error;
            enterFinalization(budgetReason(error));
            if (compaction) {
              guard.beforeReportingAuxiliaryProviderCall();
            } else {
              guard.beforeFindingFlushProviderCall();
              requestArgs = forceFindingFlushArguments(args, summaryMaxOutputTokens);
            }
          }
        }
      } else {
        if (shouldFinalizeForCost()) {
          enterFinalization("the cost budget is nearly exhausted");
        }
        guard.beforeProviderCall();
      }
      onProviderCall();
      return original(...requestArgs);
    };
  }
  return runtime;
}
