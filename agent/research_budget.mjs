import { HarnessLimitError } from "./protocol.mjs";

export const FINAL_RESEARCH_SUMMARY_INSTRUCTION = "The investigation budget is exhausted. Do not use tools. Return only a concise final research summary of the strongest recovered behavior, assets, deobfuscation work, artifacts, exact evidence IDs, and unresolved gaps.";

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

export function budgetedModelRuntime(runtime, guard, researchMode, isFinalizing, enterFinalization, shouldFinalizeForCost, summaryMaxOutputTokens, onProviderCall) {
  for (const method of ["stream", "streamSimple"]) {
    const original = runtime[method].bind(runtime);
    runtime[method] = (...args) => {
      let requestArgs = args;
      if (researchMode) {
        const compaction = isCompactionCall(args);
        if (isFinalizing() && compaction) {
          guard.beforeReportingAuxiliaryProviderCall();
        } else if (isFinalizing()) {
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
              guard.beforeSummaryProviderCall();
              requestArgs = forceSummaryArguments(args, summaryMaxOutputTokens);
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
