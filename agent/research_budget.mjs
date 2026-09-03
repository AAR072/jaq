import { HarnessLimitError } from "./protocol.mjs";

export const FINAL_RESEARCH_SUMMARY_INSTRUCTION = "The investigation budget is exhausted. Do not use tools. Return only a concise final research summary of the strongest recovered behavior, assets, deobfuscation work, artifacts, exact evidence IDs, and unresolved gaps.";
export const FINAL_FINDING_FLUSH_INSTRUCTION = "The reporting budget is exhausted. Evidence-reading tools are closed. Call record_finding now for any remaining reportable application behavior, credential, infrastructure, payload, persistence, impact, recovery request, or single concrete analysis blocker. Do not record packaging, parser, interpreter, library, tooling, or investigation-process details. Use multiple record_finding calls in this response when needed. Do not claim a finding was persisted unless you actually call the tool.";

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

export function budgetedModelRuntime(runtime, guard, mode, finalizationStage, enterFinalization, enterSummary, summaryMaxOutputTokens, onProviderCall) {
  for (const method of ["stream", "streamSimple"]) {
    const original = runtime[method].bind(runtime);
    runtime[method] = (...args) => {
      let requestArgs = args;
      if (mode === "research") {
        const compaction = isCompactionCall(args);
        const stage = finalizationStage();
        if (stage && compaction) {
          guard.beforeReportingAuxiliaryProviderCall();
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
              guard.beforeSummaryProviderCall();
              requestArgs = forceSummaryArguments(args, summaryMaxOutputTokens);
            }
          }
        }
      } else if (mode === "report") {
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
      }
      onProviderCall();
      return original(...requestArgs);
    };
  }
  return runtime;
}
