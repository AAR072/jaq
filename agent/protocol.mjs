import { createHash } from "node:crypto";

export const MAX_PROTOCOL_FRAME_BYTES = 8 * 1024 * 1024;

export class HarnessLimitError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "HarnessLimitError";
    this.code = code;
  }
}

export class LineChannel {
  constructor(input = process.stdin, output = process.stdout) {
    this.input = input;
    this.output = output;
    this.buffer = Buffer.alloc(0);
    this.frames = [];
    this.waiters = [];
    this.ended = false;
    this.nextRequestID = 1;
    input.on("data", (chunk) => this.#onData(Buffer.from(chunk)));
    input.on("end", () => this.#end(new Error("JAQ broker closed stdin")));
    input.on("error", (error) => this.#end(error));
  }

  #onData(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    if (this.buffer.length > MAX_PROTOCOL_FRAME_BYTES && this.buffer.indexOf(0x0a) === -1) {
      this.#end(new Error("JAQ broker frame exceeds the protocol limit"));
      return;
    }
    for (;;) {
      const newline = this.buffer.indexOf(0x0a);
      if (newline < 0) return;
      const raw = this.buffer.subarray(0, newline);
      this.buffer = this.buffer.subarray(newline + 1);
      if (raw.length === 0) continue;
      if (raw.length > MAX_PROTOCOL_FRAME_BYTES) {
        this.#end(new Error("JAQ broker frame exceeds the protocol limit"));
        return;
      }
      let frame;
      try {
        frame = JSON.parse(raw.toString("utf8"));
      } catch {
        this.#end(new Error("JAQ broker sent malformed JSON"));
        return;
      }
      if (!frame || typeof frame !== "object" || Array.isArray(frame)) {
        this.#end(new Error("JAQ broker frame must be a JSON object"));
        return;
      }
      const waiter = this.waiters.shift();
      if (waiter) waiter.resolve(frame);
      else this.frames.push(frame);
    }
  }

  #end(error) {
    if (this.ended) return;
    this.ended = true;
    for (const waiter of this.waiters.splice(0)) waiter.reject(error);
  }

  read() {
    if (this.frames.length) return Promise.resolve(this.frames.shift());
    if (this.ended) return Promise.reject(new Error("JAQ broker channel is closed"));
    return new Promise((resolve, reject) => this.waiters.push({ resolve, reject }));
  }

  send(frame) {
    const encoded = `${JSON.stringify(frame)}\n`;
    if (Buffer.byteLength(encoded) > MAX_PROTOCOL_FRAME_BYTES) {
      throw new Error("JAQ harness frame exceeds the protocol limit");
    }
    this.output.write(encoded);
  }

  async request(operation, payload = {}) {
    const id = this.nextRequestID++;
    this.send({ type: "request", id, operation, payload });
    const response = await this.read();
    if (response.type !== "response" || response.id !== id) {
      throw new Error("JAQ broker response correlation failed");
    }
    if (response.ok !== true) {
      const message = typeof response.error?.message === "string"
        ? response.error.message.slice(0, 500)
        : "JAQ broker rejected the request";
      const error = new Error(message);
      error.name = typeof response.error?.type === "string" ? response.error.type : "BrokerError";
      throw error;
    }
    return response.result;
  }
}

function collectEvidenceIDs(value, found = new Set(), depth = 0) {
  if (depth > 8 || value === null || value === undefined) return found;
  if (Array.isArray(value)) {
    for (const item of value) collectEvidenceIDs(item, found, depth + 1);
    return found;
  }
  if (typeof value !== "object") return found;
  for (const [key, item] of Object.entries(value)) {
    if ((key === "id" || key === "observation_id") && typeof item === "string" && item.startsWith("obs-")) {
      found.add(item);
    }
    collectEvidenceIDs(item, found, depth + 1);
  }
  return found;
}

export function compactToolResult(toolName, value, maxChars = 2400) {
  const serialized = JSON.stringify(value);
  const evidenceIDs = [...collectEvidenceIDs(value)].slice(0, 100);
  const base = {
    untrusted_evidence: true,
    tool: toolName,
    evidence_ids: evidenceIDs,
  };
  const complete = { ...base, data: value };
  const completeText = JSON.stringify(complete);
  if (completeText.length <= maxChars) return completeText;
  const digest = createHash("sha256").update(serialized).digest("hex");
  const bounded = {
    ...base,
    data: {
      truncated: true,
      sha256: digest,
      preview: "",
    },
  };
  const overhead = JSON.stringify(bounded).length;
  bounded.data.preview = serialized.slice(0, Math.max(0, maxChars - overhead - 8));
  while (JSON.stringify(bounded).length > maxChars && bounded.data.preview.length) {
    bounded.data.preview = bounded.data.preview.slice(0, -16);
  }
  return JSON.stringify(bounded);
}

export class BudgetGuard {
  constructor(limits, stats = () => undefined) {
    this.limits = limits;
    this.stats = stats;
    this.providerCalls = 0;
    this.toolCalls = 0;
  }

  beforeProviderCall() {
    const current = this.stats();
    if (this.providerCalls >= this.limits.max_model_calls) {
      throw new HarnessLimitError("MODEL_CALL_BUDGET", "investigator model-call budget exhausted");
    }
    if (current && current.tokens.total >= this.limits.max_total_tokens) {
      throw new HarnessLimitError("TOKEN_BUDGET", "investigator cumulative token budget exhausted");
    }
    if (current && current.cost >= this.limits.max_cost_usd) {
      throw new HarnessLimitError("COST_BUDGET", "investigator cost budget exhausted");
    }
    this.providerCalls += 1;
  }

  beforeToolCall() {
    if (this.toolCalls >= this.limits.max_tool_calls) {
      throw new HarnessLimitError("TOOL_CALL_BUDGET", "investigator tool-call budget exhausted");
    }
    this.toolCalls += 1;
  }

  snapshot() {
    return { provider_calls: this.providerCalls, tool_calls: this.toolCalls };
  }
}

export function parseModelSelector(selector) {
  if (typeof selector !== "string" || !selector.includes("/")) {
    throw new Error("JAQ investigator model must be a provider/model string");
  }
  const [provider, ...parts] = selector.split("/");
  const model = parts.join("/");
  if (!/^[A-Za-z0-9._-]+$/.test(provider) || !model || model.length > 300) {
    throw new Error("JAQ investigator model selector is invalid");
  }
  return { provider, model };
}

export function sanitizeError(error) {
  let message = error instanceof Error ? error.message : String(error);
  message = message.replace(/bearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [redacted]");
  message = message.replace(/\b(?:sk|sess|key)-[A-Za-z0-9_-]{12,}\b/g, "[redacted]");
  return message.split(/\s+/).join(" ").slice(0, 1000);
}
