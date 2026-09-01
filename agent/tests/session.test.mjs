import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { InMemoryCredentialStore } from "@earendil-works/pi-ai";
import {
  createAgentSession,
  DefaultResourceLoader,
  ModelRuntime,
  SessionManager,
  SettingsManager,
} from "@earendil-works/pi-coding-agent";

test("Pi session exposes only explicitly allowed JAQ custom tools", async () => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), "jaq-pi-session-test-"));
  try {
    const runtime = await ModelRuntime.create({
      credentials: new InMemoryCredentialStore(), modelsPath: null, refreshOnCreate: false,
    });
    const model = runtime.getModel("deepseek", "deepseek-v4-flash");
    assert.ok(model);
    const settings = SettingsManager.inMemory({ defaultTools: [], quietStartup: true }, { projectTrusted: false });
    const loader = new DefaultResourceLoader({
      cwd, agentDir: cwd, settingsManager: settings,
      noExtensions: true, noSkills: true, noPromptTemplates: true, noThemes: true, noContextFiles: true,
      systemPrompt: "JAQ fixture prompt.",
    });
    await loader.reload();
    const jaqTool = {
      name: "jaq_fixture",
      label: "JAQ fixture",
      description: "Return a fixture result.",
      parameters: { type: "object", additionalProperties: false, properties: {} },
      async execute() {
        return { content: [{ type: "text", text: "ok" }], details: {} };
      },
    };
    const { session } = await createAgentSession({
      cwd, agentDir: cwd, modelRuntime: runtime, model, thinkingLevel: "off",
      noTools: "builtin", tools: [jaqTool.name], customTools: [jaqTool],
      resourceLoader: loader, settingsManager: settings, sessionManager: SessionManager.inMemory(cwd),
    });
    assert.deepEqual(session.getActiveToolNames(), ["jaq_fixture"]);
    assert.deepEqual(loader.getAgentsFiles().agentsFiles, []);
    assert.equal(loader.getExtensions().extensions.length, 0);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});
