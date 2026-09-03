# JAQ Technical Vision

## Milestone 1: Autonomous Static PE Investigator

JAQ's first milestone is a local, evidence-first vertical slice for defensively investigating a manually supplied Windows Portable Executable. The sample is inert input: JAQ validates and hashes it, mounts it read-only into a network-disabled static-analysis container, and never launches it or contacts any endpoint it contains.

The command-line contract is:

```text
jaq analyze --sample <absolute-path> --output <directory>
```

Go is the trusted controller. It validates the input, records a versioned run manifest, performs deterministic lightweight PE extraction, starts a pinned persistent Radare2 static sandbox, launches the Python investigator, and validates every persisted output before accepting a run. Native PE evidence is published before the sandbox starts, so later failures retain a partial evidence package.

Pi SDK is the host-side investigator harness. It owns provider compatibility, bounded tool turns, append-only resumable sessions, context compaction, and usage accounting. Pi receives only JAQ-owned tools; its built-in filesystem, editor, and shell tools are disabled. Python remains the trusted tool/evidence broker: it queries existing evidence, drives the project-owned facade over official Radare2 MCP, runs arbitrary shell commands only inside the disposable static sandbox, and validates incremental `record_finding` calls. Full tool results are persisted before return while Pi sees evidence IDs and bounded previews. Accepted semantic findings are immediately fsynced to `findings.jsonl`. LiteLLM remains only behind the optional, tool-free judge role.

All binary-derived text and all tool output are hostile data. Every investigator-selected Radare MCP or shell request is persisted before execution, and its bounded result is persisted before it is returned to the model. MCP initialization and tool discovery are bounded control traffic, not sample evidence. Claims may cite only observation IDs. Deterministic verification checks schemas, evidence existence, structured relationships, reachability where available, and judge consistency. The optional judge remains tool-free and sees only cited static evidence.

Research completion is cost-governed rather than turn-gated. By default the research model has no call, tool, or cumulative-token stop counter; the dollar budget is authoritative. A hard reporting cadence blocks a ninth consecutive analysis-tool call until at least one supported finding is persisted. Configured research caps apply only to evidence-gathering. At exhaustion the harness removes analysis tools, reserves up to two bounded thinking-off calls that can only invoke `record_finding`, and then reserves one bounded tool-free call for the prose summary; bounded Pi compaction needed to make that report fit is tracked separately. Persisted evidence is assessed for application entrypoint analysis, application-function disassembly/decompilation, call/xref analysis, and concrete deobfuscation work. Missing coverage is recorded as an unresolved warning instead of preventing a research artifact from being written.

Exploratory research and dossier formatting are failure-isolated. Research never asks the model to produce one schema-constrained final object. It records small evidence-backed findings as they are discovered and ends with prose. JAQ compiles the versioned checkpoint and dossier locally from the persisted tool and findings ledgers. If prose is missing, persisted records still produce a partial checkpoint and dossier without a model call, Radare rerun, or helper-command rerun. Coverage deficiencies become explicit unresolved warnings instead of invalidating the research artifact. The same recovery is available manually through `scripts/jaq-harvest`. Provider authentication, balance, cancellation, and timeout errors remain explicit rather than being misreported as terminal-call failures.

Each completed run writes:

- `run-manifest.json`: hashes, versions, configuration and prompt hashes, role metadata, status, timestamps, and resource usage.
- `observations.jsonl`: deterministic, typed, provenance-bearing facts.
- `findings.jsonl`: append-only, evidence-backed semantic conclusions captured during research.
- `claims.json`: structured investigator claims and evidence references.
- `assets.json`: exact infrastructure, credential, configuration, and payload-reference assets with evidence.
- `requests.json`: evidence-backed acquisition or dynamic-analysis requests in `pending_authorization` state; no request is executed in this milestone.
- `score.json`: verification results, optional judgments, and model usage.
- `report.md`: an evidence-backed analyst dossier.

Formats are versioned and validated at every trust boundary. Native observations remain comparable across identical runs; interactive command observations form a provenance chain containing the logical tool, arguments, result digest, analyzer version, and parent request ID.

## Security and isolation

The image pins Radare2 6.2.0 and the official radare2-mcp 1.8.6. The controller resolves and runs the local image by immutable content ID. Docker supplies no network, no Linux capabilities, no privilege escalation, a read-only root filesystem, fixed UID/GID 65532, bounded CPU/memory/processes, one read-only staged PE mount, and disposable tmpfs storage at `/work` and `/tmp`. No host directory is writable from the container.

The model may choose arbitrary command strings, but the host always launches one fixed `docker exec` argv and the string is interpreted only by `/bin/bash` inside the offline container. The image contains static utilities and compilers but intentionally excludes PE runtimes, emulators, Frida, and debugger tooling. The sample remains read-only and JAQ never launches it. Per-command and whole-run deadlines, container resource limits, forced container cleanup, model/tool/token/cost budgets, and early Pi compaction bound the run. Pi session files, raw provider traces, credentials, samples, generated runs, scratch files, and derived artifacts stay outside version control.

There is an unavoidable semantic boundary here: arbitrary helper code operating on PE bytes is Turing-complete, so a kernel cannot reliably distinguish a static decoder from a hand-written emulator. This milestone enforces the absence of native PE execution and supplied dynamic toolchains, while the investigator policy forbids emulation and runtime analysis. A future hard semantic guarantee would require replacing arbitrary commands with brokered transformations; that would conflict with the deliberately open-ended deobfuscation workflow selected for this milestone.

## Deferred milestones

This slice deliberately excludes dynamic analysis and its request/judge authorization flow, sample acquisition, MalwareBazaar, submissions, corpus/global correlation, campaign graphs, visualization, Temporal, PostgreSQL, production infrastructure, and novelty claims. Static commands must not execute, emulate, or debug the supplied PE.

The acquisition control plane is now present: evidence-backed remote stages may produce pending requests, and an operator may approve or deny requests. Operational assets are proposed by the final model and retained only when their exact values are supported by cited observations; JAQ does not promote regex matches automatically. Approved remote payloads are fetched in a separate bounded Docker invocation and analyzed as child runs. Dynamic approvals remain handoff-only until a dedicated dynamic sandbox exists.

## Acceptance boundary

Unit and integration tests generate a harmless PE fixture and exercise malformed input, sandbox startup/cleanup, MCP lifecycle and ID correlation, arbitrary-command isolation, output/time limits, incremental evidence IDs, invalid model tools, unsupported claims, hostile output, and mocked investigator/judge loops. The tagged Docker test verifies the live container, required static tools, read-only PE, offline posture, writable scratch, failed native PE execution, and cleanup.
