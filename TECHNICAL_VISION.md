# JAQ Technical Vision

## Milestone 1: Autonomous Static PE Investigator

JAQ's first milestone is a local, evidence-first vertical slice for defensively investigating a manually supplied Windows Portable Executable. The sample is inert input: JAQ validates and hashes it, mounts it read-only into a network-disabled static-analysis container, and never launches it or contacts any endpoint it contains.

The command-line contract is:

```text
jaq analyze --sample <absolute-path> --output <directory>
```

Go is the trusted controller. It validates the input, records a versioned run manifest, performs deterministic lightweight PE extraction, starts a pinned persistent Radare2 static sandbox, launches the Python investigator, and validates every persisted output before accepting a run. Native PE evidence is published before the sandbox starts, so later failures retain a partial evidence package.

Pi SDK is the host-side investigator harness. It owns provider compatibility, bounded tool turns, append-only resumable sessions, context compaction, and usage accounting. A research session receives Radare2 and static sandbox tools but no reporting tool; a fresh reporter receives read-only evidence operations plus `record_finding` but no analysis/runtime tools. Python remains the trusted broker. Full research results are persisted before return while Pi sees evidence IDs and bounded previews; accepted reporter findings are immediately fsynced to `findings.jsonl`. LiteLLM remains only behind the optional, tool-free judge role.

All binary-derived text and all tool output are hostile data. Every investigator-selected Radare MCP or shell request is persisted before execution, and its bounded result is persisted before it is returned to the model. MCP initialization and tool discovery are bounded control traffic, not sample evidence. Claims may cite only observation IDs. Deterministic verification checks schemas, evidence existence, structured relationships, reachability where available, and judge consistency. The optional judge remains tool-free and sees only cited static evidence.

Research completion is cost-governed rather than turn-gated. The researcher spends its budget on reaching and understanding application-owned code, not documenting packaging or tool development, and retains one tool-free summary call at exhaustion. The reporter has a separate small budget and records only analyst-relevant scopes. Reporter failure cannot invalidate already appended findings, and blocker-only output is explicitly partial. Persisted evidence is assessed for application entrypoint analysis, application-function disassembly/decompilation, call/xref analysis, and concrete deobfuscation work. Missing coverage is recorded as an unresolved warning instead of preventing a research artifact from being written.

Exploratory research and dossier formatting are failure-isolated. The researcher ends with prose and the fresh reporter appends one small finding at a time; neither produces one schema-constrained final object. JAQ compiles the versioned checkpoint and dossier locally from the persisted tool and findings ledgers. Reporter interruption preserves every accepted record. If prose is missing, persisted evidence still produces a partial checkpoint without a Radare/helper rerun. Coverage deficiencies become explicit unresolved warnings instead of invalidating the research artifact. The same recovery is available through `scripts/jaq-harvest`.

Each completed run writes:

- `run-manifest.json`: hashes, versions, configuration and prompt hashes, role metadata, status, timestamps, and resource usage.
- `observations.jsonl`: deterministic, typed, provenance-bearing facts.
- `findings.jsonl`: append-only, evidence-backed semantic conclusions captured by the isolated reporter.
- `claims.json`: structured investigator claims and evidence references.
- `assets.json`: exact infrastructure, credential, configuration, and payload-reference assets with evidence.
- `communications.json`: recovered exfiltration and command/control paths, kept distinct from endpoint ownership.
- `requests.json`: evidence-backed acquisition or dynamic-analysis requests in `pending_authorization` state; no request is executed in this milestone.
- `score.json`: verification results, optional judgments, and model usage.
- `report.md`: an evidence-backed analyst dossier.

Formats are versioned and validated at every trust boundary. Native observations remain comparable across identical runs; interactive command observations form a provenance chain containing the logical tool, arguments, result digest, analyzer version, and parent request ID.

## Security and isolation

The image pins Radare2 6.2.0, the official radare2-mcp 1.8.6, CPython 3.14 for non-executing marshal/bytecode inspection, capa plus its offline rules/signatures, and versioned Python static-analysis packages. It also provides a deterministic Go clone/residue profiler, PyInstaller extraction, .NET metadata/CIL parsing, native PE utilities, archive/installer extractors, YARA, and common decoding tools. `/opt/jaq/TOOLS.md` is the in-image capability inventory and `jaq-tools` prints it. The controller resolves and runs the local image by immutable content ID. Docker supplies no network, no Linux capabilities, no privilege escalation, a read-only root filesystem, fixed UID/GID 65532, bounded CPU/memory/processes, one read-only staged PE mount, and disposable tmpfs storage at `/work` and `/tmp`. No host directory is writable from the container.

The model may choose arbitrary command strings, but the host always launches one fixed `docker exec` argv and the string is interpreted only by `/bin/bash` inside the offline container. The image contains static utilities, compilers, and a `pyc-disasm` wrapper that uses Python 3.14 `marshal`/`dis` without importing or executing recovered code. It intentionally excludes PE/.NET runtimes, emulators, Frida, and debugger tooling. The sample remains read-only and JAQ never launches it. Per-command and whole-run deadlines, container resource limits, forced container cleanup, model/tool/token/cost budgets, and early Pi compaction bound the run. Pi session files, raw provider traces, credentials, samples, generated runs, scratch files, and derived artifacts stay outside version control.

There is an unavoidable semantic boundary here: arbitrary helper code operating on PE bytes is Turing-complete, so a kernel cannot reliably distinguish a static decoder from a hand-written emulator. This milestone enforces the absence of native PE execution and supplied dynamic toolchains, while the investigator policy forbids emulation and runtime analysis. A future hard semantic guarantee would require replacing arbitrary commands with brokered transformations; that would conflict with the deliberately open-ended deobfuscation workflow selected for this milestone.

## Deferred milestones

This slice deliberately excludes dynamic analysis and its request/judge authorization flow, sample acquisition, MalwareBazaar, submissions, corpus/global correlation, campaign graphs, visualization, Temporal, PostgreSQL, production infrastructure, and novelty claims. Static commands must not execute, emulate, or debug the supplied PE.

The acquisition control plane is now present: evidence-backed remote stages may produce pending requests, and an operator may approve or deny requests. Operational assets are proposed by the final model and retained only when their exact values are supported by cited observations; JAQ does not promote regex matches automatically. Approved remote payloads are fetched in a separate bounded Docker invocation and analyzed as child runs. Dynamic approvals remain handoff-only until a dedicated dynamic sandbox exists.

## Acceptance boundary

Unit and integration tests generate a harmless PE fixture and exercise malformed input, sandbox startup/cleanup, MCP lifecycle and ID correlation, arbitrary-command isolation, output/time limits, incremental evidence IDs, invalid model tools, unsupported claims, hostile output, and mocked investigator/judge loops. The tagged Docker test verifies the live container, required static tools, read-only PE, offline posture, writable scratch, failed native PE execution, and cleanup.
