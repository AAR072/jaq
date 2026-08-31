# JAQ Technical Vision

## Milestone 1: Autonomous Static PE Investigator

JAQ's first milestone is a local, evidence-first vertical slice for defensively investigating a manually supplied Windows Portable Executable. The sample is inert input: JAQ validates and hashes it, mounts it read-only into a network-disabled static-analysis container, and never executes it or contacts any endpoint it contains.

The command-line contract is:

```text
jaq analyze --sample <absolute-path> --output <directory>
```

Go is the trusted controller. It validates the input, records a versioned run manifest, performs deterministic lightweight PE extraction, invokes the pinned Ghidra container with resource and privilege restrictions, merges the evidence package, launches the bounded Python investigator, and validates every persisted output before accepting a run. Stage failures and timeouts are recorded in the manifest.

Python is the untrusted-model boundary. The investigator can only use typed, read-only queries over `observations.jsonl`; it has no shell, general filesystem operation, or network tool. LiteLLM sits behind a project-owned `ModelClient`, while logical `investigator` and optional `judge` roles select provider/model strings through configuration. Provider credentials remain in environment variables understood by LiteLLM and are never persisted in prompts, traces, manifests, or reports.

All binary-derived text is hostile data. Strings, symbol names, decompiler output, comments, resources, and embedded documents are delimited as evidence and never promoted to instructions. Model claims must conform to a versioned schema and cite observation IDs. Deterministic verification checks schema constraints, evidence existence, extracted values, reference relationships, and reachability claims where the evidence supports them. An optional independent judge adds a `supported`, `unsupported`, or `unclear` verdict; the pipeline remains fully testable with mocked clients and no provider credentials.

Each completed run writes:

- `run-manifest.json`: hashes, versions, configuration and prompt hashes, role metadata, status, timestamps, and resource usage.
- `observations.jsonl`: deterministic, typed, provenance-bearing facts.
- `claims.json`: structured investigator claims and evidence references.
- `score.json`: verification results, optional judgments, and model usage.
- `report.md`: an evidence-backed analyst dossier.

Formats are versioned and validated at every trust boundary. Comparable runs use content-derived observation IDs, normalized ordering, pinned analyzer versions, and complete configuration metadata; wall-clock timestamps and resource usage are intentionally run-specific.

## Security and isolation

The Ghidra 12.1.3 image uses the official public release archive and SHA-256 checksum. At runtime Docker supplies no network, no Linux capabilities, no privilege escalation, a read-only root filesystem, a non-root UID/GID, bounded processes and memory, a read-only single-file sample mount, and disposable in-memory project/temp storage. Only the evidence output directory is writable. The image and controller expose no dynamic-analysis path.

The host controller never interprets extracted endpoints as destinations. The investigator receives evidence records through an allowlisted in-process API, not paths or commands. Output paths are controller-selected and model responses cannot change them. Raw provider traces, credentials, samples, generated runs, Ghidra projects, and artifacts stay outside version control.

## Deferred milestones

This slice deliberately excludes sample acquisition, MalwareBazaar, submission workflows, corpus/global correlation, campaign graphs, visualization, dynamic execution, Temporal, PostgreSQL, production infrastructure, and novelty claims. It may record candidate hidden assets and scoring hooks, but global novelty requires a later prospective corpus evaluation.

## Acceptance boundary

Unit and integration tests generate a harmless PE fixture in memory and exercise malformed inputs, analyzer crashes and timeouts, missing models, invalid tool calls, unsupported claims, prompt-like hostile strings, and mocked investigator/judge loops. Container contract tests verify the isolation arguments without requiring a running daemon. A live acceptance run is intentionally operator-triggered after Docker is started and a provider model/key is supplied through the environment.
