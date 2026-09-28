# JAQ

JAQ is an autonomous, evidence-first static investigator for Windows PE files. DeepSeek drives Radare2 MCP and arbitrary helper commands inside a network-disabled disposable container; JAQ never launches the supplied PE.

## Quick start

Prerequisites are Go 1.24+, Python 3.11+, Node 22.19+, and Docker with its daemon running. Install the Python post-processing package and the pinned Pi SDK, then build the static sandbox and CLI:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[llm]'
npm install --ignore-scripts
make sandbox-image
make build
```

Choose a LiteLLM provider/model string and keep its provider key in the environment:

```sh
export JAQ_INVESTIGATOR_MODEL='deepseek/deepseek-flash'
export DEEPSEEK_API_KEY='...'
./bin/jaq analyze --sample /absolute/path/to/sample.exe --output /absolute/path/to/runs/example
```

For the normal local workflow, put those two assignments in the gitignored `.env` and run:

```sh
./scripts/jaq-run /absolute/path/to/sample.exe
```

The wrapper loads `.env`, activates `.venv` when present, builds the CLI if needed, and writes to a fresh timestamped directory under `runs/`. Supply an absolute second argument to choose a different output directory.

DeepSeek V4.1 Flash uses the API ID `deepseek-flash`. JAQ includes a compatibility entry for its pinned SDK and estimates costs at published peak rates, so off-peak billing can be lower. The old `deepseek-v4-flash` API alias uses the same updated estimate.

The offline image includes native PE tooling, capa with pinned offline rules/signatures, PyInstaller extraction, Python 3.14 marshal/bytecode disassembly, .NET metadata/CIL libraries, archive/installer extractors, YARA, common decoding/crypto utilities, and pinned GoReSym 3.4 metadata recovery. It automatically records a bounded Go clone/residue profile with conservative Windows `LazyProc`/`LazyDLL` target resolution, so repeated junk-like blocks cannot outrank unique application calls and unresolved indirect paths cannot support negative capability claims. For binaries otherwise identified as Go, the model conditionally runs GoReSym when `go-profile` reports `not_go`/`partial` because `main.*` symbols are missing or pclntab recovery is needed, then correlates recovered addresses with static disassembly. GoReSym recovers Go build/pclntab/function/type/string metadata from stripped or malformed/unpacked binaries; it does not resolve `LazyProc`/`Syscall` targets or prove behavior. A parser failure is not negative evidence, and Redress is not included. Inside the sandbox, `jaq-tools` prints the installed inventory from `/opt/jaq/TOOLS.md`; tools are ordinary commands and libraries on `PATH`, not additional model APIs.

Runs emit safe structured progress without exposing model prose, sample strings, commands, endpoints, or credentials. Specialized analysis tools are shown immediately; repeated static-command work and model/cost counters are summarized periodically:

```text
jaq: [research] started
jaq: [research] tool #8: r2_decompile_function
jaq: [research] model calls=10 tools=14 cost=$0.00642
jaq: [research] checkpoint compiled locally from persisted evidence
jaq: [report] started
jaq: [report] tool #3: record_finding
jaq: [report] dossier compiled locally from 8 recorded findings
```

Set `JAQ_JUDGE_MODEL` to enable the optional independent judge. The judge may use a different LiteLLM provider; no second key is required for mocked tests.

The investigator uses two isolated Pi sessions with different jobs. The research session has Radare2 and the offline command sandbox, persists every tool result, and focuses on recovering application-owned code, behavior, and every phone-home path; it has no finding/reporting tool. A fresh reporter receives the research summary and selected evidence, can read persisted observations, and appends small intelligence records through `record_finding`. It has no Radare, command, filesystem, network, or dynamic-analysis capability. At completion JAQ locally compiles `research.json`, `claims.json`, `communications.json`, `assets.json`, and `requests.json`; neither session submits a giant final JSON object. Exact-value assets must occur in cited evidence, and incidental regex matches are not promoted automatically.

Research is cost-governed by default: there is no model-call, tool-call, or cumulative-token stopping limit unless `JAQ_MAX_MODEL_CALLS`, `JAQ_MAX_TOOL_CALLS`, or `JAQ_MAX_TOTAL_TOKENS` is explicitly set. `JAQ_MAX_COST_USD` defaults to `$0.10`; at exhaustion all research tools close and one tool-free summary call remains available. The reporter has a separate default `$0.03` budget, 20 model calls, and 100 evidence/finding tool calls; configure it with `JAQ_REPORTER_MODEL`, `JAQ_REPORTER_THINKING`, and `JAQ_REPORT_*` variables. If its cap is reached, evidence-reading closes, accepted findings remain durable, and bounded record-only flushes run before completion. The controller retains a 30-minute stage timeout. Coverage gaps become unresolved warnings instead of rejecting the run. Full research results remain in `observations.jsonl`, while the Markdown report renders bounded evidence previews rather than duplicating raw output.

`JAQ_INACTIVITY_TIMEOUT_SECONDS` defaults to `300`. If research emits no progress, tool request, or completion frame for that interval, JAQ terminates the stalled Pi child and compiles the evidence already produced into a partial dossier. `JAQ_REPORT_INACTIVITY_TIMEOUT_SECONDS` optionally sets the reporter timeout independently.

Finalization is local: the research checkpoint is saved before reporting begins, and accepted findings are durable immediately. The reporter can search and page through complete persisted observations with `read_evidence`; it is not limited to truncated previews. When its final finding flush ends, JAQ compiles the report without another model-summary request. The report opens with a locally composed overview of accepted claims and retains the research narrative in an explicitly unverified notes section. Empty asset or communication sections mean nothing was recorded, not that the capability is absent. The CLI prints the final run status.

The opening summary contains up to five concise finding titles, prioritizing distinct behavior scopes. `tags.json` exports the versioned `jaq-intelligence-v1` taxonomy: explicit behavior scopes, asset types, and request kinds with source record IDs, evidence IDs, and verification status. Tags are not independent verdicts or ATT&CK/family assignments. Network communication records also retain their claim's verification status.

Every compilation, including model-free recovery, indexes literal HTTP(S) URLs from successful analyzer results and native sample strings. `assets.json.recovered_urls` preserves these values and their evidence separately from the model-recorded `assets` array; it never labels a regex match as C2 or triggers acquisition. The reporter receives this compact index before bulk evidence, so URLs are visible even when a large observation was truncated. Unclassified URLs remain visible at the front of the report after reporter failure or budget exhaustion. The index is bounded to 500 distinct URLs of at most 2,048 characters, reports omitted occurrences, and does not recover encoded/computed destinations or every bare domain/IP. See [OUTPUT_CONTRACT.md](OUTPUT_CONTRACT.md) for field meanings.

Completion is quality-gated: at least one application claim must be accepted, analyzer health checks and deobfuscation coverage must be complete, and no core analysis blocker may remain. Otherwise every finding is preserved but the run is marked `partial`. Static “benign/safe” certifications are never accepted, incorrect abbreviated hashes are rejected, and negative capability claims are downgraded when application-owned crypto, unresolved dynamic calls, or analyzer failures contradict them.

The output directory must be new or empty. A completed run contains `run-manifest.json`, `observations.jsonl`, `findings.jsonl`, `research.json`, `claims.json`, `communications.json`, `assets.json`, `requests.json`, `tags.json`, `score.json`, and `report.md`; JAQ refuses to overwrite an existing run. `findings.jsonl` is the append-only semantic audit trail. `communications.json` lists the recovered exfiltration and command/control paths. `assets.json` retains the complete flat asset list and adds full-value categories for credentials/tokens, all communication endpoints, the attacker-controlled subset, payloads, execution/persistence, contacts/financial, configuration, and other assets. A secret-bearing webhook appears as both a credential and communication endpoint, while legitimate provider APIs are not labeled attacker infrastructure. The Markdown report presents the same explicit sections. Unsupported positive reachability is downgraded to `unknown` without rejecting an otherwise evidence-backed finding. Action requests begin as evidence-backed `pending_authorization` records. JAQ can fetch an explicitly approved remote payload in its bounded fetch container; it still does not perform dynamic analysis.

If a run retains analysis evidence or incremental findings but fails before publishing the final files, reuse the persisted work instead of paying to reverse the sample again:

```sh
./scripts/jaq-harvest /absolute/path/to/existing/run
```

For recovery with **no model calls**, including when the provider is unavailable or the run has no findings yet:

```sh
./scripts/jaq-harvest --compile-only /absolute/path/to/existing/run
```

This compiles saved findings and research notes, preserves limitations, and requires neither `.env`, Node, a provider key, nor Docker. It does not overwrite published dossier files. The Go controller automatically attempts this same bounded local recovery when its investigator process fails or reaches the stage deadline; the original error remains explicit and the run remains partial. Force-killing the controller itself requires the recovery command.

When `research.json` is missing, the wrapper compiles it locally from the persisted evidence ledger. When `findings.jsonl` contains records, the final dossier is compiled locally with no model call. When it is empty, the same fresh incremental reporter runs over the saved research without rerunning Radare. Recovery never uses an atomic terminal dossier submission.

Normal analysis uses the same zero-cost fallback automatically if the final prose summary is unavailable: persisted tool evidence still becomes a valid partial checkpoint without another model call. Provider authentication, balance, timeout, and cancellation failures remain explicit and recoverable; they are not disguised as terminal-call failures.

Each reporter `record_finding` call is validated independently. A required intelligence scope permits application behavior, credentials, infrastructure, persistence, impact, payloads, configuration, and concrete blockers; packaging, parser, interpreter, library, and tooling-progress scopes are not available. JAQ assigns stable IDs, deduplicates repeated assets and requests, preserves factual asset values byte-for-byte, and rejects missing evidence or unsupported exact values before appending. Runs containing only blockers are marked `partial` rather than falsely `completed`.

Review and decide requests explicitly:

```sh
./bin/jaq requests --run /absolute/path/to/run
./bin/jaq approve --run /absolute/path/to/run --request request-1
./bin/jaq deny --run /absolute/path/to/run --request request-2
```

An approved `fetch_remote_payload` uses a disposable, rootless Docker fetch with no host mounts, redirects disabled, a 64 MiB limit, and a 45-second deadline. A fetched PE receives a child JAQ run linked by `parent-request.json`. Dynamic-analysis approvals create an `awaiting_external_executor` handoff only; JAQ still has no dynamic executor.

Run the credential-free test suite with `make test`. After building the image, verify the real offline container with `go test -tags=integration ./internal/sandbox -run TestPersistentSandboxRuntimeContract -v`. A live model run remains operator-triggered. Dynamic analysis is deliberately absent. See [TECHNICAL_VISION.md](TECHNICAL_VISION.md) for the detailed trust boundary.
