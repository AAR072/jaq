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
export JAQ_INVESTIGATOR_MODEL='deepseek/deepseek-v4-flash'
export DEEPSEEK_API_KEY='...'
./bin/jaq analyze --sample /absolute/path/to/sample.exe --output /absolute/path/to/runs/example
```

For the normal local workflow, put those two assignments in the gitignored `.env` and run:

```sh
./scripts/jaq-run /absolute/path/to/sample.exe
```

The wrapper loads `.env`, activates `.venv` when present, builds the CLI if needed, and writes to a fresh timestamped directory under `runs/`. Supply an absolute second argument to choose a different output directory.

Runs emit safe structured progress without exposing model prose, sample strings, commands, endpoints, or credentials. Specialized analysis tools are shown immediately; repeated static-command work and model/cost counters are summarized periodically:

```text
jaq: [research] started
jaq: [research] tool #8: r2_decompile_function
jaq: [research] tool #9: record_finding
jaq: [research] model calls=10 tools=14 cost=$0.00642
jaq: [research] preparing final summary at cost=$0.10000
jaq: [research] checkpoint compiled locally from persisted evidence
```

Set `JAQ_JUDGE_MODEL` to enable the optional independent judge. The judge may use a different LiteLLM provider; no second key is required for mocked tests.

The investigator uses one Pi research session. It performs static reverse engineering with Radare2 and the offline command sandbox and persists every tool result. Whenever DeepSeek understands an important behavior, credential, token, username/password, C2 endpoint, URL, payload reference, configuration value, or follow-up need, it calls the small `record_finding` tool. JAQ validates the cited evidence and immediately appends the accepted semantic record to `findings.jsonl`. At completion JAQ locally compiles `research.json`, `claims.json`, `assets.json`, and `requests.json`; there is no mandatory harvest model, giant final JSON submission, or formatting retry loop. Exact-value assets must occur in cited evidence, and incidental regex matches are not promoted automatically.

Research is cost-governed by default: there is no model-call, tool-call, or cumulative-token stopping limit unless `JAQ_MAX_MODEL_CALLS`, `JAQ_MAX_TOOL_CALLS`, or `JAQ_MAX_TOTAL_TOKENS` is explicitly set. `JAQ_MAX_COST_USD` defaults to `$0.10`; these limits apply to evidence-gathering. At a limit, JAQ closes every research tool and permits exactly one reporting-only model call, with thinking disabled and output capped by `JAQ_SUMMARY_MAX_OUTPUT_TOKENS` (default 4,096). The resulting prose is incorporated into the locally compiled checkpoint. At most two internal Pi compaction calls may precede that final summary, and neither can invoke tools. The controller retains a 30-minute stage timeout as an emergency wall-clock bound. Coverage gaps in application entrypoint analysis, disassembly/decompilation, call/xref work, or deobfuscation are recorded as unresolved warnings rather than rejecting the run. Full research tool results remain in the evidence ledger, while Pi receives bounded previews and automatically compacts older research context.

The output directory must be new or empty. A completed run contains `run-manifest.json`, `observations.jsonl`, `findings.jsonl`, `research.json`, `claims.json`, `assets.json`, `requests.json`, `score.json`, and `report.md`; JAQ refuses to overwrite an existing run. `findings.jsonl` is the append-only semantic audit trail. `assets.json` retains the complete flat asset list and adds full-value `categories` for credentials/tokens, C2/infrastructure, payloads, execution/persistence, contacts/financial, configuration, and other assets. The Markdown report presents the same explicit sections. Unsupported positive reachability is downgraded to `unknown` without rejecting an otherwise evidence-backed finding. Action requests begin as evidence-backed `pending_authorization` records. JAQ can fetch an explicitly approved remote payload in its bounded fetch container; it still does not perform dynamic analysis.

If a run retains analysis evidence or incremental findings but fails before publishing the final files, reuse the persisted work instead of paying to reverse the sample again:

```sh
./scripts/jaq-harvest /absolute/path/to/existing/run
```

When `research.json` is missing, the wrapper compiles it locally from the persisted evidence ledger. When `findings.jsonl` contains records, the final dossier is also compiled locally with no model call and without rerunning Radare. Older runs created before the findings ledger can still use the legacy bounded harvest compatibility path.

Normal analysis uses the same zero-cost fallback automatically if the final prose summary is unavailable: persisted tool evidence still becomes a valid partial checkpoint without another model call. Provider authentication, balance, timeout, and cancellation failures remain explicit and recoverable; they are not disguised as terminal-call failures.

Each `record_finding` call is validated independently while the relevant evidence is still in the model's immediate context. JAQ assigns stable IDs, deduplicates repeated assets and requests, preserves factual asset values byte-for-byte, and rejects missing evidence or unsupported exact values before appending the record. The original tool arguments remain in the private `model-session` JSONL for audit.

Review and decide requests explicitly:

```sh
./bin/jaq requests --run /absolute/path/to/run
./bin/jaq approve --run /absolute/path/to/run --request request-1
./bin/jaq deny --run /absolute/path/to/run --request request-2
```

An approved `fetch_remote_payload` uses a disposable, rootless Docker fetch with no host mounts, redirects disabled, a 64 MiB limit, and a 45-second deadline. A fetched PE receives a child JAQ run linked by `parent-request.json`. Dynamic-analysis approvals create an `awaiting_external_executor` handoff only; JAQ still has no dynamic executor.

Run the credential-free test suite with `make test`. After building the image, verify the real offline container with `go test -tags=integration ./internal/sandbox -run TestPersistentSandboxRuntimeContract -v`. A live model run remains operator-triggered. Dynamic analysis is deliberately absent. See [TECHNICAL_VISION.md](TECHNICAL_VISION.md) for the detailed trust boundary.
