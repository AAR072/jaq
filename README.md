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

Set `JAQ_JUDGE_MODEL` to enable the optional independent judge. The judge may use a different LiteLLM provider; no second key is required for mocked tests.

The investigator uses two fresh Pi sessions. The research session performs static reverse engineering with Radare2 and the offline command sandbox, persists every tool result, and writes `research.json`. A smaller terminal-only harvest session receives the research checkpoint and a bounded bundle of important evidence directly in its prompt, then produces claims, credentials, tokens, usernames/passwords, C2 infrastructure, URLs, payload references, and action requests. Its only tool is `submit_investigation`; it cannot explore with Radare2, shell, filesystem, network, or evidence tools. Model-submitted assets must cite evidence containing their exact values; incidental regex matches are not promoted automatically.

Research is cost-governed by default: there is no model-call, tool-call, or cumulative-token stopping limit unless `JAQ_MAX_MODEL_CALLS`, `JAQ_MAX_TOOL_CALLS`, or `JAQ_MAX_TOTAL_TOKENS` is explicitly set. `JAQ_MAX_COST_USD` defaults to `$0.10`; the controller retains a 30-minute stage timeout as an emergency wall-clock bound. A research checkpoint is rejected unless persisted evidence shows a successful Radare analysis (`r2_analyze` or equivalent `r2 -A`), application entrypoint coverage, disassembly/decompilation of at least three application addresses, call-tree/xref work, and an evidence-backed deobfuscation assessment or attempt. Harvest has a separate default budget of 5 model calls, 180,000 tokens, and `$0.03`; override it with the corresponding `JAQ_HARVEST_MAX_*` variables. `JAQ_HARVESTER_MODEL` optionally selects a different provider/model and defaults to `JAQ_INVESTIGATOR_MODEL`; `JAQ_HARVESTER_THINKING` defaults to `off`. Full research tool results remain in the evidence ledger, while Pi receives bounded previews and automatically compacts older research context.

The output directory must be new or empty. A completed run contains `run-manifest.json`, `observations.jsonl`, `research.json`, `claims.json`, `assets.json`, `requests.json`, `score.json`, and `report.md`; JAQ refuses to overwrite an existing run. Action requests begin as evidence-backed `pending_authorization` records. JAQ can fetch an explicitly approved remote payload in its bounded fetch container; it still does not perform dynamic analysis.

If the provider fails only during the final harvest, reuse the completed research instead of paying to reverse the sample again:

```sh
./scripts/jaq-harvest /absolute/path/to/existing/run
```

Each retry receives a fresh `model-session/harvest-N` directory and still cannot access the static sandbox.

Review and decide requests explicitly:

```sh
./bin/jaq requests --run /absolute/path/to/run
./bin/jaq approve --run /absolute/path/to/run --request request-1
./bin/jaq deny --run /absolute/path/to/run --request request-2
```

An approved `fetch_remote_payload` uses a disposable, rootless Docker fetch with no host mounts, redirects disabled, a 64 MiB limit, and a 45-second deadline. A fetched PE receives a child JAQ run linked by `parent-request.json`. Dynamic-analysis approvals create an `awaiting_external_executor` handoff only; JAQ still has no dynamic executor.

Run the credential-free test suite with `make test`. After building the image, verify the real offline container with `go test -tags=integration ./internal/sandbox -run TestPersistentSandboxRuntimeContract -v`. A live model run remains operator-triggered. Dynamic analysis is deliberately absent. See [TECHNICAL_VISION.md](TECHNICAL_VISION.md) for the detailed trust boundary.
