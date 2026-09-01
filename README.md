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
./bin/jaq analyze --sample /absolute/path/to/sample.exe --output ./runs/example
```

Set `JAQ_JUDGE_MODEL` to enable the optional independent judge. The judge may use a different LiteLLM provider; no second key is required for mocked tests.

The investigator runs through the host-side Pi SDK with only JAQ tools enabled. Defaults cap one run at 12 model calls, 40 tool calls, 500,000 cumulative tokens, and an estimated $0.10. Override them with `JAQ_MAX_MODEL_CALLS`, `JAQ_MAX_TOOL_CALLS`, `JAQ_MAX_TOTAL_TOKENS`, and `JAQ_MAX_COST_USD`. Full tool results remain in the evidence ledger; Pi receives bounded previews and automatically compacts older context.

The output directory must be new or empty. A completed run contains `run-manifest.json`, `observations.jsonl`, `claims.json`, `assets.json`, `requests.json`, `score.json`, and `report.md`; JAQ refuses to overwrite an existing run. Action requests are evidence-backed `pending_authorization` placeholders only: this milestone does not fetch remote payloads or perform dynamic analysis.

Run the credential-free test suite with `make test`. After building the image, verify the real offline container with `go test -tags=integration ./internal/sandbox -run TestPersistentSandboxRuntimeContract -v`. A live model run remains operator-triggered. Dynamic analysis is deliberately absent. See [TECHNICAL_VISION.md](TECHNICAL_VISION.md) for the detailed trust boundary.
