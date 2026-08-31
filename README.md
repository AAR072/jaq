# JAQ

JAQ is a local, evidence-first static investigator for Windows PE files. Milestone 1 never executes a sample and confines Ghidra to a network-disabled, rootless container.

## Quick start

Prerequisites are Go 1.24+, Python 3.11+, and Docker with its daemon running. Install the local Python package with the LiteLLM extra, then build the analyzer and CLI:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[llm]'
make analyzer-image
make build
```

Choose a LiteLLM provider/model string and keep its provider key in the environment:

```sh
export JAQ_INVESTIGATOR_MODEL='deepseek/deepseek-chat'
export DEEPSEEK_API_KEY='...'
./bin/jaq analyze --sample /absolute/path/to/sample.exe --output ./runs/example
```

Set `JAQ_JUDGE_MODEL` to enable the optional independent judge. The judge may use a different LiteLLM provider; no second key is required for mocked tests.

The output directory must be new or empty. A completed run contains `run-manifest.json`, `observations.jsonl`, `claims.json`, `score.json`, and `report.md`; JAQ refuses to overwrite an existing run.

Run the credential-free test suite with `make test`. The Docker contract is tested without a daemon, while the image build and a live model run remain operator-triggered acceptance steps. See [TECHNICAL_VISION.md](TECHNICAL_VISION.md) for the trust model and deferred scope.
