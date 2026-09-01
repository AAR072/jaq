from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from jaq_investigator.evidence import EvidenceStore
from jaq_investigator.investigator import EvidenceToolError, Investigator, InvestigatorConfig
from jaq_investigator.model import ModelResponse, ToolCall
from jaq_investigator.schemas import Observation


class RecordingRuntime:
    def __init__(self, store):
        self.store = store
        self.closed = False

    def model_tools(self):
        return ({
            "type": "function",
            "function": {
                "name": "run_static_command",
                "description": "Run an offline helper.",
                "parameters": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]},
            },
        },)

    def execute(self, name, arguments):
        request = self.store.append_tool_request(
            source="static-sandbox", version="1.0", tool_name=name,
            arguments=arguments, sample_sha256="a" * 64, sequence=1,
        )
        result = self.store.append_tool_result(
            request_id=request.id, source="static-sandbox", version="1.0",
            tool_name=name, result={"stdout": "decoded-config", "returncode": 0},
            sample_sha256="a" * 64, sequence=1, status="ok", duration_ms=1,
        )
        return {
            "observation_id": result.id,
            "status": "ok",
            "untrusted_static_result": {"stdout": "decoded-config", "returncode": 0},
        }

    def close(self):
        self.closed = True


class AdaptiveClient:
    model = "mock/investigator"
    provider = "mock"

    def __init__(self):
        self.calls = 0

    def generate_structured(self, **kwargs):
        self.calls += 1
        if self.calls == 1:
            return ModelResponse(tool_calls=(ToolCall("run_static_command", {"command": "python3 decode.py"}, "tool-1"),))
        tool_messages = [item for item in kwargs["messages"] if item["role"] == "tool"]
        envelope = json.loads(tool_messages[-1]["content"])
        evidence_id = envelope["data"]["observation_id"]
        return ModelResponse(structured={
            "schema_version": "1.0",
            "claims": [{
                "schema_version": "1.0", "id": "claim-1",
                "classification": "decoded_asset", "explanation": "The offline helper recovered a configuration marker.",
                "confidence": 0.7, "evidence_ids": [evidence_id], "asset_role": "configuration",
                "reachability": {"schema_version": "1.0", "status": "unknown", "entrypoints": [], "path_evidence_ids": []},
                "unresolved": False,
            }],
        })


class UnpersistedRuntime(RecordingRuntime):
    def execute(self, name, arguments):
        return {
            "observation_id": "obs-native",
            "status": "ok",
            "untrusted_static_result": {"stdout": "not in the ledger"},
        }


class AgentIntegrationTest(unittest.TestCase):
    def test_model_sees_only_persisted_tool_result(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "observations.jsonl"
            native = Observation(
                id="obs-native", type="artifact.hash.sha256", raw_value="a" * 64,
                normalized_value="a" * 64, artifact_location={"artifact": "sample"},
                analyzer={"name": "jaq-pe", "version": "0.1.0"}, provenance={"source": "fixture"},
            )
            path.write_text(json.dumps(native.to_dict()) + "\n", encoding="utf-8")
            store = EvidenceStore(path)
            runtime = RecordingRuntime(store)
            claims = Investigator(
                store, client=AdaptiveClient(), tool_runtime=runtime,
                config=InvestigatorConfig(model="mock/investigator"),
            ).run()
            cited = claims["claims"][0]["evidence_ids"][0]
            self.assertIsNotNone(store.get(cited))
            self.assertEqual(store.get(cited).type, "static-sandbox.tool_result")
            self.assertEqual(len(path.read_text(encoding="utf-8").splitlines()), 3)

    def test_runtime_cannot_relabel_existing_native_evidence_as_a_tool_result(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "observations.jsonl"
            native = Observation(
                id="obs-native", type="artifact.hash.sha256", raw_value="a" * 64,
                normalized_value="a" * 64, artifact_location={"artifact": "sample"},
                analyzer={"name": "jaq-pe", "version": "0.1.0"}, provenance={"source": "fixture"},
            )
            path.write_text(json.dumps(native.to_dict()) + "\n", encoding="utf-8")
            store = EvidenceStore(path)
            with self.assertRaises(EvidenceToolError):
                Investigator(
                    store, client=AdaptiveClient(), tool_runtime=UnpersistedRuntime(store),
                    config=InvestigatorConfig(model="mock/investigator"),
                ).run()


if __name__ == "__main__":
    unittest.main()
