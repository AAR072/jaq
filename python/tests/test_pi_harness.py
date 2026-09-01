from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from jaq_investigator.evidence import EvidenceStore
from jaq_investigator.pi_harness import (
    PiHarnessConfig, PiHarnessError, PiHarnessRunner, PiInvestigator, PiToolBroker,
)
from jaq_investigator.prompts import INVESTIGATION_SCHEMA, RESEARCH_SCHEMA
from jaq_investigator.schemas import Observation


class FakeRuntime:
    def model_tools(self):
        return ({
            "type": "function",
            "function": {
                "name": "static_fixture",
                "description": "Fixture-only static runtime operation.",
                "parameters": {"type": "object", "additionalProperties": False, "properties": {}},
            },
        },)

    def execute(self, name, arguments):
        raise AssertionError(f"unexpected runtime call {name} {arguments}")


class PiHarnessProtocolTest(unittest.TestCase):
    def test_fake_pi_process_completes_through_broker_and_submit_claims(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            evidence_path = root / "observations.jsonl"
            observation = Observation(
                id="obs-native", type="artifact.hash.sha256", raw_value="a" * 64,
                normalized_value="a" * 64, artifact_location={"artifact": "sample"},
                analyzer={"name": "jaq-pe", "version": "0.1.0"}, provenance={"source": "fixture"},
            )
            evidence_path.write_text(json.dumps(observation.to_dict()) + "\n", encoding="utf-8")
            fake = root / "fake_harness.py"
            fake.write_text(
                """
import json, sys
init = json.loads(sys.stdin.readline())
assert init["type"] == "init"
assert init["mode"] == "harvest"
assert "submit_claims" not in {item["name"] for item in init["tool_definitions"]}
assert "static_fixture" not in {item["name"] for item in init["tool_definitions"]}
print(json.dumps({"type":"request","id":1,"operation":"execute_tool","payload":{"name":"list_observation_types","arguments":{}}}), flush=True)
reply = json.loads(sys.stdin.readline())
assert reply["ok"] is True
claims = {"schema_version":"1.0","claims":[{"schema_version":"1.0","id":"claim-1","classification":"fixture","explanation":"The fixture has a deterministic hash observation.","confidence":0.9,"evidence_ids":["obs-native"],"asset_role":"fixture","reachability":{"schema_version":"1.0","status":"unknown","entrypoints":[],"path_evidence_ids":[]},"unresolved":False}],"assets":[{"schema_version":"1.0","id":"asset-1","type":"payload_hash","value":"a"*64,"normalized_value":"a"*64,"role":"sample","confidence":1.0,"evidence_ids":["obs-native"],"unresolved":False}],"action_requests":[{"schema_version":"1.0","id":"request-1","kind":"dynamic_analysis","status":"pending_authorization","reason":"Recover a runtime-decrypted payload.","evidence_ids":["obs-native"],"target":{},"requested_observations":["decrypted_payload"]}]}
print(json.dumps({"type":"request","id":2,"operation":"validate_claims","payload":{"claims":claims}}), flush=True)
validated = json.loads(sys.stdin.readline())
assert validated["ok"] is True
print(json.dumps({"type":"complete","submission":validated["result"],"usage":{"input_tokens":10,"output_tokens":5,"cache_read_tokens":2,"cache_write_tokens":0,"total_tokens":17,"cost_usd":0.001,"provider_calls":2,"tool_calls":1},"session":{"id":"fake-session","file":"fake.jsonl"}}), flush=True)
""",
                encoding="utf-8",
            )
            config = PiHarnessConfig(
                model="deepseek/deepseek-v4-flash", node=sys.executable, script=fake,
                session_dir=root / "session", thinking_level="off",
                max_model_calls=4, max_tool_calls=4, max_total_tokens=1000,
                max_cost_usd=0.1, max_output_tokens=1000, tool_preview_chars=1000,
                max_context_tokens=1000, keep_recent_tokens=100,
            )
            store = EvidenceStore(evidence_path)
            result = PiHarnessRunner(config).run(
                PiToolBroker(store, FakeRuntime()), mode="harvest",
                output_schema=INVESTIGATION_SCHEMA,
                system_prompt="Static fixture investigator.", task="Inspect it.",
            )
            self.assertEqual(result.claims["claims"][0]["id"], "claim-1")
            self.assertEqual(result.claims["assets"][0]["id"], "asset-1")
            self.assertEqual(result.claims["action_requests"][0]["status"], "pending_authorization")
            self.assertEqual(result.usage["total_tokens"], 17)
            self.assertEqual(result.session["id"], "fake-session")
            broad = json.loads(json.dumps(result.claims))
            broad["action_requests"][0]["requested_observations"] = ["processes", "registry writes"]
            with self.assertRaises(PiHarnessError):
                PiToolBroker(store, FakeRuntime()).validate_claims(broad)
            omitted = json.loads(json.dumps(result.claims))
            omitted["assets"] = []
            recovered = PiToolBroker(store, FakeRuntime()).validate_claims(omitted)
            self.assertEqual(recovered["assets"][0]["type"], "payload_hash")

    def test_research_checkpoint_uses_phase_specific_contract(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            observation = Observation(
                id="obs-native", type="pe.string", raw_value="fixture",
                normalized_value="fixture", artifact_location={"artifact": "sample"},
                analyzer={"name": "jaq-pe", "version": "0.1.0"}, provenance={"source": "fixture"},
            )
            evidence_path = root / "observations.jsonl"
            evidence_path.write_text(json.dumps(observation.to_dict()) + "\n", encoding="utf-8")
            fake = root / "fake_research.py"
            fake.write_text(
                """
import json, sys
init = json.loads(sys.stdin.readline())
assert init["mode"] == "research"
assert "list_candidate_assets" not in {item["name"] for item in init["tool_definitions"]}
assert "static_fixture" in {item["name"] for item in init["tool_definitions"]}
checkpoint = {"schema_version":"1.0","research_complete":True,"summary":"Static research completed.","important_evidence_ids":["obs-native"],"unresolved_questions":[]}
print(json.dumps({"type":"request","id":1,"operation":"validate_research","payload":{"research":checkpoint}}), flush=True)
validated = json.loads(sys.stdin.readline())
assert validated["ok"] is True
print(json.dumps({"type":"complete","submission":validated["result"],"usage":{"total_tokens":3,"cost_usd":0.0,"provider_calls":1,"tool_calls":0},"session":{"id":"research","file":"research.jsonl"}}), flush=True)
""",
                encoding="utf-8",
            )
            config = PiHarnessConfig(
                model="deepseek/deepseek-v4-flash", node=sys.executable, script=fake,
                session_dir=root / "session", thinking_level="off", max_model_calls=2,
                max_tool_calls=2, max_total_tokens=1000, max_cost_usd=0.1,
                max_output_tokens=1000, tool_preview_chars=1000,
                max_context_tokens=1000, keep_recent_tokens=100,
            )
            result = PiHarnessRunner(config).run(
                PiToolBroker(EvidenceStore(evidence_path), FakeRuntime()), mode="research",
                output_schema=RESEARCH_SCHEMA, system_prompt="Research only.", task="Inspect it.",
            )
            self.assertTrue(result.submission["research_complete"])
            self.assertEqual(result.submission["important_evidence_ids"], ["obs-native"])

    def test_pi_investigator_runs_fresh_research_and_harvest_sessions(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "output"
            output.mkdir()
            observation = Observation(
                id="obs-native", type="artifact.hash.sha256", raw_value="b" * 64,
                normalized_value="b" * 64, artifact_location={"artifact": "sample"},
                analyzer={"name": "jaq-pe", "version": "0.1.0"}, provenance={"source": "fixture"},
            )
            evidence_path = output / "observations.jsonl"
            evidence_path.write_text(json.dumps(observation.to_dict()) + "\n", encoding="utf-8")
            fake = root / "fake_two_phase.py"
            fake.write_text(
                """
import json, sys
init = json.loads(sys.stdin.readline())
if init["mode"] == "research":
    assert init["session_dir"].endswith("/model-session/research")
    assert "candidate-inventory" not in init["task"]
    value = {"schema_version":"1.0","research_complete":True,"summary":"Found the sample hash.","important_evidence_ids":["obs-native"],"unresolved_questions":[]}
    operation, field = "validate_research", "research"
else:
    assert "/model-session/harvest" in init["session_dir"]
    assert "candidate-inventory" in init["task"]
    assert "list_candidate_assets" in {item["name"] for item in init["tool_definitions"]}
    value = {"schema_version":"1.0","claims":[{"schema_version":"1.0","id":"claim-1","classification":"fixture","explanation":"The sample has a persisted hash.","confidence":1.0,"evidence_ids":["obs-native"],"asset_role":"sample","reachability":{"schema_version":"1.0","status":"unknown","entrypoints":[],"path_evidence_ids":[]},"unresolved":False}],"assets":[],"action_requests":[]}
    operation, field = "validate_claims", "claims"
print(json.dumps({"type":"request","id":1,"operation":operation,"payload":{field:value}}), flush=True)
validated = json.loads(sys.stdin.readline())
assert validated["ok"] is True
print(json.dumps({"type":"complete","submission":validated["result"],"usage":{"input_tokens":10,"output_tokens":2,"total_tokens":12,"cost_usd":0.001,"provider_calls":1,"tool_calls":0},"session":{"id":init["mode"],"file":init["mode"]+".jsonl"}}), flush=True)
""",
                encoding="utf-8",
            )
            environment = {
                "JAQ_INVESTIGATOR_MODEL": "deepseek/deepseek-v4-flash",
                "JAQ_HARVESTER_MODEL": "deepseek/deepseek-v4-flash",
                "JAQ_PI_HARNESS": str(fake),
                "JAQ_NODE": sys.executable,
            }
            with patch.dict(os.environ, environment, clear=False):
                investigator = PiInvestigator(EvidenceStore(evidence_path), FakeRuntime(), output)
                dossier = investigator.run("Inspect the fixture.")
            self.assertEqual(dossier["claims"][0]["id"], "claim-1")
            self.assertEqual(dossier["assets"][0]["type"], "payload_hash")
            self.assertTrue((output / "research.json").is_file())
            self.assertEqual(investigator.last_run.usage["total_tokens"], 24)
            self.assertEqual(investigator.last_run.usage["cost_microusd"], 2000)
            checkpoint = json.loads((output / "research.json").read_text(encoding="utf-8"))
            retried = investigator.harvest(checkpoint)
            self.assertEqual(retried["claims"][0]["id"], "claim-1")
            self.assertTrue((output / "model-session" / "harvest-2").is_dir())
            self.assertEqual(investigator.last_run.usage["total_tokens"], 12)


if __name__ == "__main__":
    unittest.main()
