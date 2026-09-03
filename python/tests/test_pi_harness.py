from __future__ import annotations

from contextlib import redirect_stderr
import io
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from jaq_investigator.cli import finalize_research_only, run_pipeline
from jaq_investigator.evidence import EvidenceStore
from jaq_investigator.pi_harness import (
    PiHarnessConfig, PiHarnessError, PiHarnessRunner, PiInvestigator, PiToolBroker,
    _emit_progress,
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

    def close(self):
        return None


def coverage_observations() -> list[Observation]:
    observations: list[Observation] = []
    tools = [
        ("r2_analyze", {}),
        ("r2_decompile_function", {"address": "0x1000"}),
        ("r2_disassemble_function", {"address": "0x1100"}),
        ("r2_disassemble", {"address": "0x1200"}),
        ("r2_xrefs_to", {"address": "0x1000"}),
    ]
    for index, (tool, arguments) in enumerate(tools):
        request_id = f"req-coverage-{index}"
        result_id = f"obs-coverage-{index}"
        observations.append(Observation(
            id=request_id, type="radare2-mcp.tool_request",
            raw_value={"tool": tool, "arguments": arguments},
            normalized_value={"tool": tool, "sequence": index},
            artifact_location={"artifact": "sample"},
            analyzer={"name": "fixture", "version": "1"},
            provenance={"source": "fixture", "stage": "agent-tool-request"},
            metadata={"tool_name": tool, "sequence": index},
        ))
        observations.append(Observation(
            id=result_id, type="radare2-mcp.tool_result",
            raw_value={"tool": tool, "result": {"ok": True}},
            normalized_value={"tool": tool, "status": "ok", "result": {"ok": True}},
            artifact_location={"artifact": "sample"},
            analyzer={"name": "fixture", "version": "1"},
            provenance={
                "source": "fixture", "stage": "agent-tool-result",
                "parent_observation_ids": [request_id],
            },
            metadata={"tool_name": tool, "status": "ok", "sequence": index},
        ))
    return observations


def coverage_checkpoint(important_id: str) -> dict:
    coverage_ids = [f"obs-coverage-{index}" for index in range(5)]
    return {
        "schema_version": "1.0", "research_complete": True,
        "summary": "Application entrypoint and three functions were analyzed.",
        "important_evidence_ids": [important_id, *coverage_ids],
        "unresolved_questions": [],
        "coverage": {
            "application_entrypoints": [{
                "name": "main", "address": "0x1000", "evidence_ids": ["obs-coverage-1"],
            }],
            "analyzed_functions": [
                {"name": "main", "address": "0x1000", "purpose": "entry", "evidence_ids": ["obs-coverage-1"]},
                {"name": "worker", "address": "0x1100", "purpose": "worker", "evidence_ids": ["obs-coverage-2"]},
                {"name": "decode", "address": "0x1200", "purpose": "decoder", "evidence_ids": ["obs-coverage-3"]},
            ],
            "call_graph_evidence_ids": ["obs-coverage-4"],
            "deobfuscation_attempts": [{
                "technique": "semantic function recovery", "status": "partial",
                "outcome": "Three application functions classified.",
                "evidence_ids": ["obs-coverage-1", "obs-coverage-2", "obs-coverage-3"],
            }],
            "recovered_artifacts": [],
        },
    }


class PiHarnessProtocolTest(unittest.TestCase):
    def test_recovery_cli_compiles_research_without_removed_checkpoint_api(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "output"
            output.mkdir()
            evidence_path = output / "observations.jsonl"
            evidence_path.write_text(
                "".join(json.dumps(item.to_dict()) + "\n" for item in coverage_observations()),
                encoding="utf-8",
            )
            fake = root / "unused.py"
            fake.write_text("raise AssertionError('model must not run')\n", encoding="utf-8")
            with patch.dict(os.environ, {
                "JAQ_INVESTIGATOR_MODEL": "deepseek/deepseek-v4-flash",
                "JAQ_PI_HARNESS": str(fake), "JAQ_NODE": sys.executable,
            }, clear=False):
                checkpoint = finalize_research_only(evidence_path, output)
            self.assertTrue(checkpoint["research_complete"])
            self.assertTrue((output / "research.json").is_file())

    def test_research_recovery_prioritizes_coverage_over_many_finding_evidence_ids(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "output"
            output.mkdir()
            native = [
                Observation(
                    id=f"obs-finding-{index}", type="fixture", raw_value=f"value-{index}",
                    normalized_value=f"value-{index}", artifact_location={"artifact": "sample"},
                    analyzer={"name": "fixture", "version": "1"}, provenance={"source": "fixture"},
                )
                for index in range(210)
            ]
            evidence_path = output / "observations.jsonl"
            evidence_path.write_text(
                "".join(json.dumps(item.to_dict()) + "\n" for item in [*native, *coverage_observations()]),
                encoding="utf-8",
            )
            fake = root / "unused.py"
            fake.write_text("raise AssertionError('model must not run')\n", encoding="utf-8")
            with patch.dict(os.environ, {
                "JAQ_INVESTIGATOR_MODEL": "deepseek/deepseek-v4-flash",
                "JAQ_PI_HARNESS": str(fake), "JAQ_NODE": sys.executable,
            }, clear=False):
                investigator = PiInvestigator(EvidenceStore(evidence_path), FakeRuntime(), output)
                for index in range(210):
                    investigator.finding_ledger.append("asset", {
                        "schema_version": "1.0", "id": f"asset-{index}", "type": "other",
                        "value": f"value-{index}", "normalized_value": f"value-{index}",
                        "role": "fixture", "confidence": 1.0,
                        "evidence_ids": [f"obs-finding-{index}"], "unresolved": False,
                    })
                checkpoint = investigator.finalize_persisted_research().submission
            self.assertLessEqual(len(checkpoint["important_evidence_ids"]), 200)
            self.assertTrue(set(checkpoint["coverage"]["call_graph_evidence_ids"]).issubset(
                checkpoint["important_evidence_ids"]
            ))

    def test_complete_pipeline_writes_dossier_from_incremental_findings(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "output"
            output.mkdir()
            token = "MTIzNDU2Nzg5MDEyMzQ1Njc4.abcdef.abcdefghijklmnopqrstuvwxyz123456"
            observation = Observation(
                id="obs-token", type="fixture.decoded_config",
                raw_value={"discord_token": token}, normalized_value={"discord_token": token},
                artifact_location={"artifact": "sample"}, analyzer={"name": "fixture", "version": "1"},
                provenance={"source": "fixture"},
            )
            evidence_path = output / "observations.jsonl"
            evidence_path.write_text(json.dumps(observation.to_dict()) + "\n", encoding="utf-8")
            fake = root / "fake_pipeline.py"
            fake.write_text(
                f'''\
import json, sys
init = json.loads(sys.stdin.readline())
records = [
  {{"kind":"behavior","title":"Discord command and control","description":"The decoded configuration contains a Discord command-and-control credential.","confidence":0.95,"evidence_ids":["obs-token"]}},
  {{"kind":"asset","title":"Discord bot token","description":"Exact embedded Discord credential.","confidence":0.99,"evidence_ids":["obs-token"],"asset_type":"bearer_token","value":{json.dumps(token)},"role":"Discord C2 authentication"}}
]
for index, finding in enumerate(records, 1):
    print(json.dumps({{"type":"request","id":index,"operation":"execute_tool","payload":{{"name":"record_finding","arguments":finding}}}}), flush=True)
    assert json.loads(sys.stdin.readline())["ok"] is True
print(json.dumps({{"type":"complete","submission":None,"usage":{{"input_tokens":20,"output_tokens":5,"total_tokens":25,"cost_usd":0.002,"provider_calls":2,"tool_calls":2}},"session":{{"id":"research","file":"research.jsonl"}}}}), flush=True)
''',
                encoding="utf-8",
            )
            with patch.dict(os.environ, {
                "JAQ_INVESTIGATOR_MODEL": "deepseek/deepseek-v4-flash",
                "JAQ_PI_HARNESS": str(fake), "JAQ_NODE": sys.executable,
                "JAQ_JUDGE_MODEL": "",
            }, clear=False):
                result = run_pipeline(evidence_path, output, tool_runtime=FakeRuntime())
            self.assertEqual(result["claims"]["assets"][0]["value"], token)
            self.assertIn(token, (output / "assets.json").read_text(encoding="utf-8"))
            self.assertIn(token, (output / "report.md").read_text(encoding="utf-8"))
            for name in (
                "findings.jsonl", "research.json", "claims.json", "assets.json",
                "requests.json", "score.json", "report.md",
            ):
                self.assertTrue((output / name).is_file(), name)
            self.assertFalse((output / "model-session" / "harvest").exists())

    def test_progress_frames_render_only_bounded_controller_fields(self):
        output = io.StringIO()
        with patch.dict(os.environ, {"JAQ_PROGRESS_TRANSPORT": "1"}), redirect_stderr(output):
            _emit_progress({
                "type": "progress", "phase": "research", "event": "tool_started",
                "provider_calls": 3, "tool_calls": 7, "cost_usd": 0.01234,
                "tool": "r2_decompile_function",
            })
        self.assertEqual(
            output.getvalue(),
            "JAQ_PROGRESS [research] tool #7: r2_decompile_function\n",
        )
        summary_output = io.StringIO()
        with patch.dict(os.environ, {"JAQ_PROGRESS_TRANSPORT": "1"}), redirect_stderr(summary_output):
            _emit_progress({
                "type": "progress", "phase": "research", "event": "finalizing",
                "provider_calls": 70, "tool_calls": 72, "cost_usd": 0.1,
            })
        self.assertEqual(
            summary_output.getvalue(),
            "JAQ_PROGRESS [research] preparing final summary at cost=$0.10000\n",
        )
        flush_output = io.StringIO()
        with patch.dict(os.environ, {"JAQ_PROGRESS_TRANSPORT": "1"}), redirect_stderr(flush_output):
            _emit_progress({
                "type": "progress", "phase": "research", "event": "finding_flush",
                "provider_calls": 113, "tool_calls": 119, "cost_usd": 0.1,
            })
        self.assertEqual(
            flush_output.getvalue(),
            "JAQ_PROGRESS [research] investigation cap reached; recording final findings at cost=$0.10000\n",
        )
        with self.assertRaises(PiHarnessError):
            _emit_progress({
                "type": "progress", "phase": "research", "event": "tool_started",
                "provider_calls": 3, "tool_calls": 7, "cost_usd": 0.01234,
                "tool": "r2_decompile_function", "raw_output": "untrusted",
            })
        for bad_field, bad_value in (("phase", []), ("event", []), ("cost_usd", 10**10_000)):
            malformed = {
                "type": "progress", "phase": "research", "event": "model_progress",
                "provider_calls": 3, "tool_calls": 7, "cost_usd": 0.01234,
            }
            malformed[bad_field] = bad_value
            with self.assertRaises(PiHarnessError):
                _emit_progress(malformed)

    def test_fake_pi_process_completes_through_broker_and_submit_claims(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            evidence_path = root / "observations.jsonl"
            observation = Observation(
                id="obs-native", type="artifact.hash.sha256", raw_value="a" * 64,
                normalized_value="a" * 64, artifact_location={"artifact": "sample"},
                analyzer={"name": "jaq-pe", "version": "0.1.0"}, provenance={"source": "fixture"},
            )
            all_observations = [observation, *coverage_observations()]
            evidence_path.write_text(
                "".join(json.dumps(item.to_dict()) + "\n" for item in all_observations),
                encoding="utf-8",
            )
            fake = root / "fake_harness.py"
            fake.write_text(
                """
import json, sys
init = json.loads(sys.stdin.readline())
assert init["type"] == "init"
assert init["mode"] == "harvest"
assert "submit_claims" not in {item["name"] for item in init["tool_definitions"]}
assert "static_fixture" not in {item["name"] for item in init["tool_definitions"]}
assert init["tool_definitions"] == []
print(json.dumps({"type":"request","id":1,"operation":"execute_tool","payload":{"name":"list_observation_types","arguments":{}}}), flush=True)
reply = json.loads(sys.stdin.readline())
assert reply["ok"] is False
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
                max_cost_usd=0.1, max_output_tokens=1000, summary_max_output_tokens=256,
                tool_preview_chars=1000,
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
            filtered = PiToolBroker(store, FakeRuntime()).validate_claims(broad)
            self.assertEqual(filtered["action_requests"], [])
            mixed = json.loads(json.dumps(result.claims))
            rejected_request = json.loads(json.dumps(mixed["action_requests"][0]))
            rejected_request["id"] = "request-broad-confirmation"
            rejected_request["requested_observations"] = ["processes", "registry writes"]
            mixed["action_requests"].insert(0, rejected_request)
            mixed_result = PiToolBroker(store, FakeRuntime()).validate_claims(mixed)
            self.assertEqual(mixed_result["claims"], result.claims["claims"])
            self.assertEqual(mixed_result["assets"], result.claims["assets"])
            self.assertEqual(
                [item["id"] for item in mixed_result["action_requests"]], ["request-1"]
            )
            formatting = json.loads(json.dumps(result.claims))
            formatting["ignored"] = "remove me"
            formatting["claims"][0]["ignored"] = "remove me"
            formatting["claims"][0]["classification"] = "c" * 300
            formatting["assets"][0]["ignored"] = "remove me"
            formatting["assets"][0]["role"] = "r" * 300
            original_asset_value = formatting["assets"][0]["value"]
            repaired = PiToolBroker(store, FakeRuntime()).validate_claims(formatting)
            self.assertEqual(len(repaired["claims"][0]["classification"]), 200)
            self.assertNotIn("ignored", repaired["claims"][0])
            self.assertEqual(len(repaired["assets"][0]["role"]), 200)
            self.assertEqual(repaired["assets"][0]["value"], original_asset_value)
            omitted = json.loads(json.dumps(result.claims))
            omitted["assets"] = []
            recovered = PiToolBroker(store, FakeRuntime()).validate_claims(omitted)
            self.assertEqual(recovered["assets"], [])
            unsupported = json.loads(json.dumps(omitted))
            unsupported["assets"] = [{
                "schema_version": "1.0", "id": "garbage-domain", "type": "domain",
                "value": "eq.io", "normalized_value": "eq.io", "role": "network_infrastructure",
                "confidence": 0.9, "evidence_ids": ["obs-native"], "unresolved": False,
            }]
            self.assertEqual(
                PiToolBroker(store, FakeRuntime()).validate_claims(unsupported)["assets"], []
            )

    def test_research_checkpoint_uses_phase_specific_contract(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            observation = Observation(
                id="obs-native", type="pe.string", raw_value="fixture",
                normalized_value="fixture", artifact_location={"artifact": "sample"},
                analyzer={"name": "jaq-pe", "version": "0.1.0"}, provenance={"source": "fixture"},
            )
            evidence_path = root / "observations.jsonl"
            all_observations = [observation, *coverage_observations()]
            evidence_path.write_text(
                "".join(json.dumps(item.to_dict()) + "\n" for item in all_observations),
                encoding="utf-8",
            )
            fake = root / "fake_research.py"
            fake.write_text(
                """
import json, sys
init = json.loads(sys.stdin.readline())
assert init["mode"] == "research"
assert "static_fixture" in {item["name"] for item in init["tool_definitions"]}
checkpoint = json.loads(r'''__CHECKPOINT__''')
print(json.dumps({"type":"request","id":1,"operation":"validate_research","payload":{"research":checkpoint}}), flush=True)
validated = json.loads(sys.stdin.readline())
assert validated["ok"] is True
print(json.dumps({"type":"complete","submission":validated["result"],"usage":{"total_tokens":3,"cost_usd":0.0,"provider_calls":1,"tool_calls":0},"session":{"id":"research","file":"research.jsonl"}}), flush=True)
""".replace("__CHECKPOINT__", json.dumps(coverage_checkpoint("obs-native"))),
                encoding="utf-8",
            )
            config = PiHarnessConfig(
                model="deepseek/deepseek-v4-flash", node=sys.executable, script=fake,
                session_dir=root / "session", thinking_level="off", max_model_calls=2,
                max_tool_calls=2, max_total_tokens=1000, max_cost_usd=0.1,
                max_output_tokens=1000, summary_max_output_tokens=256, tool_preview_chars=1000,
                max_context_tokens=1000, keep_recent_tokens=100,
            )
            result = PiHarnessRunner(config).run(
                PiToolBroker(EvidenceStore(evidence_path), FakeRuntime()), mode="research",
                output_schema=RESEARCH_SCHEMA, system_prompt="Research only.", task="Inspect it.",
            )
            self.assertTrue(result.submission["research_complete"])
            self.assertEqual(
                result.submission["important_evidence_ids"],
                coverage_checkpoint("obs-native")["important_evidence_ids"],
            )
            incomplete = coverage_checkpoint("obs-native")
            incomplete["coverage"]["analyzed_functions"][2]["address"] = "0x9999"
            incomplete_result = PiToolBroker(
                EvidenceStore(evidence_path), FakeRuntime()
            ).validate_research(incomplete)
            self.assertTrue(any("Coverage incomplete" in item for item in incomplete_result["unresolved_questions"]))
            mismatched = coverage_checkpoint("obs-native")
            for function in mismatched["coverage"]["analyzed_functions"]:
                function["evidence_ids"] = ["obs-coverage-0"]
            mismatched_result = PiToolBroker(
                EvidenceStore(evidence_path), FakeRuntime()
            ).validate_research(mismatched)
            self.assertTrue(any("Coverage incomplete" in item for item in mismatched_result["unresolved_questions"]))
            forged_attempt = coverage_checkpoint("obs-native")
            forged_attempt["coverage"]["deobfuscation_attempts"][0]["evidence_ids"] = ["obs-native"]
            forged_result = PiToolBroker(
                EvidenceStore(evidence_path), FakeRuntime()
            ).validate_research(forged_attempt)
            self.assertTrue(any("Coverage incomplete" in item for item in forged_result["unresolved_questions"]))
            omitted_important = coverage_checkpoint("obs-native")
            omitted_important["important_evidence_ids"] = ["obs-native"]
            reconciled = PiToolBroker(
                EvidenceStore(evidence_path), FakeRuntime()
            ).validate_research(omitted_important)
            self.assertTrue(
                {"obs-native", "obs-coverage-1", "obs-coverage-2", "obs-coverage-3", "obs-coverage-4"}
                .issubset(reconciled["important_evidence_ids"])
            )
            legacy = coverage_checkpoint("obs-native")
            legacy["coverage"]["analysis_evidence_ids"] = ["obs-coverage-0"]
            accepted_legacy = PiToolBroker(
                EvidenceStore(evidence_path), FakeRuntime()
            ).validate_research(legacy)
            self.assertNotIn("analysis_evidence_ids", accepted_legacy["coverage"])
            formatting = coverage_checkpoint("obs-native")
            formatting["ignored"] = "remove me"
            formatting["important_evidence_ids"].append("obs-native")
            formatting["coverage"]["ignored"] = "remove me"
            formatting["coverage"]["analyzed_functions"][0]["ignored"] = "remove me"
            formatting["coverage"]["analyzed_functions"][0]["name"] = "n" * 500
            repaired = PiToolBroker(
                EvidenceStore(evidence_path), FakeRuntime()
            ).validate_research(formatting)
            self.assertEqual(len(repaired["coverage"]["analyzed_functions"][0]["name"]), 300)
            self.assertNotIn("ignored", repaired)
            self.assertNotIn("ignored", repaired["coverage"])
            self.assertNotIn("ignored", repaired["coverage"]["analyzed_functions"][0])
            self.assertEqual(repaired["important_evidence_ids"].count("obs-native"), 1)
            missing_evidence = coverage_checkpoint("obs-native")
            missing_evidence["important_evidence_ids"].append("obs-missing")
            with self.assertRaisesRegex(PiHarnessError, "missing evidence IDs"):
                PiToolBroker(EvidenceStore(evidence_path), FakeRuntime()).validate_research(missing_evidence)

    def test_research_defaults_to_cost_only_without_call_tool_or_token_caps(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            fake = root / "fake.py"
            fake.write_text("", encoding="utf-8")
            with patch.dict(os.environ, {
                "JAQ_INVESTIGATOR_MODEL": "deepseek/deepseek-v4-flash",
                "JAQ_PI_HARNESS": str(fake),
            }, clear=True):
                config = PiHarnessConfig.from_env(root)
            self.assertIsNone(config.max_model_calls)
            self.assertIsNone(config.max_tool_calls)
            self.assertIsNone(config.max_total_tokens)
            self.assertEqual(config.max_cost_usd, 0.10)

    def test_pi_investigator_compiles_incremental_findings_without_harvest_session(self):
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
            all_observations = [observation, *coverage_observations()]
            evidence_path.write_text(
                "".join(json.dumps(item.to_dict()) + "\n" for item in all_observations),
                encoding="utf-8",
            )
            fake = root / "fake_two_phase.py"
            fake.write_text(
                """
import json, sys
init = json.loads(sys.stdin.readline())
assert init["mode"] == "research"
assert init["session_dir"].endswith("/model-session/research")
assert "record_finding" in {item["name"] for item in init["tool_definitions"]}
finding = {"kind":"behavior","title":"fixture","description":"The sample has a persisted hash.","confidence":1.0,"evidence_ids":["obs-native"],"role":"sample"}
print(json.dumps({"type":"request","id":1,"operation":"execute_tool","payload":{"name":"record_finding","arguments":finding}}), flush=True)
validated = json.loads(sys.stdin.readline())
assert validated["ok"] is True
print(json.dumps({"type":"complete","submission":None,"usage":{"input_tokens":10,"output_tokens":2,"total_tokens":12,"cost_usd":0.001,"provider_calls":1,"tool_calls":1},"session":{"id":"research","file":"research.jsonl"}}), flush=True)
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
            self.assertEqual(dossier["claims"][0]["classification"], "fixture")
            self.assertEqual(dossier["assets"], [])
            self.assertEqual(len((output / "findings.jsonl").read_text(encoding="utf-8").splitlines()), 1)
            self.assertTrue((output / "research.json").is_file())
            self.assertFalse((output / "model-session" / "harvest").exists())
            self.assertEqual(investigator.last_run.usage["total_tokens"], 12)
            self.assertEqual(investigator.last_run.usage["cost_microusd"], 1000)
            checkpoint = json.loads((output / "research.json").read_text(encoding="utf-8"))
            retried = investigator.harvest(checkpoint)
            self.assertEqual(retried["claims"][0]["classification"], "fixture")
            self.assertFalse((output / "model-session" / "harvest-2").exists())

    def test_missing_research_terminal_compiles_checkpoint_locally(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "output"
            output.mkdir()
            native = Observation(
                id="obs-native", type="artifact.hash.sha256", raw_value="c" * 64,
                normalized_value="c" * 64, artifact_location={"artifact": "sample"},
                analyzer={"name": "fixture", "version": "1"}, provenance={"source": "fixture"},
            )
            evidence_path = output / "observations.jsonl"
            evidence_path.write_text(
                "".join(json.dumps(item.to_dict()) + "\n" for item in [native, *coverage_observations()]),
                encoding="utf-8",
            )
            fake = root / "fake_fallback.py"
            fake.write_text(
                """
import json, sys
init = json.loads(sys.stdin.readline())
assert init["mode"] == "research"
print(json.dumps({"type":"complete","submission":None,"usage":{"input_tokens":10,"output_tokens":2,"total_tokens":12,"cost_usd":0.001,"provider_calls":1,"tool_calls":0},"session":{"id":"research","file":"research.jsonl"}}), flush=True)
""",
                encoding="utf-8",
            )
            environment = {
                "JAQ_INVESTIGATOR_MODEL": "deepseek/deepseek-v4-flash",
                "JAQ_PI_HARNESS": str(fake), "JAQ_NODE": sys.executable,
            }
            with patch.dict(os.environ, environment, clear=False):
                investigator = PiInvestigator(EvidenceStore(evidence_path), FakeRuntime(), output)
                dossier = investigator.run("Inspect the fixture.")
            self.assertEqual(dossier["claims"], [])
            self.assertTrue((output / "research.json").is_file())
            self.assertFalse((output / "model-session" / "research-finalize").exists())
            self.assertNotIn("research_recovered_total_tokens", investigator.last_run.usage)

    def test_provider_failure_does_not_trigger_checkpoint_fallback(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "output"
            output.mkdir()
            observation = Observation(
                id="obs-native", type="fixture", raw_value="fixture", normalized_value="fixture",
                artifact_location={"artifact": "sample"}, analyzer={"name": "fixture", "version": "1"},
                provenance={"source": "fixture"},
            )
            evidence_path = output / "observations.jsonl"
            evidence_path.write_text(json.dumps(observation.to_dict()) + "\n", encoding="utf-8")
            fake = root / "fake_provider_error.py"
            fake.write_text(
                """
import json, sys
json.loads(sys.stdin.readline())
print(json.dumps({"type":"error","error":{"code":"HARNESS_FAILURE","type":"Error","message":"provider error: 402 Insufficient Balance"}}), flush=True)
""",
                encoding="utf-8",
            )
            with patch.dict(os.environ, {
                "JAQ_INVESTIGATOR_MODEL": "deepseek/deepseek-v4-flash",
                "JAQ_PI_HARNESS": str(fake), "JAQ_NODE": sys.executable,
            }, clear=False):
                investigator = PiInvestigator(EvidenceStore(evidence_path), FakeRuntime(), output)
                with self.assertRaisesRegex(PiHarnessError, "Insufficient Balance"):
                    investigator.run("Inspect the fixture.")
            self.assertFalse((output / "model-session" / "research-finalize").exists())

    def test_cost_cap_preserves_incremental_findings_and_completes_locally(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "output"
            output.mkdir()
            observation = Observation(
                id="obs-native", type="fixture", raw_value="embedded capability",
                normalized_value="embedded capability", artifact_location={"artifact": "sample"},
                analyzer={"name": "fixture", "version": "1"}, provenance={"source": "fixture"},
            )
            evidence_path = output / "observations.jsonl"
            evidence_path.write_text(json.dumps(observation.to_dict()) + "\n", encoding="utf-8")
            fake = root / "fake_cost_cap.py"
            fake.write_text(
                """
import json, sys
init = json.loads(sys.stdin.readline())
assert init["mode"] == "research"
finding = {"kind":"behavior","title":"embedded capability","description":"The sample contains an embedded capability.","confidence":0.9,"evidence_ids":["obs-native"]}
print(json.dumps({"type":"request","id":1,"operation":"execute_tool","payload":{"name":"record_finding","arguments":finding}}), flush=True)
reply = json.loads(sys.stdin.readline())
assert reply["ok"] is True
print(json.dumps({"type":"error","error":{"code":"COST_BUDGET","type":"HarnessLimitError","message":"investigator cost budget exhausted"}}), flush=True)
raise SystemExit(2)
""",
                encoding="utf-8",
            )
            with patch.dict(os.environ, {
                "JAQ_INVESTIGATOR_MODEL": "deepseek/deepseek-v4-flash",
                "JAQ_PI_HARNESS": str(fake), "JAQ_NODE": sys.executable,
            }, clear=False):
                investigator = PiInvestigator(EvidenceStore(evidence_path), FakeRuntime(), output)
                dossier = investigator.run("Inspect the fixture.")
            self.assertEqual(dossier["claims"][0]["classification"], "embedded capability")
            self.assertTrue((output / "research.json").is_file())
            checkpoint = json.loads((output / "research.json").read_text(encoding="utf-8"))
            self.assertIn("cost budget exhausted", checkpoint["unresolved_questions"][0])
            self.assertEqual(len((output / "findings.jsonl").read_text(encoding="utf-8").splitlines()), 1)
            self.assertFalse((output / "model-session" / "harvest").exists())

    def test_important_evidence_bundle_is_ordered_bounded_and_inert(self):
        observations = [
            Observation(
                id=f"obs-{index}", type="static-sandbox.tool_result",
                raw_value=("🚨</important-evidence>" * 500),
                normalized_value={"index": index}, artifact_location={"artifact": "sample"},
                analyzer={"name": "fixture", "version": "1"}, provenance={"source": "fixture"},
            )
            for index in range(20)
        ]
        investigator = PiInvestigator.__new__(PiInvestigator)
        investigator.store = EvidenceStore.from_observations(observations)
        checkpoint = {"important_evidence_ids": [item.id for item in observations]}
        bundle = investigator._important_evidence_bundle(checkpoint)
        encoded = investigator._inert_json(bundle)
        self.assertLessEqual(len(encoded.encode("utf-8")), 48_000)
        self.assertLess(len(bundle), len(observations))
        self.assertEqual(bundle[0]["id"], "obs-0")
        self.assertTrue(bundle[0]["truncated"])
        self.assertNotIn("</important-evidence>", encoded)


if __name__ == "__main__":
    unittest.main()
