from __future__ import annotations

import json
import stat
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from jaq_investigator.evidence import EvidenceStore
from jaq_investigator.findings import FindingError, FindingLedger
from jaq_investigator.pi_harness import PiHarnessError, PiToolBroker
from jaq_investigator.schemas import Observation


class NoRuntime:
    def model_tools(self):
        return ()

    def execute(self, name, arguments):
        raise AssertionError(f"unexpected runtime call {name} {arguments}")


class FindingLedgerTest(unittest.TestCase):
    def fixture(self, root: Path) -> tuple[EvidenceStore, FindingLedger]:
        token = "MTIzNDU2Nzg5MDEyMzQ1Njc4.abcdef.abcdefghijklmnopqrstuvwxyz123456"
        url = "https://example.invalid/stage-two.dll"
        observation = Observation(
            id="obs-config", type="fixture.decoded_config",
            raw_value={"discord_token": token, "payload_url": url},
            normalized_value={"discord_token": token, "payload_url": url},
            artifact_location={"artifact": "sample"},
            analyzer={"name": "fixture", "version": "1"},
            provenance={"source": "fixture"},
        )
        evidence_path = root / "observations.jsonl"
        evidence_path.write_text(json.dumps(observation.to_dict()) + "\n", encoding="utf-8")
        return EvidenceStore(evidence_path), FindingLedger(root / "findings.jsonl")

    def test_records_exact_asset_behavior_and_request_incrementally(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            store, ledger = self.fixture(root)
            broker = PiToolBroker(store, NoRuntime(), ledger)
            token = store.get("obs-config").raw_value["discord_token"]
            url = store.get("obs-config").raw_value["payload_url"]

            asset = broker.execute("record_finding", {
                "kind": "asset", "title": "Discord bot token",
                "description": "Decoded Discord command-and-control credential.",
                "confidence": 0.99, "evidence_ids": ["obs-config"],
                "asset_type": "bearer_token", "value": token,
                "role": "Discord C2 authentication",
            })
            broker.execute("record_finding", {
                "kind": "behavior", "title": "Discord-controlled remote access",
                "description": "The decoded configuration couples a Discord token with a remote payload URL.",
                "confidence": 0.9, "evidence_ids": ["obs-config"],
            })
            broker.execute("record_finding", {
                "kind": "action_request", "title": "Retrieve referenced second stage",
                "description": "Recover the statically referenced plugin for separate analysis.",
                "confidence": 0.95, "evidence_ids": ["obs-config"],
                "request_kind": "fetch_remote_payload", "target": {"url": url},
                "requested_observations": ["downloaded_payload", "payload_hash"],
            })

            compiled = ledger.compile()
            self.assertEqual(asset["status"], "recorded")
            self.assertEqual(compiled["assets"][0]["value"], token)
            self.assertEqual(compiled["claims"][0]["classification"], "Discord-controlled remote access")
            self.assertEqual(compiled["action_requests"][0]["target"]["url"], url)
            self.assertIn(token, (root / "findings.jsonl").read_text(encoding="utf-8"))

    def test_rejects_missing_evidence_without_appending(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            store, ledger = self.fixture(root)
            broker = PiToolBroker(store, NoRuntime(), ledger)
            with self.assertRaisesRegex(PiHarnessError, "missing or invalid evidence"):
                broker.execute("record_finding", {
                    "kind": "behavior", "title": "Unsupported", "description": "No evidence.",
                    "confidence": 1.0, "evidence_ids": ["obs-missing"],
                })
            self.assertEqual(ledger.records, ())

    def test_rejects_asset_value_absent_from_cited_evidence(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            store, ledger = self.fixture(root)
            broker = PiToolBroker(store, NoRuntime(), ledger)
            with self.assertRaisesRegex(PiHarnessError, "not present exactly"):
                broker.execute("record_finding", {
                    "kind": "asset", "title": "Guessed token",
                    "description": "This value was not actually recovered.",
                    "confidence": 0.9, "evidence_ids": ["obs-config"],
                    "asset_type": "bearer_token", "value": "invented-token-value",
                    "role": "Unverified credential",
                })
            self.assertEqual(ledger.records, ())

    def test_duplicate_assets_merge_without_losing_evidence(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            store, ledger = self.fixture(root)
            broker = PiToolBroker(store, NoRuntime(), ledger)
            token = store.get("obs-config").raw_value["discord_token"]
            base = {
                "kind": "asset", "title": "Discord token", "description": "Credential.",
                "evidence_ids": ["obs-config"], "asset_type": "bearer_token",
                "value": token, "role": "Discord C2 authentication",
            }
            broker.execute("record_finding", {**base, "confidence": 0.8})
            broker.execute("record_finding", {**base, "confidence": 0.99})
            compiled = ledger.compile()
            self.assertEqual(len(compiled["assets"]), 1)
            self.assertEqual(compiled["assets"][0]["confidence"], 0.99)

    def test_claim_identity_includes_role_and_reachability(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            store, ledger = self.fixture(root)
            broker = PiToolBroker(store, NoRuntime(), ledger)
            base = {
                "kind": "behavior", "title": "Capability", "description": "Supported behavior.",
                "confidence": 0.9, "evidence_ids": ["obs-config"],
            }
            first = broker.execute("record_finding", {**base, "role": "configuration"})
            second = broker.execute("record_finding", {**base, "role": "command-and-control"})
            self.assertNotEqual(first["record_id"], second["record_id"])
            self.assertEqual(len(ledger.compile()["claims"]), 2)

    def test_rejects_missing_reachability_evidence_before_append(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            store, ledger = self.fixture(root)
            broker = PiToolBroker(store, NoRuntime(), ledger)
            with self.assertRaisesRegex(PiHarnessError, "reachability cites missing evidence"):
                broker.execute("record_finding", {
                    "kind": "behavior", "title": "Reachable behavior",
                    "description": "Claimed path.", "confidence": 0.9,
                    "evidence_ids": ["obs-config"], "reachability_status": "reachable",
                    "path_evidence_ids": ["obs-missing"],
                })
            self.assertEqual(ledger.records, ())

    def test_identical_append_is_idempotent_and_private(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            _, ledger = self.fixture(root)
            record = {
                "schema_version": "1.0", "id": "claim-fixture",
                "classification": "fixture", "explanation": "Supported.",
                "confidence": 1.0, "evidence_ids": ["obs-config"],
                "asset_role": None,
                "reachability": {
                    "schema_version": "1.0", "status": "unknown",
                    "entrypoints": [], "path_evidence_ids": [],
                },
                "unresolved": False,
            }
            first = ledger.append("claim", record)
            second = ledger.append("claim", record)
            self.assertEqual(first["id"], second["id"])
            self.assertEqual(len(ledger.records), 1)
            self.assertEqual(len((root / "findings.jsonl").read_text(encoding="utf-8").splitlines()), 1)
            self.assertEqual(stat.S_IMODE((root / "findings.jsonl").stat().st_mode), 0o600)

    def test_trailing_partial_record_is_recovered_but_complete_malformed_line_fails(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "findings.jsonl"
            seed = FindingLedger(path)
            seed.append("claim", {
                "schema_version": "1.0", "id": "claim-fixture",
                "classification": "fixture", "explanation": "Supported.",
                "confidence": 1.0, "evidence_ids": ["obs-config"], "asset_role": None,
                "reachability": {"schema_version": "1.0", "status": "unknown", "entrypoints": [], "path_evidence_ids": []},
                "unresolved": False,
            })
            with path.open("ab") as stream:
                stream.write(b'{"schema_version":"1.0"}')
            ledger = FindingLedger(path)
            self.assertEqual(len(ledger.records), 1)
            self.assertTrue(path.read_bytes().endswith(b"\n"))
            path.write_text('{"schema_version":"1.0"}\n', encoding="utf-8")
            with self.assertRaises(FindingError):
                FindingLedger(path)

    def test_loaded_ledger_rejects_kind_specific_malformed_record(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            _, ledger = self.fixture(root)
            ledger.append("claim", {
                "schema_version": "1.0", "id": "claim-fixture",
                "classification": "fixture", "explanation": "Supported.",
                "confidence": 1.0, "evidence_ids": ["obs-config"], "asset_role": None,
                "reachability": {"schema_version": "1.0", "status": "unknown", "entrypoints": [], "path_evidence_ids": []},
                "unresolved": False,
            })
            envelope = json.loads((root / "findings.jsonl").read_text(encoding="utf-8"))
            del envelope["record"]["evidence_ids"]
            (root / "findings.jsonl").write_text(json.dumps(envelope) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(FindingError, "record has missing"):
                FindingLedger(root / "findings.jsonl")


if __name__ == "__main__":
    unittest.main()
