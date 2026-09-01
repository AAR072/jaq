from __future__ import annotations

import unittest

from jaq_investigator.candidates import extract_candidates
from jaq_investigator.cli import _render_operational
from jaq_investigator.schemas import Observation


class CandidateTest(unittest.TestCase):
    def test_extracts_operational_candidates_with_evidence(self):
        observation = Observation(
            id="obs-1", type="pe.string.ascii",
            raw_value="download https://stage.example/payload.exe contact ops@example.com key ghp_abcdefghijklmnopqrstuvwxyz1234 discord AAAAAAAAAAAAAAAAAAAAAAAA.BBBBBB.CCCCCCCCCCCCCCCCCCCCCCCCCCC telegram 123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            normalized_value="", artifact_location={"artifact":"sample"},
            analyzer={"name":"fixture","version":"1"}, provenance={"source":"fixture"},
        )
        candidates = extract_candidates([observation])
        kinds = {item.type for item in candidates}
        self.assertTrue({"remote_payload", "email", "api_key", "bearer_token"}.issubset(kinds))
        self.assertTrue(any(item.role == "telegram_bot_token" for item in candidates))
        self.assertTrue(all(item.evidence_ids == ("obs-1",) for item in candidates))

    def test_ignores_dotnet_names_and_version_numbers_and_preserves_url_templates(self):
        observation = Observation(
            id="obs-1", type="pe.string.ascii",
            raw_value=(
                'System.IO System.Net Version=4.0.0.0 '
                'http://www.google.com/maps/place/{0},{1}'
            ),
            normalized_value="", artifact_location={"artifact": "sample"},
            analyzer={"name": "fixture", "version": "1"}, provenance={"source": "fixture"},
        )
        candidates = extract_candidates([observation])
        values = {item.value for item in candidates}
        self.assertNotIn("System.IO", values)
        self.assertNotIn("System.Net", values)
        self.assertNotIn("4.0.0.0", values)
        self.assertIn("http://www.google.com/maps/place/{0},{1}", values)

    def test_private_report_shows_full_credential_and_sha256(self):
        token = "123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        report = _render_operational({"assets": [{"type": "api_key", "value": token, "role": "telegram_bot_token", "confidence": 0.99}], "action_requests": []})
        self.assertIn(token, report)
        self.assertIn("sha256:", report)


if __name__ == "__main__":
    unittest.main()
