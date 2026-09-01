from __future__ import annotations

import unittest

from jaq_investigator.candidates import extract_candidates
from jaq_investigator.schemas import Observation


class CandidateTest(unittest.TestCase):
    def test_extracts_operational_candidates_with_evidence(self):
        observation = Observation(
            id="obs-1", type="pe.string.ascii",
            raw_value="download https://stage.example/payload.exe contact ops@example.com key ghp_abcdefghijklmnopqrstuvwxyz1234",
            normalized_value="", artifact_location={"artifact":"sample"},
            analyzer={"name":"fixture","version":"1"}, provenance={"source":"fixture"},
        )
        candidates = extract_candidates([observation])
        kinds = {item.type for item in candidates}
        self.assertTrue({"url", "email", "api_key"}.issubset(kinds))
        self.assertTrue(all(item.evidence_ids == ("obs-1",) for item in candidates))


if __name__ == "__main__":
    unittest.main()
