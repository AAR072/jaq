# JAQ output contract

The dossier is compiled locally from saved observations and findings. Reporting
failure or an exhausted model budget must not erase those records. A partial
run retains its limitations; generating a report does not make analysis complete.

## Asset records and recovered URLs

`assets.json` keeps its existing `schema_version: "1.0"`, `assets` and
`categories` fields. Model-recorded assets retain their exact values, types,
roles, confidence, and evidence references. Two additive fields make unmatched
URL evidence visible:

- `recovered_urls`: a deterministic inventory of literal HTTP(S) text from
  native sample strings and successful analyzer result bodies. Each entry has
  a stable `id`, exact `value`, `status`, `asset_ids`, `evidence_ids`, occurrence
  count and bounded source `context`.
- `url_inventory`: extraction method, capacity, omitted occurrence count,
  unclassified count and limitations.

`status: "recorded"` means an exact value also occurs in the model's asset
inventory; `asset_ids` supplies the interpreted roles. `status: "unclassified"`
means the text was recovered but no corresponding asset was recorded. Neither
status proves a live connection or attacker ownership. Library/documentation
URLs can appear in analyzer output. Only model-recorded assets can initiate the
existing payload-recovery request workflow; this index cannot do so.

The index scans result bodies, not request commands or researcher narratives.
It keeps at most 500 distinct URLs, each at most 2,048 characters, and up to
100 evidence IDs per URL. It reports omitted occurrences when capacity or
length limits are reached. Values remain in observations.jsonl even when
omitted from the index. Encoded/computed destinations, bare domains and bare
IP addresses require further analysis. The Markdown report shows the first
30 indexed URLs; assets.json contains the full retained index.

The reporter receives a bounded URL index before its ordinary selected
evidence. It records sample-related endpoints before writing long behavior
descriptions, using a neutral `url` asset when a stronger role is unsupported.
The same local index is regenerated during `--compile-only`, even with an empty
findings ledger or no available provider.

## Tags

`tags.json` has `schema_version: "1.0"` and
`taxonomy: "jaq-intelligence-v1"`. Its `tags` array groups records by
`kind`, `tag` and `status`. Each group includes `claim_ids`, `asset_ids`,
`request_ids` and `evidence_ids`; only the relevant source-ID array is populated.

| Kind | Tag source | Status |
| --- | --- | --- |
| `behavior` | Explicit scope in findings.jsonl | Claim's `accepted`, `unclear` or `rejected` verification result |
| `asset` | Validated asset type | `recorded` or `unresolved` |
| `request` | Action request kind | `pending_authorization` in the original dossier |

Behavior scopes are `application_logic`, `execution`, `persistence`,
`privilege_escalation`, `defense_evasion`, `credential_access`, `discovery`,
`collection`, `command_control`, `exfiltration` and `impact`. The document's
`behavior_labels` maps these stable IDs to display labels and `claim_scopes`
maps claim IDs to their recorded scopes.

No tags are guessed from words in a description. Legacy claims without a
recorded scope remain untagged. Rejected or unclear claims retain their own
status groups and never contribute to the report's accepted tag summary.
Tags organize the investigator's conclusions; they are not independent
verification, malware-family attribution or MITRE ATT&CK mappings. Request
tags describe the dossier at compilation time; requests.json is authoritative
for subsequent approval and execution status.

## Follow-up requests and screening

Requests keep schema version `1.0` and the existing authorization `status`.
New optional fields are additive. Screening verdict and execution state are
separate from authorization: `pending_authorization` does not imply qualified.
The controller only advertises an approval wait for qualified candidates.

- `justification`: `missing_artifact`, `expected_value`, `blocker`,
  `why_this_action`, `novelty`, `static_attempts` (method, result, evidence_ids),
  and `evidence_excerpts` (evidence_id, exact quote). Text fields are bounded to
  2,000 characters; at most eight attempts and eight excerpts. Nested references
  must belong to the request's evidence IDs. Excerpts are checked against
  persisted analyzer output and expanded with surrounding context. Submitted
  commands are not evidence of successful work. Every cited attempt needs an
  excerpt of its result. An empty attempts list can be justified by an observed
  external/runtime dependency; unnecessary static work need not be invented.
- `screening`: policy/model version, provider, verdict, fixed reason codes,
  five independent `checks` with choices/probabilities/confidence, threshold,
  calibration status, evidence references, review input hash, bounded review
  input and provider token usage when available. Verdicts are `qualified`,
  `unsupported`, or `insufficient_evidence`. Qualification requires every
  criterion's supported probability to clear the kind-specific threshold;
  a confidently unsupported criterion blocks the request. Uncertainty holds it.
- `execution`: dynamic requests (`dynamic_analysis`, `memory_dump`,
  `network_capture`) have the result envelope below, even when screening holds
  them. This describes executor availability, not completed analysis.

```json
{
  "schema_version": "1.0",
  "executor": "dynamic_analysis",
  "status": "placeholder",
  "executed": false,
  "reason_code": "executor_not_implemented",
  "message": "Dynamic analysis is a placeholder; no sample was executed.",
  "request_id": "request-example",
  "target": {},
  "requested_observations": ["unpacked_payload"],
  "artifacts": [],
  "observations": []
}
```

The containing run identifies the input sample via its manifest and observation
ledger. A future executor receives the complete request (including target,
evidence, objective and requested outputs) in `handoff.json.request` and returns
the versioned envelope in `handoff.json.result`. Artifact and observation arrays
are empty today; populated item schemas must be versioned when the executor is
implemented. No shell command or model-provided execution plan is dispatched.

Asset-derived fetch candidates still preserve potentially useful stage links,
but cannot qualify without an explicit evidence-backed justification. Distinct
dynamic objectives/outputs are kept separate; repeated fetches of the same
target are merged, including a later explicit justification. Unsupported and
uncertain screened candidates stay in `requests.json` and do not erase findings.
Malformed findings may still be rejected at recording time. Other request kinds
retain their operator-only workflow and do not claim a Jev screening verdict.

Missing keys, provider/response errors, oversized context, and exhausted screening
budgets never count as qualification. Offline compilation performs no Jev calls
and produces an unresolved screening result. `approve` and `resume` enforce
qualification when screening is present; legacy requests without it retain the
old explicit operator workflow. Request decisions preserve `partial`/`failed`
analysis status. `tags.json` continues to describe authorization status, not the
screening verdict; consult the corresponding request for the latter.

All thresholds currently carry `calibration_status: "uncalibrated"`. Tune on
labeled cases split by sample, then evaluate on held-out samples, separately for
fetch and dynamic requests. Measure unnecessary requests admitted, justified
requests blocked/held, and abstentions. Include persuasive unsupported requests,
terse legitimate requests, already recovered artifacts and missing context.
Model probabilities or another model's opinion are not ground-truth labels.

## Report and compatibility

The opening summary lists up to five accepted finding titles, prioritizing
distinct behavior scopes and then confidence within a scope. It does not
repeat long evidence dumps. Full claims and citations remain in the body.
Recovered URLs and accepted behavior tags appear near the top.
`communications.json` includes `verification_status` for each linked claim.

The Go controller validates the new indexes' evidence references and tag source
record links. Existing run directories without the additive fields or tags.json
remain readable. New Python runs always emit tags.json. Published files are
never overwritten; recompile into a fresh directory with the original
research.json and findings.jsonl, pointing `--evidence` at the original ledger.
