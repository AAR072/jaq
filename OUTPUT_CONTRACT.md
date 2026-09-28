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
