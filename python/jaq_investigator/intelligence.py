"""Local output indexes; no model calls or network access."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import urlsplit

from .evidence import EvidenceStore


BEHAVIOR_LABELS = {
    "application_logic": "Application logic",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege_escalation": "Privilege escalation",
    "defense_evasion": "Defense evasion",
    "credential_access": "Credential access",
    "discovery": "Discovery",
    "collection": "Collection",
    "command_control": "Command and control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}
SUMMARY_PRIORITY = (
    "command_control", "credential_access", "exfiltration", "persistence",
    "impact", "collection", "privilege_escalation", "defense_evasion",
    "execution", "discovery", "application_logic",
)
_URL_RE = re.compile(r"https?://[^\s\x00-\x1f\x7f<>\"'`\\]+", re.IGNORECASE)
MAX_RECOVERED_URLS = 500


def _text_leaves(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for nested in value.values():
            yield from _text_leaves(nested)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            yield from _text_leaves(nested)


def recover_urls(store: EvidenceStore, assets: Iterable[Mapping[str, Any]] = ()) -> dict[str, Any]:
    """Index URLs in successful analyzer output without assigning network roles.

    Only result bodies and native sample strings are scanned, never tool
    requests, commands, researcher prose, or metadata. A helper's output can
    still contain library/documentation URLs: matching text is an observation,
    not evidence of a connection or attacker ownership.
    """
    found: dict[str, dict[str, Any]] = {}
    omitted_occurrences = 0
    for observation in store.observations:
        if observation.type.startswith("pe.string."):
            value = observation.normalized_value
        elif observation.type.endswith(".tool_result"):
            if observation.metadata.get("status") != "ok":
                continue
            normalized = observation.normalized_value
            result = normalized.get("result") if isinstance(normalized, Mapping) else None
            if not isinstance(result, Mapping) or result.get("isError") or result.get("returncode", 0) != 0:
                continue
            # stderr and request arguments are diagnostics, not recovered data.
            value = result.get("stdout", result.get("content", []))
        else:
            continue
        for text in _text_leaves(value):
            for match in _URL_RE.finditer(text):
                url = match.group().rstrip(".,;")
                while url.endswith(")") and url.count(")") > url.count("("):
                    url = url[:-1]
                if len(url) > 2048:
                    omitted_occurrences += 1
                    continue
                try:
                    parsed = urlsplit(url)
                    host = parsed.hostname
                    _ = parsed.port
                except ValueError:
                    continue
                if not host or not re.fullmatch(r"[A-Za-z0-9._:\[\]-]+", host) or not re.search(r"[A-Za-z0-9]", host):
                    continue
                if url not in found:
                    if len(found) >= MAX_RECOVERED_URLS:
                        omitted_occurrences += 1
                        continue
                    found[url] = {
                        "id": "url-" + hashlib.sha256(url.encode()).hexdigest()[:24],
                        "value": url,
                        "status": "unclassified",
                        "asset_ids": [],
                        "evidence_ids": [],
                        "occurrences": 0,
                        "context": text[max(0, match.start() - 120):match.end() + 1400],
                    }
                item = found[url]
                item["occurrences"] += 1
                if observation.id not in item["evidence_ids"] and len(item["evidence_ids"]) < 100:
                    item["evidence_ids"].append(observation.id)
    for asset in assets:
        value = asset.get("value")
        if isinstance(value, str) and value in found:
            found[value]["asset_ids"].append(asset["id"])
            found[value]["status"] = "recorded"
    return {
        "recovered_urls": [found[value] for value in sorted(found)],
        "url_inventory": {
            "method": "literal_http_urls_in_analyzer_results",
            "limit": MAX_RECOVERED_URLS,
            "omitted_occurrences": omitted_occurrences,
            "unclassified_count": sum(item["status"] == "unclassified" for item in found.values()),
            "limitations": "Literal HTTP(S) URLs only; computed, encoded, bare-domain and IP-only destinations may be absent. Tool output can include library or documentation URLs. Roles require review.",
        },
    }


def compile_tags(
    records: Iterable[Mapping[str, Any]],
    claims: Iterable[Mapping[str, Any]],
    score: Mapping[str, Any],
    assets: Iterable[Mapping[str, Any]],
    requests: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Project explicit finding scopes and typed assets; never infer from prose."""
    claims_by_id = {item["id"]: item for item in claims}
    statuses = {item["claim_id"]: item["status"] for item in score["verification_results"]}
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    scopes: dict[str, str] = {}

    def add(kind: str, tag: str, status: str, item: Mapping[str, Any], ref_key: str) -> None:
        key = (kind, tag, status)
        row = grouped.setdefault(key, {
            "kind": kind, "tag": tag, "status": status,
            "claim_ids": [], "asset_ids": [], "request_ids": [], "evidence_ids": [],
        })
        if item["id"] not in row[ref_key]:
            row[ref_key].append(item["id"])
        row["evidence_ids"] = sorted(set(row["evidence_ids"]) | set(item["evidence_ids"]))

    for envelope in records:
        scope = envelope.get("scope")
        claim = claims_by_id.get(envelope["record"]["id"])
        if envelope["kind"] == "claim" and scope in BEHAVIOR_LABELS and claim is not None:
            scopes[claim["id"]] = scope
            add("behavior", scope, statuses.get(claim["id"], "unclear"), claim, "claim_ids")
    for asset in assets:
        add("asset", asset["type"], "unresolved" if asset.get("unresolved") else "recorded", asset, "asset_ids")
    for request in requests:
        add("request", request["kind"], request["status"], request, "request_ids")
    return {
        "schema_version": "1.0",
        "taxonomy": "jaq-intelligence-v1",
        "description": "Tags inherit recorded scopes/types and verification status; they are not independent judgments, malware-family labels, or ATT&CK mappings.",
        "behavior_labels": BEHAVIOR_LABELS,
        "claim_scopes": scopes,
        "tags": [grouped[key] for key in sorted(grouped)],
    }
