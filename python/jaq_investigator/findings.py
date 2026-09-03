"""Append-only semantic findings recorded during static research."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import threading
from typing import Any, Mapping


FINDING_SCHEMA_VERSION = "1.0"
MAX_FINDINGS = 1_200
MAX_FINDING_LINE_BYTES = 1 << 20
MAX_FINDINGS_FILE_BYTES = 64 << 20


class FindingError(RuntimeError):
    """A finding is malformed or cannot be persisted safely."""


class FindingLedger:
    """Private JSONL ledger with content-addressed, idempotent appends."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()
        self._records: list[dict[str, Any]] = []
        self._by_id: dict[str, dict[str, Any]] = {}
        if self.path.exists():
            self._load()
        else:
            if self.path.parent.is_symlink() or not self.path.parent.is_dir():
                raise FindingError("findings parent must be a real directory")
            descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(descriptor)

    @property
    def records(self) -> tuple[dict[str, Any], ...]:
        return tuple(dict(item) for item in self._records)

    def _load(self) -> None:
        if self.path.is_symlink() or not self.path.is_file():
            raise FindingError("findings ledger must be a regular file")
        if self.path.stat().st_size > MAX_FINDINGS_FILE_BYTES:
            raise FindingError("findings ledger exceeds the size limit")
        try:
            with self.path.open("rb+") as raw:
                data = raw.read()
                if data and not data.endswith(b"\n"):
                    # An acknowledged finding is fsynced with its newline. A
                    # trailing partial record can only be an interrupted
                    # append, so preserve all complete records and discard only
                    # the unusable suffix instead of losing the entire run.
                    complete_end = data.rfind(b"\n") + 1
                    raw.seek(complete_end)
                    raw.truncate()
                    raw.flush()
                    os.fsync(raw.fileno())
            with self.path.open("r", encoding="utf-8") as stream:
                for line_number, line in enumerate(stream, 1):
                    if len(line.encode("utf-8")) > MAX_FINDING_LINE_BYTES or not line.endswith("\n"):
                        raise FindingError(f"invalid findings ledger line {line_number}")
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError as error:
                        raise FindingError(f"invalid findings ledger line {line_number}") from error
                    self._validate_envelope(record)
                    if record["sequence"] != line_number:
                        raise FindingError("findings ledger sequence is not contiguous")
                    self._validate_record(record["kind"], record["record"])
                    if record["id"] != self._content_id(
                        record["kind"], record["title"], record["description"],
                        record["confidence"], record["record"], record.get("scope"),
                    ):
                        raise FindingError("finding content id does not match its record")
                    if record["id"] in self._by_id:
                        raise FindingError("findings ledger repeats an id")
                    self._records.append(record)
                    self._by_id[record["id"]] = record
        except (OSError, UnicodeError) as error:
            raise FindingError("could not read findings ledger") from error
        if len(self._records) > MAX_FINDINGS:
            raise FindingError("findings ledger exceeds the record limit")

    @staticmethod
    def _validate_envelope(value: Any) -> None:
        base_fields = {
            "schema_version", "id", "sequence", "kind", "title", "description", "confidence", "record",
        }
        if not isinstance(value, Mapping) or set(value) not in {frozenset(base_fields), frozenset(base_fields | {"scope"})}:
            raise FindingError("finding envelope is malformed")
        if value.get("schema_version") != FINDING_SCHEMA_VERSION:
            raise FindingError("finding has an unsupported schema version")
        if not isinstance(value.get("id"), str) or not value["id"].startswith("finding-"):
            raise FindingError("finding id is invalid")
        if not isinstance(value.get("sequence"), int) or isinstance(value["sequence"], bool) or value["sequence"] < 1:
            raise FindingError("finding sequence is invalid")
        if value.get("kind") not in {"claim", "asset", "action_request"}:
            raise FindingError("finding kind is invalid")
        if "scope" in value and (
            not isinstance(value["scope"], str) or not value["scope"] or len(value["scope"]) > 100
        ):
            raise FindingError("finding scope is invalid")
        if (
            not isinstance(value.get("title"), str) or not value["title"].strip() or len(value["title"]) > 200
            or not isinstance(value.get("description"), str) or not value["description"].strip()
            or len(value["description"]) > 12_000
        ):
            raise FindingError("finding narrative is invalid")
        confidence = value.get("confidence")
        if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not 0 <= confidence <= 1:
            raise FindingError("finding confidence is invalid")
        if not isinstance(value.get("record"), Mapping):
            raise FindingError("finding record is malformed")

    @staticmethod
    def _validate_record(kind: str, record: Mapping[str, Any]) -> None:
        common = {"schema_version", "id", "evidence_ids"}
        required = {
            "claim": common | {
                "classification", "explanation", "confidence", "asset_role",
                "reachability", "unresolved",
            },
            "asset": common | {
                "type", "value", "normalized_value", "role", "confidence", "unresolved",
            },
            "action_request": common | {
                "kind", "status", "reason", "target", "requested_observations",
            },
        }[kind]
        if set(record) != required or record.get("schema_version") != FINDING_SCHEMA_VERSION:
            raise FindingError("finding record has missing or unsupported fields")
        if not isinstance(record.get("id"), str) or not record["id"]:
            raise FindingError("finding record id is invalid")
        evidence_ids = record.get("evidence_ids")
        if not isinstance(evidence_ids, list) or not evidence_ids or any(
            not isinstance(item, str) or not item for item in evidence_ids
        ):
            raise FindingError("finding record evidence IDs are invalid")
        if kind == "claim":
            reachability = record.get("reachability")
            if not isinstance(reachability, Mapping) or set(reachability) != {
                "schema_version", "status", "entrypoints", "path_evidence_ids",
            }:
                raise FindingError("finding claim reachability is invalid")
            if not isinstance(record.get("confidence"), (int, float)) or isinstance(record["confidence"], bool):
                raise FindingError("finding claim confidence is invalid")
        elif kind == "asset":
            if not isinstance(record.get("confidence"), (int, float)) or isinstance(record["confidence"], bool):
                raise FindingError("finding asset confidence is invalid")
        elif (
            not isinstance(record.get("target"), Mapping)
            or not isinstance(record.get("requested_observations"), list)
        ):
            raise FindingError("finding action request is invalid")

    @staticmethod
    def _content_id(
        kind: str,
        title: str,
        description: str,
        confidence: float,
        record: Mapping[str, Any],
        scope: str | None = None,
    ) -> str:
        identity: dict[str, Any] = {
            "kind": kind, "title": title, "description": description,
            "confidence": confidence, "record": record,
        }
        if scope is not None:
            identity["scope"] = scope
        encoded = json.dumps(
            identity,
            ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        return f"finding-{hashlib.sha256(encoded).hexdigest()[:24]}"

    def append(
        self,
        kind: str,
        record: Mapping[str, Any],
        *,
        title: str | None = None,
        description: str | None = None,
        confidence: float | None = None,
        scope: str | None = None,
    ) -> dict[str, Any]:
        if kind not in {"claim", "asset", "action_request"} or not isinstance(record, Mapping):
            raise FindingError("finding kind or record is invalid")
        stable = json.loads(json.dumps(record, ensure_ascii=False, sort_keys=True, allow_nan=False))
        self._validate_record(kind, stable)
        if title is None:
            title = str(stable.get("classification") or stable.get("role") or stable.get("kind") or "Finding")
        if description is None:
            description = str(stable.get("explanation") or stable.get("reason") or stable.get("role") or title)
        if confidence is None:
            confidence = stable.get("confidence", 1.0)
        if (
            not isinstance(title, str) or not title.strip() or len(title) > 200
            or not isinstance(description, str) or not description.strip() or len(description) > 12_000
        ):
            raise FindingError("finding narrative is invalid")
        if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not 0 <= confidence <= 1:
            raise FindingError("finding confidence is invalid")
        if scope is not None and (not isinstance(scope, str) or not scope or len(scope) > 100):
            raise FindingError("finding scope is invalid")
        finding_id = self._content_id(kind, title, description, float(confidence), stable, scope)
        with self._lock:
            existing = self._by_id.get(finding_id)
            if existing is not None:
                return dict(existing)
            if len(self._records) >= MAX_FINDINGS:
                raise FindingError("findings ledger exceeds the record limit")
            envelope = {
                "schema_version": FINDING_SCHEMA_VERSION,
                "id": finding_id,
                "sequence": len(self._records) + 1,
                "kind": kind,
                "title": title,
                "description": description,
                "confidence": float(confidence),
                "record": stable,
            }
            if scope is not None:
                envelope["scope"] = scope
            encoded = json.dumps(envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
            if len(encoded.encode("utf-8")) > MAX_FINDING_LINE_BYTES:
                raise FindingError("finding exceeds the line size limit")
            try:
                with self.path.open("a", encoding="utf-8", newline="") as stream:
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(stream.fileno())
            except OSError as error:
                raise FindingError("could not append finding") from error
            self._records.append(envelope)
            self._by_id[finding_id] = envelope
            return dict(envelope)

    def compile(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "schema_version": "1.0",
            "claims": [],
            "assets": [],
            "action_requests": [],
        }
        asset_indexes: dict[tuple[str, str], int] = {}
        request_indexes: dict[tuple[str, str], int] = {}
        for envelope in self._records:
            target = {
                "claim": "claims",
                "asset": "assets",
                "action_request": "action_requests",
            }[envelope["kind"]]
            record = dict(envelope["record"])
            if target == "assets":
                key = (
                    str(record.get("type")),
                    json.dumps(record.get("normalized_value"), ensure_ascii=False, sort_keys=True),
                )
                existing_index = asset_indexes.get(key)
                if existing_index is not None:
                    existing = result[target][existing_index]
                    existing["evidence_ids"] = list(dict.fromkeys([
                        *existing["evidence_ids"], *record["evidence_ids"],
                    ]))
                    existing["confidence"] = max(existing["confidence"], record["confidence"])
                    continue
                asset_indexes[key] = len(result[target])
            elif target == "action_requests":
                key = (
                    str(record.get("kind")),
                    json.dumps(record.get("target"), ensure_ascii=False, sort_keys=True),
                )
                existing_index = request_indexes.get(key)
                if existing_index is not None:
                    existing = result[target][existing_index]
                    existing["evidence_ids"] = list(dict.fromkeys([
                        *existing["evidence_ids"], *record["evidence_ids"],
                    ]))
                    existing["requested_observations"] = list(dict.fromkeys([
                        *existing["requested_observations"], *record["requested_observations"],
                    ]))
                    continue
                request_indexes[key] = len(result[target])
            result[target].append(record)
        return result


__all__ = ["FINDING_SCHEMA_VERSION", "FindingError", "FindingLedger"]
