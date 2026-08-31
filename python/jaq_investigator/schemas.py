"""Versioned, dependency-free data contracts for the JAQ investigator.

The controller owns all paths and creates the observations file.  Values in an
observation are data, including strings which happen to look like prompts or
instructions.  This module deliberately does not evaluate or interpret those
values; it only validates their JSON shape and records them as evidence.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
import json
import math
from typing import Any, Literal


PERSISTED_VERSION = "1.0"
SCHEMA_VERSION = PERSISTED_VERSION


class SchemaError(ValueError):
    """Raised when a persisted or model-produced object is not valid."""


# A compatibility alias makes the boundary easier to use from controller code.
ValidationError = SchemaError


def _copy_json(value: Any, field_name: str) -> Any:
    """Validate and detach a JSON-compatible value.

    ``allow_nan=False`` is intentional: NaN and infinities are not JSON data
    and would make otherwise reproducible persisted records ambiguous.
    """

    try:
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False)
        return json.loads(encoded)
    except (TypeError, ValueError, OverflowError) as exc:
        raise SchemaError(f"{field_name} must be JSON-compatible") from exc


def _text(value: Any, field_name: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise SchemaError(f"{field_name} must be a string")
    if not allow_empty and not value.strip():
        raise SchemaError(f"{field_name} must not be empty")
    return value


def _optional_text(value: Any, field_name: str) -> str | None:
    if value is None:
        return None
    return _text(value, field_name)


def _ids(value: Any, field_name: str, *, required: bool = False) -> tuple[str, ...]:
    if value is None:
        if required:
            raise SchemaError(f"{field_name} must be a nonempty list of strings")
        return ()
    if isinstance(value, str) or not isinstance(value, (list, tuple, set, frozenset)):
        raise SchemaError(f"{field_name} must be a list of strings")
    result: list[str] = []
    for item in value:
        item_text = _text(item, field_name + "[]")
        if item_text in result:
            raise SchemaError(f"{field_name} must not contain duplicate IDs")
        result.append(item_text)
    if required and not result:
        raise SchemaError(f"{field_name} must be nonempty")
    return tuple(result)


def _mapping(value: Any, field_name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise SchemaError(f"{field_name} must be an object")
    copied = _copy_json(dict(value), field_name)
    # JSON object keys are strings.  json.dumps turns integer keys into
    # strings, but accepting them here would make direct and persisted objects
    # behave differently, so reject them explicitly.
    if any(not isinstance(key, str) for key in value):
        raise SchemaError(f"{field_name} keys must be strings")
    return copied


def _version(data: Mapping[str, Any]) -> None:
    if "schema_version" not in data:
        raise SchemaError("schema_version is required")
    supplied = data["schema_version"]
    if supplied != PERSISTED_VERSION:
        raise SchemaError(
            f"unsupported schema version {supplied!r}; expected {PERSISTED_VERSION}"
        )


def _first(data: Mapping[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if name in data:
            return data[name]
    return default


def _required(data: Mapping[str, Any], *names: str) -> Any:
    marker = object()
    value = _first(data, *names, default=marker)
    if value is marker:
        raise SchemaError(f"missing required field {names[0]}")
    return value


def _relation_ids(value: Any) -> tuple[str, ...]:
    """Extract IDs from a relationship field without reading arbitrary text.

    Relationship fields are controller-created structured fields.  A mapping
    entry can use the common ``id``, ``observation_id``, ``target_id`` or
    ``source_id`` key.  Free-form strings are treated as exact IDs, never as
    search expressions.
    """

    if value is None:
        return ()
    if isinstance(value, str):
        return (value,) if value.strip() else ()
    if isinstance(value, Mapping):
        for key in ("observation_id", "id", "target_id", "source_id"):
            if key in value and isinstance(value[key], str) and value[key].strip():
                return (value[key],)
        values: list[str] = []
        for nested in value.values():
            values.extend(_relation_ids(nested))
        return tuple(dict.fromkeys(values))
    if isinstance(value, (list, tuple, set, frozenset)):
        values = []
        for item in value:
            values.extend(_relation_ids(item))
        return tuple(dict.fromkeys(values))
    return ()


@dataclass(frozen=True)
class Reachability:
    """A claim's bounded reachability assertion."""

    status: Literal["reachable", "not_reachable", "unknown"]
    entrypoints: tuple[str, ...] = ()
    path_evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.status not in {"reachable", "not_reachable", "unknown"}:
            raise SchemaError(
                "reachability.status must be reachable, not_reachable, or unknown"
            )
        object.__setattr__(self, "entrypoints", _ids(self.entrypoints, "entrypoints"))
        object.__setattr__(
            self,
            "path_evidence_ids",
            _ids(self.path_evidence_ids, "path_evidence_ids"),
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Reachability":
        if not isinstance(data, Mapping):
            raise SchemaError("reachability must be an object")
        _version(data)
        status = _required(data, "status")
        entrypoints = _first(data, "entrypoints", "entrypoint_ids", default=())
        path_ids = _first(
            data,
            "path_evidence_ids",
            "pathEvidenceIds",
            "path_ids",
            default=(),
        )
        return cls(
            status=status,
            entrypoints=_ids(entrypoints, "entrypoints"),
            path_evidence_ids=_ids(path_ids, "path_evidence_ids"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": PERSISTED_VERSION,
            "status": self.status,
            "entrypoints": list(self.entrypoints),
            "path_evidence_ids": list(self.path_evidence_ids),
        }


@dataclass(frozen=True)
class Observation:
    """One deterministic fact in the controller-created evidence package."""

    id: str
    type: str
    raw_value: Any
    normalized_value: Any
    artifact_location: Any
    analyzer: Any
    provenance: Any
    references: tuple[str, ...] = ()
    reference_ids: tuple[str, ...] = ()
    calls: tuple[str, ...] = ()
    call_targets: tuple[str, ...] = ()
    callees: tuple[str, ...] = ()
    callers: tuple[str, ...] = ()
    related_observation_ids: tuple[str, ...] = ()
    relationships: Mapping[str, Any] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    analyzer_version: str | None = None
    extra: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _text(self.id, "id"))
        object.__setattr__(self, "type", _text(self.type, "type"))
        object.__setattr__(self, "raw_value", _copy_json(self.raw_value, "raw_value"))
        object.__setattr__(
            self,
            "normalized_value",
            _copy_json(self.normalized_value, "normalized_value"),
        )
        if self.artifact_location is None:
            raise SchemaError("artifact_location is required")
        object.__setattr__(
            self,
            "artifact_location",
            _copy_json(self.artifact_location, "artifact_location"),
        )
        if self.analyzer is None:
            raise SchemaError("analyzer is required")
        object.__setattr__(self, "analyzer", _copy_json(self.analyzer, "analyzer"))
        if self.provenance is None:
            raise SchemaError("provenance is required")
        object.__setattr__(self, "provenance", _copy_json(self.provenance, "provenance"))
        for name in (
            "references",
            "reference_ids",
            "calls",
            "call_targets",
            "callees",
            "callers",
            "related_observation_ids",
        ):
            object.__setattr__(self, name, _ids(getattr(self, name), name))
        object.__setattr__(self, "relationships", _mapping(self.relationships, "relationships"))
        object.__setattr__(self, "metadata", _mapping(self.metadata, "metadata"))
        object.__setattr__(self, "extra", _mapping(self.extra, "extra"))
        if self.analyzer_version is not None:
            object.__setattr__(
                self, "analyzer_version", _text(self.analyzer_version, "analyzer_version")
            )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Observation":
        if not isinstance(data, Mapping):
            raise SchemaError("observation must be an object")
        _version(data)
        known = {
            "schema_version",
            "version",
            "id",
            "observation_id",
            "type",
            "kind",
            "raw_value",
            "raw",
            "normalized_value",
            "normalized",
            "value",
            "artifact_location",
            "location",
            "artifact",
            "analyzer",
            "analyzer_identity",
            "provenance",
            "source",
            "references",
            "reference_ids",
            "calls",
            "call_targets",
            "call_target_ids",
            "callees",
            "callee_ids",
            "callers",
            "caller_ids",
            "related_observation_ids",
            "related_ids",
            "relationships",
            "metadata",
            "analyzer_version",
            "extra",
        }
        extras = dict(data.get("extra", {})) if isinstance(data.get("extra", {}), Mapping) else {}
        extras.update({key: value for key, value in data.items() if key not in known})

        def merged_ids(*names: str) -> tuple[str, ...]:
            values: list[str] = []
            for name in names:
                if name in data:
                    values.extend(_ids(data[name], name))
            return tuple(dict.fromkeys(values))

        return cls(
            id=_required(data, "id", "observation_id"),
            type=_required(data, "type", "kind"),
            raw_value=_required(data, "raw_value", "raw"),
            normalized_value=_required(data, "normalized_value", "normalized", "value"),
            artifact_location=_required(data, "artifact_location", "location", "artifact"),
            analyzer=_required(data, "analyzer", "analyzer_identity"),
            provenance=_required(data, "provenance", "source"),
            references=merged_ids("references"),
            reference_ids=merged_ids("reference_ids"),
            calls=merged_ids("calls"),
            call_targets=merged_ids("call_targets", "call_target_ids"),
            callees=merged_ids("callees", "callee_ids"),
            callers=merged_ids("callers", "caller_ids"),
            related_observation_ids=merged_ids("related_observation_ids", "related_ids"),
            relationships=_first(data, "relationships", default={}),
            metadata=_first(data, "metadata", default={}),
            analyzer_version=data.get("analyzer_version"),
            extra=extras,
        )

    def relation_ids(self, relation: str = "all") -> tuple[str, ...]:
        """Return exact IDs in structured relationship fields.

        Unknown relation names return an empty tuple.  The method does not
        search or inspect raw/normalized text.
        """

        relation_key = _text(relation, "relation").casefold()
        call_fields = (
            self.calls,
            self.call_targets,
            self.callees,
            self.callers,
        )
        reference_fields = (
            self.references,
            self.reference_ids,
            self.related_observation_ids,
        )
        values: list[str] = []
        if relation_key in {"all", "relationship", "relationships"}:
            for group in (call_fields, reference_fields):
                for field_values in group:
                    values.extend(field_values)
            for key, value in self.relationships.items():
                if key.casefold() in {
                    "call",
                    "calls",
                    "callee",
                    "callees",
                    "caller",
                    "callers",
                    "reference",
                    "references",
                    "related",
                    "related_ids",
                    "targets",
                    "edges",
                }:
                    values.extend(_relation_ids(value))
        elif relation_key in {"call", "calls", "callee", "callees", "caller", "callers"}:
            for field_values in call_fields:
                values.extend(field_values)
            for key, value in self.relationships.items():
                if key.casefold() in {"call", "calls", "callee", "callees", "caller", "callers", "targets"}:
                    values.extend(_relation_ids(value))
        elif relation_key in {"reference", "references", "related", "related_ids"}:
            for field_values in reference_fields:
                values.extend(field_values)
            for key, value in self.relationships.items():
                if key.casefold() in {"reference", "references", "related", "related_ids", "edges"}:
                    values.extend(_relation_ids(value))
        return tuple(dict.fromkeys(values))

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "schema_version": PERSISTED_VERSION,
            "id": self.id,
            "type": self.type,
            "raw_value": _copy_json(self.raw_value, "raw_value"),
            "normalized_value": _copy_json(self.normalized_value, "normalized_value"),
            "artifact_location": _copy_json(self.artifact_location, "artifact_location"),
            "analyzer": _copy_json(self.analyzer, "analyzer"),
            "provenance": _copy_json(self.provenance, "provenance"),
        }
        for name in (
            "references",
            "reference_ids",
            "calls",
            "call_targets",
            "callees",
            "callers",
            "related_observation_ids",
        ):
            values = getattr(self, name)
            if values:
                result[name] = list(values)
        if self.relationships:
            result["relationships"] = _copy_json(dict(self.relationships), "relationships")
        if self.metadata:
            result["metadata"] = _copy_json(dict(self.metadata), "metadata")
        if self.analyzer_version is not None:
            result["analyzer_version"] = self.analyzer_version
        for key, value in sorted(self.extra.items()):
            if key not in result and key not in {"schema_version", "version"}:
                result[key] = _copy_json(value, f"extra[{key}]")
        return result


@dataclass(frozen=True)
class Claim:
    """A model-produced assertion, always anchored to observation IDs."""

    id: str
    classification: str
    explanation: str
    confidence: float
    evidence_ids: tuple[str, ...]
    asset_role: str | None
    reachability: Reachability
    unresolved: bool
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _text(self.id, "id"))
        object.__setattr__(self, "classification", _text(self.classification, "classification"))
        object.__setattr__(self, "explanation", _text(self.explanation, "explanation"))
        if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)):
            raise SchemaError("confidence must be a number from 0 to 1")
        confidence = float(self.confidence)
        if not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
            raise SchemaError("confidence must be a number from 0 to 1")
        object.__setattr__(self, "confidence", confidence)
        object.__setattr__(self, "evidence_ids", _ids(self.evidence_ids, "evidence_ids", required=True))
        object.__setattr__(self, "asset_role", _optional_text(self.asset_role, "asset_role"))
        if isinstance(self.reachability, Mapping):
            object.__setattr__(self, "reachability", Reachability.from_dict(self.reachability))
        if not isinstance(self.reachability, Reachability):
            raise SchemaError("reachability must be a Reachability object")
        if not isinstance(self.unresolved, bool):
            raise SchemaError("unresolved must be a boolean")
        object.__setattr__(self, "metadata", _mapping(self.metadata, "metadata"))

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Claim":
        if not isinstance(data, Mapping):
            raise SchemaError("claim must be an object")
        required = {
            "schema_version", "id", "classification", "explanation", "confidence",
            "evidence_ids", "asset_role", "reachability", "unresolved",
        }
        if not required.issubset(data) or not set(data).issubset(required | {"metadata"}):
            raise SchemaError("claim has missing or unknown canonical fields")
        _version(data)
        return cls(
            id=data["id"],
            classification=data["classification"],
            explanation=data["explanation"],
            confidence=data["confidence"],
            evidence_ids=data["evidence_ids"],
            asset_role=data["asset_role"],
            reachability=Reachability.from_dict(data["reachability"]),
            unresolved=data["unresolved"],
            metadata=_first(data, "metadata", default={}),
        )

    def to_dict(self) -> dict[str, Any]:
        result = {
            "schema_version": PERSISTED_VERSION,
            "id": self.id,
            "classification": self.classification,
            "explanation": self.explanation,
            "confidence": self.confidence,
            "evidence_ids": list(self.evidence_ids),
            "asset_role": self.asset_role,
            "reachability": self.reachability.to_dict(),
            "unresolved": self.unresolved,
        }
        if self.metadata:
            result["metadata"] = _copy_json(dict(self.metadata), "metadata")
        return result


@dataclass(frozen=True)
class Judgment:
    """Optional independent judge output."""

    claim_id: str
    verdict: Literal["supported", "unsupported", "unclear"]
    cited_evidence_ids: tuple[str, ...] = ()
    judge_model: str | None = None
    explanation: str = ""
    model_metadata: Mapping[str, Any] = field(default_factory=dict)
    usage: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "claim_id", _text(self.claim_id, "claim_id"))
        if self.verdict not in {"supported", "unsupported", "unclear"}:
            raise SchemaError("judgment.verdict must be supported, unsupported, or unclear")
        object.__setattr__(
            self,
            "cited_evidence_ids",
            _ids(self.cited_evidence_ids, "cited_evidence_ids"),
        )
        if self.judge_model is not None:
            object.__setattr__(self, "judge_model", _text(self.judge_model, "judge_model"))
        object.__setattr__(self, "explanation", _text(self.explanation, "explanation", allow_empty=True))
        object.__setattr__(self, "model_metadata", _mapping(self.model_metadata, "model_metadata"))
        object.__setattr__(self, "usage", _mapping(self.usage, "usage"))

    @property
    def evidence_ids(self) -> tuple[str, ...]:
        """Compatibility alias used by claim-oriented callers."""

        return self.cited_evidence_ids

    @property
    def model(self) -> str | None:
        return self.judge_model

    @property
    def judge(self) -> dict[str, Any]:
        """JSON-shaped compatibility view used by the Go persistence schema."""

        value = dict(self.model_metadata)
        if self.judge_model is not None:
            value.setdefault("model", self.judge_model)
        return value

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Judgment":
        if not isinstance(data, Mapping):
            raise SchemaError("judgment must be an object")
        required = {
            "schema_version", "claim_id", "verdict", "cited_evidence_ids",
            "judge_model", "explanation", "model_metadata", "usage",
        }
        if set(data) != required:
            raise SchemaError("judgment has missing or unknown canonical fields")
        _version(data)
        if not isinstance(data["judge_model"], str) or not data["judge_model"].strip():
            raise SchemaError("judgment.judge_model is required")
        if not isinstance(data["explanation"], str) or not data["explanation"].strip():
            raise SchemaError("judgment.explanation is required")
        return cls(
            claim_id=data["claim_id"],
            verdict=data["verdict"],
            cited_evidence_ids=data["cited_evidence_ids"],
            judge_model=data["judge_model"],
            explanation=data["explanation"],
            model_metadata=data["model_metadata"],
            usage=data["usage"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": PERSISTED_VERSION,
            "claim_id": self.claim_id,
            "verdict": self.verdict,
            "cited_evidence_ids": list(self.cited_evidence_ids),
            "judge_model": self.judge_model,
            "explanation": self.explanation,
            "model_metadata": _copy_json(dict(self.model_metadata), "model_metadata"),
            "usage": _copy_json(dict(self.usage), "usage"),
        }


@dataclass(frozen=True)
class VerificationResult:
    """The deterministic decision for one claim."""

    claim_id: str
    status: Literal["accepted", "rejected", "unclear"] = "rejected"
    accepted: bool = False
    reasons: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    confidence: float | None = None
    reachability_supported: bool | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "claim_id", _text(self.claim_id, "claim_id"))
        if self.status not in {"accepted", "rejected", "unclear"}:
            raise SchemaError("verification status must be accepted, rejected, or unclear")
        # ``accepted=True`` was used by an early prototype without a status;
        # retain that ergonomic constructor while keeping persisted output
        # explicit and internally consistent.
        status = "accepted" if self.accepted and self.status == "rejected" else self.status
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "accepted", status == "accepted")
        object.__setattr__(self, "reasons", tuple(_text(reason, "reasons[]") for reason in self.reasons))
        object.__setattr__(self, "evidence_ids", _ids(self.evidence_ids, "evidence_ids"))
        if self.confidence is not None:
            if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)):
                raise SchemaError("verification confidence must be a number from 0 to 1")
            confidence = float(self.confidence)
            if not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
                raise SchemaError("verification confidence must be a number from 0 to 1")
            object.__setattr__(self, "confidence", confidence)
        if self.reachability_supported is not None and not isinstance(
            self.reachability_supported, bool
        ):
            raise SchemaError("reachability_supported must be a boolean or null")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "VerificationResult":
        if not isinstance(data, Mapping):
            raise SchemaError("verification result must be an object")
        _version(data)
        status = _first(data, "status", "verification", default=None)
        accepted = bool(_first(data, "accepted", default=False))
        if status is None:
            status = "accepted" if accepted else "rejected"
        return cls(
            claim_id=_required(data, "claim_id", "id"),
            status=status,
            accepted=accepted,
            reasons=_first(data, "reasons", "reason", default=()),
            evidence_ids=_first(data, "evidence_ids", default=()),
            confidence=_first(data, "confidence", default=None),
            reachability_supported=_first(data, "reachability_supported", default=None),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": PERSISTED_VERSION,
            "claim_id": self.claim_id,
            "status": self.status,
            "accepted": self.accepted,
            "reasons": list(self.reasons),
            "evidence_ids": list(self.evidence_ids),
            "confidence": self.confidence,
            "reachability_supported": self.reachability_supported,
        }


@dataclass(frozen=True)
class Score:
    """Aggregate verification and optional-judge results."""

    accepted: int
    rejected: int
    unclear: int
    verification_results: tuple[VerificationResult, ...] = ()
    judgments: tuple[Judgment, ...] = ()
    confidence: float = 0.0
    usage: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("accepted", "rejected", "unclear"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise SchemaError(f"{name} must be a nonnegative integer")
        object.__setattr__(
            self,
            "verification_results",
            tuple(
                item if isinstance(item, VerificationResult) else VerificationResult.from_dict(item)
                for item in (self.verification_results or ())
            ),
        )
        seen_results: set[str] = set()
        for result in self.verification_results:
            if result.claim_id in seen_results:
                raise SchemaError(f"duplicate verification result for claim: {result.claim_id}")
            seen_results.add(result.claim_id)
        object.__setattr__(
            self,
            "judgments",
            tuple(
                item if isinstance(item, Judgment) else Judgment.from_dict(item)
                for item in (self.judgments or ())
            ),
        )
        seen_judgments: set[str] = set()
        for judgment in self.judgments:
            if judgment.claim_id in seen_judgments:
                raise SchemaError(f"duplicate judgment for claim: {judgment.claim_id}")
            seen_judgments.add(judgment.claim_id)
        result_counts = {"accepted": 0, "rejected": 0, "unclear": 0}
        for result in self.verification_results:
            result_counts[result.status] += 1
        if (
            self.accepted,
            self.rejected,
            self.unclear,
        ) != (
            result_counts["accepted"],
            result_counts["rejected"],
            result_counts["unclear"],
        ):
            raise SchemaError("score counts must match verification result statuses")
        if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)):
            raise SchemaError("score confidence must be a number from 0 to 1")
        confidence = float(self.confidence)
        if not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
            raise SchemaError("score confidence must be a number from 0 to 1")
        object.__setattr__(self, "confidence", confidence)
        object.__setattr__(self, "usage", _mapping(self.usage, "usage"))

    @property
    def accepted_count(self) -> int:
        return self.accepted

    @property
    def rejected_count(self) -> int:
        return self.rejected

    @property
    def unclear_count(self) -> int:
        return self.unclear

    @property
    def verifications(self) -> tuple[VerificationResult, ...]:
        """Compatibility alias for the shorter persisted field name."""

        return self.verification_results

    @property
    def model_usage(self) -> Mapping[str, Any]:
        return self.usage

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Score":
        if not isinstance(data, Mapping):
            raise SchemaError("score must be an object")
        _version(data)
        return cls(
            accepted=_required(data, "accepted", "accepted_count"),
            rejected=_required(data, "rejected", "rejected_count"),
            unclear=_required(data, "unclear", "unclear_count"),
            verification_results=_first(
                data,
                "verification_results",
                "verifications",
                "results",
                default=(),
            ),
            judgments=_first(data, "judgments", default=()),
            confidence=_first(data, "confidence", default=0.0),
            usage=_first(data, "usage", "model_usage", default={}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": PERSISTED_VERSION,
            "accepted": self.accepted,
            "rejected": self.rejected,
            "unclear": self.unclear,
            "verification_results": [item.to_dict() for item in self.verification_results],
            "judgments": [item.to_dict() for item in self.judgments],
            "confidence": self.confidence,
            "usage": _copy_json(dict(self.usage), "usage"),
        }


@dataclass(frozen=True)
class RunManifest:
    """Controller run metadata kept here for one canonical serialization."""

    run_id: str
    status: str
    artifact_hashes: Mapping[str, Any] = field(default_factory=dict)
    timestamps: Mapping[str, Any] = field(default_factory=dict)
    versions: Mapping[str, Any] = field(default_factory=dict)
    configuration_hashes: Mapping[str, Any] = field(default_factory=dict)
    model_roles: Mapping[str, Any] = field(default_factory=dict)
    prompt_hashes: Mapping[str, Any] = field(default_factory=dict)
    resource_usage: Mapping[str, Any] = field(default_factory=dict)
    extra: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "run_id", _text(self.run_id, "run_id"))
        object.__setattr__(self, "status", _text(self.status, "status"))
        for name in (
            "artifact_hashes",
            "timestamps",
            "versions",
            "configuration_hashes",
            "model_roles",
            "prompt_hashes",
            "resource_usage",
            "extra",
        ):
            object.__setattr__(self, name, _mapping(getattr(self, name), name))

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "RunManifest":
        if not isinstance(data, Mapping):
            raise SchemaError("run manifest must be an object")
        _version(data)
        known = {
            "schema_version",
            "version",
            "run_id",
            "status",
            "artifact_hashes",
            "timestamps",
            "versions",
            "configuration_hashes",
            "config_hashes",
            "model_roles",
            "prompt_hashes",
            "resource_usage",
            "extra",
        }
        extra = dict(data.get("extra", {})) if isinstance(data.get("extra", {}), Mapping) else {}
        extra.update({key: value for key, value in data.items() if key not in known})
        return cls(
            run_id=_required(data, "run_id", "id"),
            status=_required(data, "status"),
            artifact_hashes=_first(data, "artifact_hashes", default={}),
            timestamps=_first(data, "timestamps", default={}),
            versions=_first(data, "versions", default={}),
            configuration_hashes=_first(data, "configuration_hashes", "config_hashes", default={}),
            model_roles=_first(data, "model_roles", default={}),
            prompt_hashes=_first(data, "prompt_hashes", default={}),
            resource_usage=_first(data, "resource_usage", default={}),
            extra=extra,
        )

    def to_dict(self) -> dict[str, Any]:
        result = {
            "schema_version": PERSISTED_VERSION,
            "run_id": self.run_id,
            "status": self.status,
            "artifact_hashes": _copy_json(dict(self.artifact_hashes), "artifact_hashes"),
            "timestamps": _copy_json(dict(self.timestamps), "timestamps"),
            "versions": _copy_json(dict(self.versions), "versions"),
            "configuration_hashes": _copy_json(
                dict(self.configuration_hashes), "configuration_hashes"
            ),
            "model_roles": _copy_json(dict(self.model_roles), "model_roles"),
            "prompt_hashes": _copy_json(dict(self.prompt_hashes), "prompt_hashes"),
            "resource_usage": _copy_json(dict(self.resource_usage), "resource_usage"),
        }
        for key, value in sorted(self.extra.items()):
            if key not in result:
                result[key] = _copy_json(value, f"extra[{key}]")
        return result


def as_claim(value: Claim | Mapping[str, Any]) -> Claim:
    return value if isinstance(value, Claim) else Claim.from_dict(value)


def as_observation(value: Observation | Mapping[str, Any]) -> Observation:
    return value if isinstance(value, Observation) else Observation.from_dict(value)


def as_judgment(value: Judgment | Mapping[str, Any]) -> Judgment:
    return value if isinstance(value, Judgment) else Judgment.from_dict(value)


def as_verification_result(value: VerificationResult | Mapping[str, Any]) -> VerificationResult:
    return value if isinstance(value, VerificationResult) else VerificationResult.from_dict(value)


__all__ = [
    "PERSISTED_VERSION",
    "SCHEMA_VERSION",
    "SchemaError",
    "ValidationError",
    "Reachability",
    "Observation",
    "Claim",
    "Judgment",
    "VerificationResult",
    "Score",
    "RunManifest",
    "as_claim",
    "as_observation",
    "as_judgment",
    "as_verification_result",
]
