"""Bounded, read-only investigator loop over an evidence package."""

from __future__ import annotations

import dataclasses
import hashlib
import inspect
import json
import math
import os
import re
from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol, Sequence, runtime_checkable

from .model import (
    LiteLLMModelClient,
    ModelClient,
    ModelError,
    response_model,
    response_provider,
    response_tool_calls,
    response_usage,
    structured_payload,
)
from .prompts import CLAIMS_SCHEMA, INVESTIGATOR_TOOLS, build_investigator_messages


DEFAULT_SCHEMA_VERSION = "1.0"
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_ALLOWED_TOOL_NAMES = frozenset(
    {
        "list_observation_types",
        "list_observations",
        "get_observation",
        "search_observations",
        "get_neighbors",
    }
)


class InvestigatorError(RuntimeError):
    """Base class for deterministic investigator failures."""


class InvalidToolCallError(InvestigatorError):
    """The model attempted to call a tool outside the exact allowlist/shape."""


class EvidenceToolError(InvestigatorError):
    """An allowlisted evidence operation failed."""


class EvidenceReferenceError(InvestigatorError):
    """A final claim cited an observation not present in the store."""


class InvestigatorLimitError(InvestigatorError):
    """The model exhausted the configured rounds or output budget."""


class ClaimsValidationError(InvestigatorError):
    """The final structured claims object did not satisfy the contract."""


# Compatibility spellings for callers/tests that use a more specific name.
InvalidToolError = InvalidToolCallError
InvalidClaimsError = ClaimsValidationError


@runtime_checkable
class EvidenceStore(Protocol):
    """Read-only typed operations exposed to the model loop."""

    def list_observation_types(self) -> Any:
        ...

    def list_observations(
        self, *, type: str | None = None, limit: int = 20, cursor: str | None = None
    ) -> Any:
        ...

    def get_observation(self, *, id: str) -> Any:
        ...

    def search_observations(self, *, query: str, type: str | None = None, limit: int = 20) -> Any:
        ...

    def get_neighbors(self, *, id: str, limit: int = 20) -> Any:
        ...


@dataclass
class InvestigatorConfig:
    """Bounds and model selector for one investigator run."""

    model: str | None = None
    timeout: float = 60.0
    max_rounds: int = 8
    max_tool_output_chars: int = 16_000
    max_tool_calls: int = 64
    max_claims: int = 100
    max_tokens: int = 4_000
    temperature: float | None = None
    schema_version: str = DEFAULT_SCHEMA_VERSION

    @classmethod
    def from_env(cls, **kwargs: Any) -> "InvestigatorConfig":
        """Create config using only the investigator model selector env var."""

        if "model" not in kwargs:
            selected = os.environ.get("JAQ_INVESTIGATOR_MODEL")
            kwargs["model"] = selected if selected and selected.strip() else None
        return cls(**kwargs)

    def validate(self) -> None:
        if self.model is not None and (not isinstance(self.model, str) or not self.model.strip()):
            raise ValueError("model must be a non-empty provider/model string")
        if not isinstance(self.timeout, (int, float)) or isinstance(self.timeout, bool) or self.timeout <= 0:
            raise ValueError("timeout must be positive")
        if not isinstance(self.max_rounds, int) or isinstance(self.max_rounds, bool) or not 1 <= self.max_rounds <= 100:
            raise ValueError("max_rounds must be between 1 and 100")
        if not isinstance(self.max_tool_output_chars, int) or not 1 <= self.max_tool_output_chars <= 4_000_000:
            raise ValueError("max_tool_output_chars must be between 1 and 4000000")
        if not isinstance(self.max_tool_calls, int) or isinstance(self.max_tool_calls, bool) or not 1 <= self.max_tool_calls <= 1000:
            raise ValueError("max_tool_calls must be between 1 and 1000")
        if not isinstance(self.max_claims, int) or not 1 <= self.max_claims <= 100:
            raise ValueError("max_claims must be between 1 and 100")
        if not isinstance(self.max_tokens, int) or not 1 <= self.max_tokens <= 100_000:
            raise ValueError("max_tokens must be between 1 and 100000")
        if self.temperature is not None and (
            not isinstance(self.temperature, (int, float)) or isinstance(self.temperature, bool) or self.temperature < 0
        ):
            raise ValueError("temperature must be non-negative")
        if not isinstance(self.schema_version, str) or not self.schema_version.strip():
            raise ValueError("schema_version must be non-empty")
        if self.schema_version != DEFAULT_SCHEMA_VERSION:
            raise ValueError(f"only persisted schema_version {DEFAULT_SCHEMA_VERSION!r} is supported")


# Short spelling for controller/tests that use a role-local ``Config`` name.
Config = InvestigatorConfig


@dataclass
class InvestigatorRun:
    """Claims plus non-persisted model accounting for controller handoff."""

    claims: dict[str, Any]
    rounds: int
    tool_calls: int
    usage: dict[str, int] = field(default_factory=dict)
    model: str | None = None
    provider: str | None = None


def _json_safe(value: Any) -> Any:
    """Convert common evidence records to JSON without executing model data."""

    if dataclasses.is_dataclass(value):
        return _json_safe(dataclasses.asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        if isinstance(value, float) and not math.isfinite(value):
            return str(value)
        return value
    # EvidenceStore implementations should return JSON-like records. A
    # representation fallback keeps a malformed record bounded and inert.
    return str(value)


def _compact_json(value: Any) -> str:
    return json.dumps(_json_safe(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _cap_tool_result(value: Any, limit: int) -> Any:
    if limit < 1:
        return None
    safe = _json_safe(value)
    encoded = _compact_json(safe)
    if len(encoded) <= limit:
        return safe
    digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    # Leave enough room for valid JSON framing and the digest. The preview is
    # explicitly data and may be incomplete; the model must fetch a narrower
    # record if it needs more context.
    base = {"truncated": True, "sha256": digest, "preview": ""}
    if len(_compact_json(base)) > limit:
        # Extremely small test/configuration bounds cannot carry a digest. A
        # A tiny numeric JSON value is still bounded; the surrounding tool
        # message remains the authoritative indication that data was capped.
        return 0
    overhead = len(_compact_json(base))
    preview_limit = max(0, limit - overhead - 4)
    base["preview"] = encoded[:preview_limit]
    # A pathological small limit is prevented by InvestigatorConfig, but keep
    # this branch defensive if the helper is called independently.
    while len(_compact_json(base)) > limit and base["preview"]:
        base["preview"] = base["preview"][:-1]
    return base


def _cap_tool_message(name: str, value: Any, limit: int) -> str:
    """Serialize the complete untrusted tool envelope within ``limit`` chars."""

    payload = {"untrusted_evidence": True, "tool": name, "data": _json_safe(value)}
    encoded = _compact_json(payload)
    if len(encoded) <= limit:
        return encoded
    digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    data = {"truncated": True, "sha256": digest, "preview": ""}
    bounded = {"untrusted_evidence": True, "tool": name, "data": data}
    if len(_compact_json(bounded)) > limit:
        # The full marker cannot fit at tiny caller-supplied bounds. Keep the
        # message valid JSON and bounded; the surrounding tool message still
        # carries the exact operation name.
        return "null" if limit >= 4 else "0"
    preview_limit = max(0, limit - len(_compact_json(bounded)) - 4)
    data["preview"] = encoded[:preview_limit]
    while len(_compact_json(bounded)) > limit and data["preview"]:
        data["preview"] = data["preview"][:-1]
    return _compact_json(bounded)


def _increment_usage(total: dict[str, int], current: Mapping[str, int] | None) -> None:
    for key, value in (current or {}).items():
        try:
            number = int(value)
        except (TypeError, ValueError):
            continue
        if number >= 0:
            total[key] = total.get(key, 0) + number


def _call_with_supported_keywords(callable_obj: Any, kwargs: Mapping[str, Any]) -> Any:
    """Call simple fakes as well as full ModelClient implementations."""

    try:
        signature = inspect.signature(callable_obj)
    except (TypeError, ValueError):
        return callable_obj(**dict(kwargs))
    parameters = signature.parameters.values()
    if any(parameter.kind == inspect.Parameter.VAR_KEYWORD for parameter in parameters):
        return callable_obj(**dict(kwargs))
    accepted = {parameter.name for parameter in parameters}
    return callable_obj(**{key: value for key, value in kwargs.items() if key in accepted})


def _parse_mapping_arguments(arguments: Any) -> dict[str, Any]:
    if arguments is None:
        return {}
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except (TypeError, ValueError) as error:
            raise InvalidToolCallError("tool arguments are not valid JSON") from error
    if not isinstance(arguments, Mapping):
        raise InvalidToolCallError("tool arguments must be a JSON object")
    if any(not isinstance(key, str) for key in arguments):
        raise InvalidToolCallError("tool argument names must be strings")
    return dict(arguments)


def _require_only(arguments: Mapping[str, Any], allowed: set[str]) -> None:
    unknown = sorted(set(arguments) - allowed)
    if unknown:
        raise InvalidToolCallError(f"tool arguments contain unsupported field(s): {', '.join(unknown)}")


def _require_string(arguments: Mapping[str, Any], name: str, *, nonempty: bool = True) -> str:
    value = arguments.get(name)
    if not isinstance(value, str) or (nonempty and not value.strip()):
        raise InvalidToolCallError(f"tool argument {name!r} must be a non-empty string")
    return value


def _optional_string(arguments: Mapping[str, Any], name: str) -> str | None:
    if name not in arguments or arguments[name] is None:
        return None
    value = arguments[name]
    if not isinstance(value, str):
        raise InvalidToolCallError(f"tool argument {name!r} must be a string")
    if not value.strip():
        raise InvalidToolCallError(f"tool argument {name!r} must not be empty")
    return value


def _limit(arguments: Mapping[str, Any]) -> int:
    value = arguments.get("limit", 20)
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 100:
        raise InvalidToolCallError("tool argument 'limit' must be an integer between 1 and 100")
    return value


def _cursor(arguments: Mapping[str, Any]) -> str | None:
    if "cursor" not in arguments or arguments["cursor"] is None:
        return None
    value = arguments["cursor"]
    if not isinstance(value, str) or len(value) > 500:
        raise InvalidToolCallError("tool argument 'cursor' must be a string of at most 500 characters")
    return value


def _validate_id(value: str, field_name: str = "id") -> str:
    if len(value) > 300 or not _ID_RE.fullmatch(value):
        raise InvalidToolCallError(f"tool argument {field_name!r} has invalid ID syntax")
    return value


def _invoke_store_operation(store: Any, name: str, arguments: Mapping[str, Any]) -> Any:
    """Invoke one typed operation across the anticipated store spellings.

    The public model-facing names are fixed. The Python core store already in
    this repository predates that naming and offers ``list_types``, ``get``,
    ``search``, and ``neighbors``; this adapter preserves its stricter
    validation while keeping the model allowlist exact.
    """

    candidates: list[tuple[str, Any]] = [(name, getattr(store, name, None))]
    aliases = {
        "list_observation_types": ("list_types",),
        "get_observation": ("get",),
        "search_observations": ("search",),
        "get_neighbors": ("neighbors", "call_neighbors"),
    }
    for alias in aliases.get(name, ()):
        candidates.append((alias, getattr(store, alias, None)))
    method_name, method = next(((candidate_name, candidate) for candidate_name, candidate in candidates if callable(candidate)), (name, None))
    if method is None:
        raise EvidenceToolError(f"EvidenceStore does not implement {name}")

    if method_name == "list_types":
        return method()
    if name == "get_observation":
        try:
            parameters = inspect.signature(method).parameters
        except (TypeError, ValueError):
            parameters = {}
        if "observation_id" in parameters and "id" not in parameters:
            return method(arguments["id"])
        return _call_with_supported_keywords(method, arguments)
    if method_name == "get":
        return method(arguments["id"])
    if name == "list_observations" and method_name == "list_observations":
        result = _call_with_supported_keywords(method, arguments)
        # Older core stores accept only ``type``. Apply the controller-facing
        # cursor/limit contract after that call when the result is a plain
        # list or an observations envelope.
        cursor = arguments.get("cursor")
        limit = arguments.get("limit", 20)
        if isinstance(result, list):
            values = result
            start = 0
            if cursor:
                for index, item in enumerate(values):
                    if isinstance(item, Mapping) and str(item.get("id")) == cursor:
                        start = index + 1
                        break
                    if getattr(item, "id", None) == cursor:
                        start = index + 1
                        break
            return values[start : start + limit]
        if isinstance(result, Mapping) and isinstance(result.get("observations"), list):
            values = list(result["observations"])
            start = 0
            if cursor:
                for index, item in enumerate(values):
                    item_id = item.get("id") if isinstance(item, Mapping) else getattr(item, "id", None)
                    if str(item_id) == cursor:
                        start = index + 1
                        break
            envelope = dict(result)
            envelope["observations"] = values[start : start + limit]
            return envelope
        return result
    if method_name == "search":
        # Core EvidenceStore intentionally searches normalized values only.
        return method(arguments["query"], limit=arguments.get("limit", 20))
    if method_name in {"neighbors", "call_neighbors"}:
        # ``neighbors`` accepts one or many exact IDs; the model operation is
        # intentionally one ID and both directions over all relationships.
        return method(arguments["id"], limit=arguments.get("limit", 20))

    return _call_with_supported_keywords(method, arguments)


def _lookup_observation(store: Any, observation_id: str) -> Any:
    method = getattr(store, "get_observation", None)
    if not callable(method):
        # The dependency-free core EvidenceStore names its operation ``get``
        # and exposes get_observation as an alias whose parameter remains
        # ``observation_id``. Keep this compatibility local to the boundary.
        method = getattr(store, "get", None)
    if not callable(method):
        raise EvidenceReferenceError("EvidenceStore does not expose get_observation")
    try:
        try:
            parameters = inspect.signature(method).parameters
        except (TypeError, ValueError):
            parameters = {}
        if "id" in parameters:
            result = method(id=observation_id)
        elif "observation_id" in parameters:
            result = method(observation_id=observation_id)
        else:
            result = method(observation_id)
    except EvidenceReferenceError:
        raise
    except Exception as error:
        raise EvidenceReferenceError(f"could not retrieve cited evidence {observation_id!r}") from error
    if result is None:
        raise EvidenceReferenceError(f"claim cites missing evidence {observation_id!r}")
    return result


def _normalize_reachability(
    value: Any, claim_id: str, *, schema_version: str = DEFAULT_SCHEMA_VERSION
) -> dict[str, Any]:
    """Validate the exact persisted reachability object."""

    required = {"schema_version", "status", "entrypoints", "path_evidence_ids"}
    if not isinstance(value, Mapping) or set(value) != required:
        raise ClaimsValidationError(
            f"claim {claim_id!r} reachability must contain exactly {sorted(required)}"
        )
    nested_version = value["schema_version"]
    if nested_version != schema_version:
        raise ClaimsValidationError(f"claim {claim_id!r} has unsupported reachability schema_version")
    status = value["status"]
    entrypoints = value["entrypoints"]
    path_ids = value["path_evidence_ids"]
    if status not in {"reachable", "not_reachable", "unknown"}:
        raise ClaimsValidationError(f"claim {claim_id!r} has invalid reachability status")
    if not isinstance(entrypoints, list) or len(entrypoints) > 100 or any(
        not isinstance(item, str) or not _ID_RE.fullmatch(item) or len(item) > 300 for item in entrypoints
    ):
        raise ClaimsValidationError(f"claim {claim_id!r} reachability entrypoints must be IDs")
    if not isinstance(path_ids, list) or len(path_ids) > 100 or any(
        not isinstance(item, str) or not _ID_RE.fullmatch(item) or len(item) > 300 for item in path_ids
    ):
        raise ClaimsValidationError(f"claim {claim_id!r} reachability path must be IDs")
    if len(set(entrypoints)) != len(entrypoints) or len(set(path_ids)) != len(path_ids):
        raise ClaimsValidationError(f"claim {claim_id!r} reachability IDs must be unique")
    return {
        "schema_version": schema_version,
        "status": status,
        "entrypoints": list(dict.fromkeys(entrypoints)),
        "path_evidence_ids": list(dict.fromkeys(path_ids)),
    }


def validate_claims(
    payload: Any,
    *,
    evidence_store: Any = None,
    max_claims: int = 100,
    schema_version: str = DEFAULT_SCHEMA_VERSION,
) -> dict[str, Any]:
    """Validate and canonicalize a model's final claims object.

    Evidence IDs are checked against the injected store when available.
    """

    if not isinstance(payload, Mapping):
        raise ClaimsValidationError("final model output must be a JSON object")
    if set(payload) != {"schema_version", "claims"}:
        raise ClaimsValidationError("final claims object must contain exactly schema_version and claims")
    supplied_version = payload["schema_version"]
    if not isinstance(supplied_version, str) or not supplied_version.strip():
        raise ClaimsValidationError("final claims object has an invalid schema_version")
    if supplied_version != schema_version:
        raise ClaimsValidationError(
            f"unsupported claims schema_version {supplied_version!r}; expected {schema_version!r}"
        )
    raw_claims = payload.get("claims")
    if not isinstance(raw_claims, list):
        raise ClaimsValidationError("final claims object must contain a claims array")
    if len(raw_claims) > max_claims:
        raise ClaimsValidationError(f"final claims exceed the {max_claims}-claim limit")

    canonical: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, raw_claim in enumerate(raw_claims, start=1):
        if not isinstance(raw_claim, Mapping):
            raise ClaimsValidationError(f"claim {index} must be an object")
        required_claim_fields = {
            "schema_version", "id", "classification", "explanation", "confidence",
            "evidence_ids", "asset_role", "reachability", "unresolved",
        }
        if set(raw_claim) != required_claim_fields:
            raise ClaimsValidationError(
                f"claim {index} must contain exactly {sorted(required_claim_fields)}"
            )
        claim_version = raw_claim["schema_version"]
        if claim_version != schema_version:
            raise ClaimsValidationError(f"claim {index} has unsupported schema_version")
        claim_id = raw_claim["id"]
        if not isinstance(claim_id, str) or len(claim_id) > 200 or not _ID_RE.fullmatch(claim_id):
            raise ClaimsValidationError(f"claim {index} has invalid id")
        if claim_id in seen_ids:
            raise ClaimsValidationError(f"duplicate claim id {claim_id!r}")
        seen_ids.add(claim_id)

        classification = raw_claim["classification"]
        explanation = raw_claim["explanation"]
        if not isinstance(classification, str) or not classification.strip() or len(classification) > 200:
            raise ClaimsValidationError(f"claim {claim_id!r} has empty classification")
        if not isinstance(explanation, str) or not explanation.strip() or len(explanation) > 12000:
            raise ClaimsValidationError(f"claim {claim_id!r} has empty explanation")
        confidence = raw_claim["confidence"]
        if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not math.isfinite(float(confidence)):
            raise ClaimsValidationError(f"claim {claim_id!r} confidence must be a finite number")
        if not 0 <= float(confidence) <= 1:
            raise ClaimsValidationError(f"claim {claim_id!r} confidence must be between 0 and 1")

        evidence_ids = raw_claim["evidence_ids"]
        if not isinstance(evidence_ids, list) or not 1 <= len(evidence_ids) <= 100:
            raise ClaimsValidationError(f"claim {claim_id!r} evidence_ids must be an array")
        normalized_evidence: list[str] = []
        for evidence_id in evidence_ids:
            if not isinstance(evidence_id, str) or len(evidence_id) > 300 or not _ID_RE.fullmatch(evidence_id):
                raise ClaimsValidationError(f"claim {claim_id!r} has invalid evidence ID")
            if evidence_id in normalized_evidence:
                raise ClaimsValidationError(f"claim {claim_id!r} repeats evidence {evidence_id!r}")
            normalized_evidence.append(evidence_id)

        unresolved = raw_claim["unresolved"]
        if not isinstance(unresolved, bool):
            raise ClaimsValidationError(f"claim {claim_id!r} unresolved must be boolean")
        if not normalized_evidence:
            raise ClaimsValidationError(f"claim {claim_id!r} must cite one or more evidence IDs")
        if evidence_store is not None:
            for evidence_id in normalized_evidence:
                _lookup_observation(evidence_store, evidence_id)

        asset_role = raw_claim["asset_role"]
        if asset_role is not None and not isinstance(asset_role, str):
            raise ClaimsValidationError(f"claim {claim_id!r} asset_role must be a string or null")
        if isinstance(asset_role, str) and (not asset_role.strip() or len(asset_role) > 200):
            raise ClaimsValidationError(f"claim {claim_id!r} asset_role must be nonempty and at most 200 characters")
        reachability = _normalize_reachability(
            raw_claim["reachability"], claim_id, schema_version=schema_version
        )

        canonical.append(
            {
                "schema_version": schema_version,
                "id": claim_id,
                "classification": classification.strip(),
                "explanation": explanation.strip(),
                "confidence": float(confidence),
                "evidence_ids": normalized_evidence,
                "asset_role": asset_role,
                "reachability": reachability,
                "unresolved": unresolved,
            }
        )
    return {"schema_version": schema_version, "claims": canonical}


class Investigator:
    """One bounded model/tool loop with no arbitrary model-controlled I/O."""

    def __init__(
        self,
        evidence_store: EvidenceStore,
        model_client: ModelClient | Any | None = None,
        config: InvestigatorConfig | None = None,
        *,
        client: ModelClient | Any | None = None,
    ) -> None:
        if client is not None:
            if model_client is not None:
                raise ValueError("provide model_client or client, not both")
            model_client = client
        self.evidence_store = evidence_store
        self.config = config or InvestigatorConfig.from_env()
        self.config.validate()
        self.model_client = model_client
        self.last_run: InvestigatorRun | None = None

    def _get_client(self) -> Any:
        if self.model_client is None:
            # LiteLLMModelClient reads only JAQ_INVESTIGATOR_MODEL; it raises a
            # stable MissingModelError before attempting an import/call.
            self.model_client = LiteLLMModelClient(
                self.config.model,
                default_timeout=self.config.timeout,
                default_max_tokens=self.config.max_tokens,
            )
        return self.model_client

    def _invoke_model(self, messages: Sequence[Mapping[str, Any]]) -> Any:
        client = self._get_client()
        method = getattr(client, "generate_structured", None)
        if not callable(method):
            method = getattr(client, "generate", None)
        if not callable(method):
            method = getattr(client, "complete", None)
        if not callable(method):
            raise ModelError("configured model client does not implement structured generation")
        kwargs = {
            "messages": messages,
            "schema": CLAIMS_SCHEMA,
            "tools": INVESTIGATOR_TOOLS,
            "timeout": self.config.timeout,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
            "max_rounds": self.config.max_rounds,
        }
        try:
            return _call_with_supported_keywords(method, kwargs)
        except ModelError:
            raise
        except TimeoutError as error:
            # Test doubles sometimes raise the builtin directly; normalize it
            # at this boundary just like the LiteLLM adapter does.
            from .model import ModelTimeoutError

            raise ModelTimeoutError("investigator model timed out") from error

    def _execute_tool(self, name: str, raw_arguments: Any) -> Any:
        if name not in _ALLOWED_TOOL_NAMES:
            raise InvalidToolCallError(f"tool {name!r} is not allowed")
        arguments = _parse_mapping_arguments(raw_arguments)
        if name == "list_observation_types":
            _require_only(arguments, set())
            call_kwargs: dict[str, Any] = {}
        elif name == "list_observations":
            _require_only(arguments, {"type", "limit", "cursor"})
            call_kwargs = {"type": _optional_string(arguments, "type"), "limit": _limit(arguments), "cursor": _cursor(arguments)}
        elif name == "get_observation":
            _require_only(arguments, {"id"})
            call_kwargs = {"id": _validate_id(_require_string(arguments, "id"))}
        elif name == "search_observations":
            _require_only(arguments, {"query", "type", "limit"})
            query = _require_string(arguments, "query")
            if len(query) > 256:
                raise InvalidToolCallError("tool argument 'query' is limited to 256 characters")
            call_kwargs = {
                "query": query,
                "type": _optional_string(arguments, "type"),
                "limit": _limit(arguments),
            }
        else:  # get_neighbors
            _require_only(arguments, {"id", "limit"})
            call_kwargs = {"id": _validate_id(_require_string(arguments, "id")), "limit": _limit(arguments)}

        try:
            result = _invoke_store_operation(self.evidence_store, name, call_kwargs)
        except InvestigatorError:
            raise
        except Exception as error:
            # Do not expose provider/sample-derived exception text to the model
            # or report; callers get a stable category and bounded message.
            raise EvidenceToolError(f"evidence operation {name!r} failed") from error
        return _cap_tool_result(result, self.config.max_tool_output_chars)

    def run(self, task: str | None = None) -> dict[str, Any]:
        """Run until one final claims object is returned."""

        messages: list[dict[str, Any]] = build_investigator_messages(task)
        usage: dict[str, int] = {}
        tool_calls_count = 0
        model_name: str | None = None
        provider_name: str | None = None
        for round_number in range(1, self.config.max_rounds + 1):
            raw_response = self._invoke_model(messages)
            calls = response_tool_calls(raw_response)
            _increment_usage(usage, response_usage(raw_response))
            model_name = response_model(raw_response, getattr(self._get_client(), "model", self.config.model))
            provider_name = response_provider(raw_response, getattr(self._get_client(), "provider", None))

            if calls:
                if tool_calls_count + len(calls) > self.config.max_tool_calls:
                    raise InvestigatorLimitError("model exceeded the configured tool-call limit")
                assistant_message: dict[str, Any] = {"role": "assistant"}
                content = getattr(raw_response, "content", None)
                if isinstance(raw_response, Mapping):
                    content = raw_response.get("content", content)
                if content is not None:
                    assistant_message["content"] = str(content)
                assistant_message["tool_calls"] = [
                    {
                        "id": call.id or f"tool-call-{tool_calls_count + index + 1}",
                        "type": "function",
                        "function": {"name": call.name, "arguments": _compact_json(call.arguments)},
                    }
                    for index, call in enumerate(calls)
                ]
                messages.append(assistant_message)
                for index, call in enumerate(calls):
                    result = self._execute_tool(call.name, call.arguments)
                    call_id = call.id or f"tool-call-{tool_calls_count + index + 1}"
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": call_id,
                            "name": call.name,
                            "content": _cap_tool_message(
                                call.name, result, self.config.max_tool_output_chars
                            ),
                        }
                    )
                    tool_calls_count += 1
                if round_number == self.config.max_rounds:
                    raise InvestigatorLimitError("model did not return final claims before max_rounds")
                continue

            payload = structured_payload(raw_response)
            if payload is None:
                raise ClaimsValidationError("model returned neither tool calls nor structured claims")
            claims = validate_claims(
                payload,
                evidence_store=self.evidence_store,
                max_claims=self.config.max_claims,
                schema_version=self.config.schema_version,
            )
            self.last_run = InvestigatorRun(
                claims=claims,
                rounds=round_number,
                tool_calls=tool_calls_count,
                usage=usage,
                model=model_name,
                provider=provider_name,
            )
            return claims
        raise InvestigatorLimitError("model did not return final claims")

    investigate = run


def run_investigator(
    evidence_store: EvidenceStore,
    *,
    client: ModelClient | Any | None = None,
    config: InvestigatorConfig | None = None,
    task: str | None = None,
) -> dict[str, Any]:
    """Functional convenience wrapper used by the CLI and tests."""

    return Investigator(evidence_store, client=client, config=config).run(task)


__all__ = [
    "ClaimsValidationError",
    "Config",
    "DEFAULT_SCHEMA_VERSION",
    "EvidenceReferenceError",
    "EvidenceStore",
    "EvidenceToolError",
    "InvalidClaimsError",
    "InvalidToolCallError",
    "InvalidToolError",
    "Investigator",
    "InvestigatorConfig",
    "InvestigatorError",
    "InvestigatorLimitError",
    "InvestigatorRun",
    "run_investigator",
    "validate_claims",
]
