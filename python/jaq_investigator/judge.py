"""Optional independent claim judge.

The judge is deliberately a second, tool-free model role.  It receives only
candidate claims and the observations those claims cite; it cannot broaden
the evidence set or perform arbitrary I/O.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Mapping

from .investigator import (
    DEFAULT_SCHEMA_VERSION,
    EvidenceStore,
    _call_with_supported_keywords,
    _cap_tool_result,
    _json_safe,
    _lookup_observation,
    validate_claims,
)
from .model import (
    LiteLLMModelClient,
    ModelClient,
    ModelError,
    ModelTimeoutError,
    response_model,
    response_provider,
    response_tool_calls,
    response_usage,
    structured_payload,
)
from .prompts import JUDGMENTS_SCHEMA, build_judge_messages


class JudgeError(RuntimeError):
    """Base class for deterministic judge failures."""


class JudgeValidationError(JudgeError):
    """The independent model returned malformed or out-of-scope judgments."""


@dataclass
class JudgeConfig:
    """Configuration for the optional judge role."""

    model: str | None = None
    timeout: float = 60.0
    max_tokens: int = 4_000
    max_evidence_chars: int = 128_000
    schema_version: str = DEFAULT_SCHEMA_VERSION

    @classmethod
    def from_env(cls, **kwargs: Any) -> "JudgeConfig":
        if "model" not in kwargs:
            selected = os.environ.get("JAQ_JUDGE_MODEL")
            kwargs["model"] = selected if selected and selected.strip() else None
        return cls(**kwargs)

    def validate(self) -> None:
        if self.model is not None and (not isinstance(self.model, str) or not self.model.strip()):
            raise ValueError("judge model must be a non-empty provider/model string")
        if not isinstance(self.timeout, (int, float)) or isinstance(self.timeout, bool) or self.timeout <= 0:
            raise ValueError("judge timeout must be positive")
        if not isinstance(self.max_tokens, int) or isinstance(self.max_tokens, bool) or not 1 <= self.max_tokens <= 100_000:
            raise ValueError("judge max_tokens must be between 1 and 100000")
        if not isinstance(self.max_evidence_chars, int) or not 1 <= self.max_evidence_chars <= 4_000_000:
            raise ValueError("max_evidence_chars must be between 1 and 4000000")
        if not isinstance(self.schema_version, str) or not self.schema_version.strip():
            raise ValueError("judge schema_version must be non-empty")
        if self.schema_version != DEFAULT_SCHEMA_VERSION:
            raise ValueError(f"only persisted schema_version {DEFAULT_SCHEMA_VERSION!r} is supported")


def _claim_id(claim: Mapping[str, Any]) -> str:
    value = claim.get("id", claim.get("claim_id"))
    if not isinstance(value, str) or not value:
        raise JudgeValidationError("candidate claim has no valid id")
    return value


def _claim_evidence_ids(claim: Mapping[str, Any]) -> list[str]:
    value = claim.get("evidence_ids", [])
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise JudgeValidationError("candidate claim has malformed evidence_ids")
    reachability = claim.get("reachability")
    if not isinstance(reachability, Mapping):
        raise JudgeValidationError("candidate claim has malformed reachability")
    path_ids = reachability.get("path_evidence_ids")
    if not isinstance(path_ids, list) or any(not isinstance(item, str) or not item for item in path_ids):
        raise JudgeValidationError("candidate claim has malformed path_evidence_ids")
    return list(dict.fromkeys([*value, *path_ids]))


def _canonical_judgments(
    payload: Any,
    *,
    claim_ids: set[str],
    claim_evidence: Mapping[str, set[str]],
    model: str,
    provider: str,
    usage: Mapping[str, int],
    schema_version: str,
) -> dict[str, Any]:
    if not isinstance(payload, Mapping) or set(payload) != {"schema_version", "judgments"}:
        raise JudgeValidationError("judge output must contain exactly schema_version and judgments")
    if not isinstance(payload["judgments"], list):
        raise JudgeValidationError("judge output must contain a judgments array")
    supplied_version = payload["schema_version"]
    if supplied_version != schema_version:
        raise JudgeValidationError(
            f"unsupported judgment schema_version {supplied_version!r}; expected {schema_version!r}"
        )
    raw_judgments = payload["judgments"]
    if len(raw_judgments) > len(claim_ids):
        raise JudgeValidationError("judge returned more judgments than candidate claims")
    canonical: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in raw_judgments:
        if not isinstance(raw, Mapping):
            raise JudgeValidationError("each judgment must be an object")
        required = {"claim_id", "verdict", "cited_evidence_ids", "explanation"}
        if set(raw) != required:
            raise JudgeValidationError(f"each judgment must contain exactly {sorted(required)}")
        claim_id = _claim_id(raw)
        if len(claim_id) > 200:
            raise JudgeValidationError("judgment claim_id exceeds 200 characters")
        if claim_id not in claim_ids:
            raise JudgeValidationError(f"judge returned judgment for unknown claim {claim_id!r}")
        if claim_id in seen:
            raise JudgeValidationError(f"duplicate judgment for claim {claim_id!r}")
        seen.add(claim_id)
        verdict = raw.get("verdict")
        if verdict not in {"supported", "unsupported", "unclear"}:
            raise JudgeValidationError(f"invalid verdict for claim {claim_id!r}")
        explanation = raw.get("explanation")
        if not isinstance(explanation, str) or not explanation.strip() or len(explanation) > 12000:
            raise JudgeValidationError(f"judgment for claim {claim_id!r} has empty explanation")
        cited = raw["cited_evidence_ids"]
        if not isinstance(cited, list) or len(cited) > 100 or any(
            not isinstance(item, str) or not item or len(item) > 300 for item in cited
        ):
            raise JudgeValidationError(f"judgment for claim {claim_id!r} has malformed evidence IDs")
        if len(set(cited)) != len(cited):
            raise JudgeValidationError(f"judgment for claim {claim_id!r} repeats evidence IDs")
        cited = list(dict.fromkeys(cited))
        if any(item not in claim_evidence.get(claim_id, set()) for item in cited):
            raise JudgeValidationError(f"judgment for claim {claim_id!r} cites evidence outside its claim")
        canonical.append(
            {
                "schema_version": schema_version,
                "claim_id": claim_id,
                "verdict": verdict,
                "cited_evidence_ids": cited,
                "judge_model": model,
                "model_metadata": {"provider": provider, "model": model},
                "usage": dict(usage),
                "explanation": explanation.strip(),
            }
        )
    if seen != claim_ids:
        missing = sorted(claim_ids - seen)
        raise JudgeValidationError(f"judge omitted claim(s): {', '.join(missing)}")
    # Usage is returned separately for score/run-manifest accounting. It is
    # intentionally not copied into each persisted Judgment.
    return {"schema_version": schema_version, "judgments": canonical, "usage": dict(usage)}


class Judge:
    """Run an optional no-tools independent review of investigator claims."""

    def __init__(
        self,
        evidence_store: EvidenceStore,
        model_client: ModelClient | Any | None = None,
        config: JudgeConfig | None = None,
        *,
        client: ModelClient | Any | None = None,
    ) -> None:
        if client is not None:
            if model_client is not None:
                raise ValueError("provide model_client or client, not both")
            model_client = client
        self.evidence_store = evidence_store
        self.config = config or JudgeConfig.from_env()
        self.config.validate()
        self.model_client = model_client
        self.last_usage: dict[str, int] = {}
        self.last_model: str | None = None
        self.last_provider: str | None = None

    def _get_client(self) -> Any | None:
        if self.model_client is not None:
            return self.model_client
        if self.config.model is None or not self.config.model.strip():
            return None
        self.model_client = LiteLLMModelClient(
            self.config.model,
            env_var="JAQ_JUDGE_MODEL",
            default_timeout=self.config.timeout,
            default_max_tokens=self.config.max_tokens,
        )
        return self.model_client

    def _invoke_model(self, messages: list[dict[str, Any]]) -> Any:
        client = self._get_client()
        if client is None:
            raise JudgeError("judge model is not configured")
        method = getattr(client, "generate_structured", None)
        if not callable(method):
            method = getattr(client, "generate", None)
        if not callable(method):
            method = getattr(client, "complete", None)
        if not callable(method):
            raise ModelError("configured judge client does not implement structured generation")
        kwargs = {
            "messages": messages,
            "schema": JUDGMENTS_SCHEMA,
            "tools": None,
            "timeout": self.config.timeout,
            "max_tokens": self.config.max_tokens,
            "temperature": None,
        }
        try:
            return _call_with_supported_keywords(method, kwargs)
        except ModelError:
            raise
        except TimeoutError as error:
            raise ModelTimeoutError("judge model timed out") from error

    def run(self, claims: Mapping[str, Any] | list[Mapping[str, Any]]) -> dict[str, Any]:
        """Return versioned judgments, or an empty object when disabled."""

        # Validate claim shape and evidence references before exposing anything
        # to the judge. A list is accepted only as an in-process convenience;
        # the model-facing and persisted representation remains an object.
        if isinstance(claims, list):
            claims = {"schema_version": self.config.schema_version, "claims": claims}
        canonical_claims = validate_claims(
            claims,
            evidence_store=self.evidence_store,
            max_claims=100,
            schema_version=self.config.schema_version,
        )
        if self._get_client() is None:
            self.last_usage = {}
            self.last_model = None
            self.last_provider = None
            return {"schema_version": self.config.schema_version, "judgments": [], "usage": {}}

        evidence_by_claim: dict[str, list[Mapping[str, Any]]] = {}
        claim_evidence: dict[str, set[str]] = {}
        for claim in canonical_claims["claims"]:
            claim_id = claim["id"]
            ids = _claim_evidence_ids(claim)
            claim_evidence[claim_id] = set(ids)
            records: list[Mapping[str, Any]] = []
            for evidence_id in ids:
                record = _lookup_observation(self.evidence_store, evidence_id)
                safe = _json_safe(record)
                if not isinstance(safe, Mapping):
                    safe = {"id": evidence_id, "value": safe}
                records.append(dict(safe))
            evidence_by_claim[claim_id] = records

        # Bound the complete judge context as well as each cited record. This
        # prevents a large set of individually valid observations from turning
        # into an unbounded prompt while preserving the claim-to-evidence map.
        record_count = sum(len(records) for records in evidence_by_claim.values())
        if record_count:
            record_budget = max(64, self.config.max_evidence_chars // record_count)
            evidence_by_claim = {
                claim_id: [_cap_tool_result(record, record_budget) for record in records]
                for claim_id, records in evidence_by_claim.items()
            }

        messages = build_judge_messages(canonical_claims, evidence_by_claim)
        context_chars = sum(len(str(message.get("content", ""))) for message in messages)
        if context_chars > self.config.max_evidence_chars:
            raise JudgeError("claims and cited evidence exceed the bounded judge context")
        raw_response = self._invoke_model(messages)
        if response_tool_calls(raw_response):
            raise JudgeValidationError("judge response attempted an unallowlisted tool call")
        payload = structured_payload(raw_response)
        if payload is None:
            raise JudgeValidationError("judge returned neither tool calls nor structured judgments")
        model_name = response_model(raw_response, getattr(self._get_client(), "model", self.config.model))
        provider_name = response_provider(raw_response, getattr(self._get_client(), "provider", "unknown"))
        model_name = model_name or self.config.model or "unknown"
        provider_name = provider_name or "unknown"
        usage = response_usage(raw_response)
        result = _canonical_judgments(
            payload,
            claim_ids=set(claim_evidence),
            claim_evidence=claim_evidence,
            model=model_name,
            provider=provider_name,
            usage=usage,
            schema_version=self.config.schema_version,
        )
        self.last_usage = dict(usage)
        self.last_model = model_name
        self.last_provider = provider_name
        return result

    judge = run


def judge_claims(
    claims: Mapping[str, Any] | list[Mapping[str, Any]],
    evidence_store: EvidenceStore,
    *,
    client: ModelClient | Any | None = None,
    config: JudgeConfig | None = None,
) -> dict[str, Any]:
    return Judge(evidence_store, client=client, config=config).run(claims)


__all__ = [
    "Judge",
    "JudgeConfig",
    "JudgeError",
    "JudgeValidationError",
    "judge_claims",
]
