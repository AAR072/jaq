"""Deterministic claim verification and score construction."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import json
import re
from typing import Any

from .evidence import EvidenceStore
from .schemas import (
    Claim,
    Judgment,
    SchemaError,
    Score,
    VerificationResult,
    as_claim,
    as_judgment,
    as_verification_result,
)


def _claim_id_hint(value: Any) -> str:
    if isinstance(value, Claim):
        return value.id
    if isinstance(value, Mapping):
        candidate = value.get("id", value.get("claim_id"))
        if isinstance(candidate, str) and candidate.strip():
            return candidate
    return "invalid-claim"


def _result(
    claim: Claim,
    status: str,
    reasons: Iterable[str],
    *,
    reachability_supported: bool | None = None,
) -> VerificationResult:
    return VerificationResult(
        claim_id=claim.id,
        status=status,
        accepted=status == "accepted",
        reasons=tuple(reasons),
        evidence_ids=claim.evidence_ids,
        confidence=claim.confidence,
        reachability_supported=reachability_supported,
    )


def verify_claim(claim: Claim | Mapping[str, Any], store: EvidenceStore) -> VerificationResult:
    """Verify one schema-valid claim against the immutable evidence index.

    Verification is intentionally conservative.  Existing evidence IDs are
    necessary for acceptance, and a positive reachability assertion additionally
    needs a graph path made from structured call/reference evidence.  Text in
    ``raw_value`` or ``normalized_value`` is never interpreted as a relation.
    """

    normalized = as_claim(claim)
    if not isinstance(store, EvidenceStore):
        raise TypeError("store must be an EvidenceStore")

    missing = [evidence_id for evidence_id in normalized.evidence_ids if store.get(evidence_id) is None]
    if missing:
        return _result(
            normalized,
            "rejected",
            ("evidence IDs do not exist: " + ", ".join(missing),),
        )

    cited_text = "\n".join(
        json.dumps(store.get(evidence_id).to_dict(), ensure_ascii=False, sort_keys=True).lower()
        for evidence_id in normalized.evidence_ids
    )
    exact_values = set(re.findall(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{128}\b|https?://[^\s`<>]+", normalized.explanation))
    unsupported_values = sorted(value for value in exact_values if value.lower().rstrip(".,);") not in cited_text)
    if unsupported_values:
        return _result(normalized, "rejected", ("exact value absent from cited evidence: " + ", ".join(unsupported_values[:10]),))

    reachability = normalized.reachability
    missing_path = [
        evidence_id
        for evidence_id in reachability.path_evidence_ids
        if store.get(evidence_id) is None
    ]
    if missing_path:
        return _result(
            normalized,
            "rejected",
            ("reachability path evidence IDs do not exist: " + ", ".join(missing_path),),
            reachability_supported=False,
        )

    if reachability.status == "reachable":
        supported = store.supports_reachability(
            reachability.entrypoints,
            reachability.path_evidence_ids,
            normalized.evidence_ids,
        )
        if not supported:
            reachability_reason = (
                "finding accepted; asserted reachability downgraded to unknown because no "
                "supporting structured call/reference relationship path exists"
            )
        else:
            reachability_reason = "all cited evidence and the structured reachability path passed deterministic checks"
    else:
        supported = None
        reachability_reason = "all cited evidence exists and deterministic checks passed"

    if normalized.unresolved:
        return _result(
            normalized,
            "unclear",
            tuple(dict.fromkeys(("claim is marked unresolved", reachability_reason))),
            reachability_supported=supported,
        )

    return _result(
        normalized,
        "accepted",
        (reachability_reason,),
        reachability_supported=supported,
    )


def verify_claims(
    claims: Iterable[Claim | Mapping[str, Any]],
    store: EvidenceStore,
    judgments: Iterable[Judgment | Mapping[str, Any]] | None = None,
) -> list[VerificationResult]:
    """Verify claims in stable input order, optionally applying judge verdicts."""

    normalized_claims: list[Claim] = []
    seen: set[str] = set()
    for raw_claim in claims:
        claim = as_claim(raw_claim)
        if claim.id in seen:
            raise SchemaError(f"duplicate claim ID: {claim.id}")
        seen.add(claim.id)
        normalized_claims.append(claim)

    results = [verify_claim(claim, store) for claim in normalized_claims]
    if judgments is not None:
        results = apply_judgments(results, judgments, store=store)
    return results


def _judgment_map(
    judgments: Iterable[Judgment | Mapping[str, Any]],
) -> dict[str, Judgment]:
    result: dict[str, Judgment] = {}
    for raw_judgment in judgments:
        judgment = as_judgment(raw_judgment)
        if judgment.claim_id in result:
            raise SchemaError(f"duplicate judgment for claim: {judgment.claim_id}")
        result[judgment.claim_id] = judgment
    return result


def _judgment_evidence_valid(judgment: Judgment, store: EvidenceStore | None) -> bool:
    if store is None:
        return True
    return all(store.get(evidence_id) is not None for evidence_id in judgment.cited_evidence_ids)


def apply_judgments(
    results: Iterable[VerificationResult | Mapping[str, Any]],
    judgments: Iterable[Judgment | Mapping[str, Any]],
    *,
    store: EvidenceStore | None = None,
) -> list[VerificationResult]:
    """Overlay optional independent judgments without resurrecting bad claims.

    A judge can downgrade a deterministically accepted claim to rejected or
    unclear.  It can never turn a deterministic rejection into acceptance.  A
    judge citation pointing at missing evidence is treated as unclear rather
    than trusted.
    """

    normalized_results = [as_verification_result(item) for item in results]
    judgment_by_claim = _judgment_map(judgments)
    unknown = sorted(set(judgment_by_claim) - {result.claim_id for result in normalized_results})
    if unknown:
        raise SchemaError("judgments cite unknown verification claims: " + ", ".join(unknown))
    output: list[VerificationResult] = []
    for result in normalized_results:
        judgment = judgment_by_claim.get(result.claim_id)
        if judgment is None:
            output.append(result)
            continue
        if not _judgment_evidence_valid(judgment, store):
            if result.status == "accepted":
                output.append(
                    VerificationResult(
                        claim_id=result.claim_id,
                        status="unclear",
                        reasons=result.reasons
                        + ("judge cited missing evidence",),
                        evidence_ids=result.evidence_ids,
                        confidence=result.confidence,
                        reachability_supported=result.reachability_supported,
                    )
                )
            else:
                output.append(result)
            continue
        if result.status != "accepted":
            # Deterministic rejection/uncertainty remains non-accepted even if
            # a judge mistakenly says supported.
            output.append(result)
            continue
        if judgment.verdict == "supported":
            output.append(result)
        elif judgment.verdict == "unsupported":
            output.append(
                VerificationResult(
                    claim_id=result.claim_id,
                    status="rejected",
                    reasons=result.reasons + ("independent judge verdict: unsupported",),
                    evidence_ids=result.evidence_ids,
                    confidence=result.confidence,
                    reachability_supported=result.reachability_supported,
                )
            )
        else:
            output.append(
                VerificationResult(
                    claim_id=result.claim_id,
                    status="unclear",
                    reasons=result.reasons + ("independent judge verdict: unclear",),
                    evidence_ids=result.evidence_ids,
                    confidence=result.confidence,
                    reachability_supported=result.reachability_supported,
                )
            )
    return output


def _looks_like_results(value: Any) -> bool:
    if isinstance(value, VerificationResult):
        return True
    if isinstance(value, Mapping):
        return "status" in value or "accepted" in value or "verification" in value
    return False


def build_score(
    claims: Iterable[Claim | Mapping[str, Any]] | Iterable[VerificationResult | Mapping[str, Any]] = (),
    verification_results: Iterable[VerificationResult | Mapping[str, Any]] | None = None,
    judgments: Iterable[Judgment | Mapping[str, Any]] = (),
    usage: Mapping[str, Any] | None = None,
) -> Score:
    """Construct a versioned score from deterministic results and judgments.

    For convenience, callers that already have only results may pass them as
    the first argument.  The normal controller call supplies claims followed by
    results so confidence can be calculated from the original claim values.
    """

    raw_claims = list(claims)
    if verification_results is None:
        if raw_claims and all(_looks_like_results(item) for item in raw_claims):
            raw_results = raw_claims
            normalized_claims: list[Claim] = []
        else:
            normalized_claims = [as_claim(item) for item in raw_claims]
            raw_results = []
    else:
        normalized_claims = [as_claim(item) for item in raw_claims]
        raw_results = list(verification_results)
    results = [as_verification_result(item) for item in raw_results]
    normalized_judgments = [as_judgment(item) for item in (judgments or ())]
    if normalized_claims and normalized_judgments:
        claim_by_id = {claim.id: claim for claim in normalized_claims}
        for judgment in normalized_judgments:
            claim = claim_by_id.get(judgment.claim_id)
            if claim is None:
                raise SchemaError(f"judgment cites unknown claim: {judgment.claim_id}")
            allowed = set(claim.evidence_ids) | set(claim.reachability.path_evidence_ids)
            if any(item not in allowed for item in judgment.cited_evidence_ids):
                raise SchemaError(f"judgment for {judgment.claim_id} cites evidence outside the claim")
    if normalized_judgments:
        results = apply_judgments(results, normalized_judgments)

    counts = {"accepted": 0, "rejected": 0, "unclear": 0}
    for result in results:
        counts[result.status] += 1

    confidence_by_id = {claim.id: claim.confidence for claim in normalized_claims}
    accepted_confidences = [
        confidence_by_id.get(result.claim_id, result.confidence)
        for result in results
        if result.status == "accepted"
    ]
    accepted_confidences = [
        float(value) for value in accepted_confidences if value is not None
    ]
    confidence = (
        sum(accepted_confidences) / len(accepted_confidences) if accepted_confidences else 0.0
    )
    return Score(
        accepted=counts["accepted"],
        rejected=counts["rejected"],
        unclear=counts["unclear"],
        verification_results=tuple(results),
        judgments=tuple(normalized_judgments),
        confidence=confidence,
        usage=dict(usage or {}),
    )


def verify_and_score(
    claims: Iterable[Claim | Mapping[str, Any]],
    store: EvidenceStore,
    *,
    judgments: Iterable[Judgment | Mapping[str, Any]] = (),
    usage: Mapping[str, Any] | None = None,
) -> Score:
    normalized_claims = [as_claim(item) for item in claims]
    normalized_judgments = [as_judgment(item) for item in (judgments or ())]
    results = verify_claims(normalized_claims, store, judgments=normalized_judgments)
    return build_score(normalized_claims, results, normalized_judgments, usage)


# Explicit aliases make the controller integration readable and keep the
# deterministic core discoverable for callers that use a noun-based name.
verify = verify_claim
score_claims = verify_and_score


__all__ = [
    "verify_claim",
    "verify_claims",
    "apply_judgments",
    "build_score",
    "verify_and_score",
    "verify",
    "score_claims",
]
