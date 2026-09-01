"""Stable, evidence-backed Markdown dossier rendering."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import html
import json
import re
from typing import Any

from .evidence import EvidenceStore
from .schemas import Claim, Observation, Score, VerificationResult, as_claim


_HASH_RE = re.compile(r"^(?:sha256|sha-256|sha1|sha-1|md5)?\s*[:=]?\s*([0-9a-fA-F]{32,128})$")
_HASH_KEYS = {"hash", "sha256", "sha-256", "sha1", "sha-1", "md5", "sample_hash"}


def _inline(value: Any) -> str:
    """HTML-escape a single Markdown line, including hostile evidence text."""

    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    escaped = html.escape(value, quote=True)
    # Keep untrusted text on one Markdown line so it cannot inject a heading,
    # list item, or fenced block.  The text remains visibly delimited in HTML.
    return escaped.replace("\r", "&#13;").replace("\n", "&#10;").replace("\t", "&#9;")


def _code(value: Any) -> str:
    return f"<code>{_inline(value)}</code>"


def _observation_values(observation: Observation) -> list[tuple[str, str]]:
    """Return hash candidates from structured, normalized observation data."""

    candidates: list[tuple[str, Any]] = []

    def visit(value: Any, key_hint: str = "") -> None:
        if isinstance(value, Mapping):
            for key, nested in value.items():
                if isinstance(key, str) and (key.casefold() in _HASH_KEYS or "hash" in key.casefold()):
                    candidates.append((key, nested))
                # A hash may be nested under sample/file metadata.
                if isinstance(nested, (Mapping, list, tuple)):
                    visit(nested, key)
        elif isinstance(value, (list, tuple)):
            for nested in value:
                if isinstance(nested, (Mapping, list, tuple)):
                    visit(nested, key_hint)

    visit(observation.metadata)
    visit(observation.normalized_value)
    observation_type = observation.type.casefold()
    if "hash" in observation_type or observation_type.startswith(("sha", "md5", "digest")):
        candidates.append((observation.type, observation.normalized_value))

    found: list[tuple[str, str]] = []
    for label, value in candidates:
        if isinstance(value, str):
            match = _HASH_RE.match(value.strip())
            normalized = match.group(1) if match else value.strip()
        else:
            continue
        if not normalized:
            continue
        # Labels are derived from controller-provided field names, while the
        # value is still escaped at render time.  Keep arbitrary hash-shaped
        # values rather than silently dropping a valid nonstandard digest.
        found.append((label, normalized))
    return found


def sample_hashes_from_observations(
    observations: Iterable[Observation | Mapping[str, Any]] | EvidenceStore,
) -> list[tuple[str, str]]:
    """Collect deterministic hash observations in stable order."""

    if isinstance(observations, EvidenceStore):
        items = observations.observations
    else:
        items = [item if isinstance(item, Observation) else Observation.from_dict(item) for item in observations]
    values: set[tuple[str, str]] = set()
    for observation in items:
        values.update(_observation_values(observation))
    return sorted(values, key=lambda item: (item[0].casefold(), item[0], item[1]))


def _normalize_observations(
    observations: Iterable[Observation | Mapping[str, Any]] | EvidenceStore | None,
) -> list[Observation]:
    if observations is None:
        return []
    if isinstance(observations, EvidenceStore):
        return observations.observations
    return [item if isinstance(item, Observation) else Observation.from_dict(item) for item in observations]


def _normalize_claims(claims: Iterable[Claim | Mapping[str, Any]] | None) -> list[Claim]:
    if claims is None:
        return []
    return [item if isinstance(item, Claim) else as_claim(item) for item in claims]


def _normalize_score(score: Score | Mapping[str, Any] | None) -> Score | None:
    if score is None:
        return None
    return score if isinstance(score, Score) else Score.from_dict(score)


def _default_status(claim: Claim) -> str:
    # Claims are never accepted merely because no verifier result was supplied.
    return "unclear"


def render_report(
    claims: Iterable[Claim | Mapping[str, Any]] | None = None,
    score: Score | Mapping[str, Any] | None = None,
    observations: Iterable[Observation | Mapping[str, Any]] | EvidenceStore | None = None,
    limitations: Iterable[str] | None = None,
    sample_hashes: Mapping[str, Any] | Iterable[tuple[str, Any]] | None = None,
) -> str:
    """Render a stable Markdown dossier.

    Only structured observation fields are rendered.  Every model- or
    sample-derived value is HTML-escaped and line-delimited so binary strings,
    comments, and decompiler text cannot alter the report's Markdown shape.
    """

    normalized_claims = sorted(_normalize_claims(claims), key=lambda item: item.id)
    normalized_score = _normalize_score(score)
    normalized_observations = _normalize_observations(observations)
    observation_by_id = {observation.id: observation for observation in normalized_observations}

    status_by_id: dict[str, str] = {}
    result_by_id: dict[str, VerificationResult] = {}
    if normalized_score is not None:
        for result in normalized_score.verification_results:
            status_by_id[result.claim_id] = result.status
            result_by_id[result.claim_id] = result

    accepted: list[Claim] = []
    rejected_or_unclear: list[tuple[Claim, str]] = []
    for claim in normalized_claims:
        status = status_by_id.get(claim.id, _default_status(claim))
        if status == "accepted":
            accepted.append(claim)
        else:
            rejected_or_unclear.append((claim, status))

    if sample_hashes is None:
        hash_values = sample_hashes_from_observations(normalized_observations)
    elif isinstance(sample_hashes, Mapping):
        hash_values = sorted(
            [(str(key), str(value)) for key, value in sample_hashes.items()],
            key=lambda item: (item[0].casefold(), item[0], item[1]),
        )
    else:
        hash_values = sorted(
            [(str(key), str(value)) for key, value in sample_hashes],
            key=lambda item: (item[0].casefold(), item[0], item[1]),
        )

    default_limitations = (
        "Static evidence only; JAQ did not launch the supplied sample.",
        "Agent-authored helper commands ran only inside an offline disposable static sandbox.",
        "Dynamic analysis, debugging, and runtime unpacking were not attempted.",
        "Reachability is accepted only when structured call/reference evidence supplies a path.",
        "Global novelty and corpus correlation are outside this milestone.",
    )
    if limitations is None:
        limitation_values = list(default_limitations)
    else:
        limitation_values = list(default_limitations) + [str(item) for item in limitations]
    limitation_values = sorted(dict.fromkeys(item for item in limitation_values if item.strip()), key=str.casefold)

    lines: list[str] = ["# JAQ Intelligence Dossier", ""]
    lines.extend(["## Summary", ""])
    if normalized_score is None:
        lines.append(f"- Accepted claims: {len(accepted)}")
        lines.append(f"- Rejected claims: {sum(status == 'rejected' for _, status in rejected_or_unclear)}")
        lines.append(f"- Unclear claims: {sum(status == 'unclear' for _, status in rejected_or_unclear)}")
    else:
        lines.append(f"- Accepted claims: {normalized_score.accepted}")
        lines.append(f"- Rejected claims: {normalized_score.rejected}")
        lines.append(f"- Unclear claims: {normalized_score.unclear}")
        lines.append(f"- Confidence: {_code(f'{normalized_score.confidence:.3f}')}")
    lines.append("")

    lines.extend(["## Sample hashes", ""])
    if hash_values:
        for label, value in hash_values:
            lines.append(f"- {_code(label)}: {_code(value)}")
    else:
        lines.append("- No sample hash observations were recorded.")
    lines.append("")

    lines.extend(["## Accepted claims", ""])
    if not accepted:
        lines.append("No claims were accepted.")
    for claim in accepted:
        lines.append(f"### {_code(claim.id)} — {_code(claim.classification)}")
        lines.append("")
        lines.append(f"- Explanation: {_code(claim.explanation)}")
        lines.append(f"- Confidence: {_code(f'{claim.confidence:.3f}')}")
        lines.append(
            "- Evidence IDs: "
            + ", ".join(_code(evidence_id) for evidence_id in claim.evidence_ids)
        )
        lines.append(f"- Asset role: {_code(claim.asset_role) if claim.asset_role is not None else 'null'}")
        reachability = claim.reachability
        lines.append(f"- Reachability: {_code(reachability.status)}")
        if reachability.entrypoints:
            lines.append(
                "- Entrypoints: "
                + ", ".join(_code(item) for item in reachability.entrypoints)
            )
        if reachability.path_evidence_ids:
            lines.append(
                "- Path evidence IDs: "
                + ", ".join(_code(item) for item in reachability.path_evidence_ids)
            )
        details = [observation_by_id[item] for item in claim.evidence_ids if item in observation_by_id]
        for observation in sorted(details, key=lambda item: item.id):
            lines.append(
                f"- Evidence {_code(observation.id)} ({_code(observation.type)}): "
                f"normalized value {_code(observation.normalized_value)}"
            )
        lines.append("")

    lines.extend(["## Rejected and unclear claims", ""])
    if not rejected_or_unclear:
        lines.append("None.")
    for claim, status in rejected_or_unclear:
        result = result_by_id.get(claim.id)
        lines.append(f"### {_code(claim.id)} — {_code(status)}")
        lines.append("")
        lines.append(f"- Classification: {_code(claim.classification)}")
        lines.append(f"- Explanation: {_code(claim.explanation)}")
        lines.append(
            "- Evidence IDs: "
            + ", ".join(_code(evidence_id) for evidence_id in claim.evidence_ids)
        )
        if result is not None and result.reasons:
            lines.append("- Verification: " + "; ".join(_code(reason) for reason in result.reasons))
        lines.append("")

    lines.extend(["## Limitations", ""])
    for limitation in limitation_values:
        lines.append(f"- {_code(limitation)}")
    lines.append("")
    return "\n".join(lines)


render_dossier = render_report
render_markdown_report = render_report


__all__ = [
    "sample_hashes_from_observations",
    "render_report",
    "render_dossier",
    "render_markdown_report",
]
