"""JAQ's dependency-free evidence and claim core."""

from .evidence import EvidenceError, EvidenceStore
from .report import (
    render_dossier,
    render_markdown_report,
    render_report,
    sample_hashes_from_observations,
)
from .schemas import (
    PERSISTED_VERSION,
    SCHEMA_VERSION,
    Claim,
    Judgment,
    Observation,
    Reachability,
    RunManifest,
    SchemaError,
    Score,
    ValidationError,
    VerificationResult,
)
from .verifier import (
    apply_judgments,
    build_score,
    score_claims,
    verify,
    verify_and_score,
    verify_claim,
    verify_claims,
)


__all__ = [
    "PERSISTED_VERSION",
    "SCHEMA_VERSION",
    "SchemaError",
    "ValidationError",
    "Observation",
    "Reachability",
    "Claim",
    "Judgment",
    "VerificationResult",
    "Score",
    "RunManifest",
    "EvidenceError",
    "EvidenceStore",
    "verify_claim",
    "verify_claims",
    "apply_judgments",
    "build_score",
    "verify_and_score",
    "verify",
    "score_claims",
    "render_report",
    "render_dossier",
    "render_markdown_report",
    "sample_hashes_from_observations",
]
