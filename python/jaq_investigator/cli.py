"""Small controller-facing CLI for the Python investigator boundary."""

from __future__ import annotations

import argparse
import html
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping

from .evidence import EvidenceStore as CanonicalEvidenceStore
from .investigator import Investigator, InvestigatorConfig
from .judge import Judge, JudgeConfig
from .model import ModelError
from .pi_harness import EvidenceOnlyRuntime, PiHarnessError, PiInvestigator
from .report import render_report
from .runtime import StaticToolRuntime
from .verifier import verify_and_score


_ASSET_CATEGORY_ORDER = (
    "credentials_and_tokens",
    "c2_and_infrastructure",
    "payloads",
    "execution_and_persistence",
    "contacts_and_financial",
    "configuration",
    "other",
)
_ASSET_CATEGORY_LABELS = {
    "credentials_and_tokens": "Credentials and tokens",
    "c2_and_infrastructure": "C2 and infrastructure",
    "payloads": "Payloads",
    "execution_and_persistence": "Execution and persistence",
    "contacts_and_financial": "Contacts and financial",
    "configuration": "Configuration",
    "other": "Other assets",
}
_ASSET_TYPE_CATEGORIES = {
    **dict.fromkeys({
        "api_key", "bearer_token", "oauth_credential", "username_password",
        "private_key", "certificate", "encryption_key", "database_connection",
    }, "credentials_and_tokens"),
    **dict.fromkeys({
        "c2_endpoint", "domain", "ip_address", "url", "download_location",
        "webhook", "cloud_bucket",
    }, "c2_and_infrastructure"),
    **dict.fromkeys({"payload_hash", "embedded_payload", "remote_payload"}, "payloads"),
    **dict.fromkeys({
        "command", "path", "mutex", "named_pipe", "registry_path",
        "service_name", "scheduled_task",
    }, "execution_and_persistence"),
    **dict.fromkeys({"email", "crypto_wallet"}, "contacts_and_financial"),
    "configuration": "configuration",
}


def _group_assets(assets: Any) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = {name: [] for name in _ASSET_CATEGORY_ORDER}
    if not isinstance(assets, list):
        return groups
    for raw in assets:
        if not isinstance(raw, Mapping):
            continue
        item = dict(raw)
        category = _ASSET_TYPE_CATEGORIES.get(str(item.get("type")), "other")
        groups[category].append(item)
    for records in groups.values():
        records.sort(key=lambda item: (str(item.get("type")), str(item.get("id"))))
    return groups


def _resolve_evidence_path(value: str) -> Path:
    path = Path(value)
    if path.is_dir():
        path = path / "observations.jsonl"
    return path


def _write_private(path: Path, content: str) -> None:
    # Publish within the controller-selected directory so a partial model
    # response cannot leave a plausible-looking output file behind.
    fd, temporary_name = tempfile.mkstemp(prefix=".jaq-output-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="jaq-investigator", description="Run JAQ's bounded static evidence investigator")
    parser.add_argument("--evidence", required=True, help="observations.jsonl path or evidence directory")
    parser.add_argument("--output", required=True, help="controller-selected output directory")
    parser.add_argument("--task", default=None, help="optional operational investigation request")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument(
        "--harvest-only", action="store_true",
        help="reuse research.json and observations.jsonl without rerunning static research",
    )
    modes.add_argument(
        "--finalize-research-only", action="store_true",
        help="create research.json from a failed run's persisted observations without rerunning analysis",
    )
    return parser


def run_pipeline(
    evidence_path: str | Path,
    output_dir: str | Path,
    *,
    client: Any | None = None,
    judge_client: Any | None = None,
    investigator_config: InvestigatorConfig | None = None,
    judge_config: JudgeConfig | None = None,
    task: str | None = None,
    tool_runtime: Any | None = None,
    harvest_only: bool = False,
) -> dict[str, Any]:
    """Run the complete claims → judge → score → report handoff.

    ``client`` and ``judge_client`` are dependency-injection points for
    credential-free tests. Production callers leave them unset; model
    selectors then come from the two role-specific environment variables.
    """

    evidence_path = _resolve_evidence_path(str(evidence_path))
    store = CanonicalEvidenceStore(evidence_path)
    output_dir = Path(output_dir)
    if output_dir.is_symlink() or (output_dir.exists() and not output_dir.is_dir()):
        raise ValueError("output must be a real directory, not a file or symlink")
    output_dir.mkdir(parents=True, exist_ok=True)
    for name in ("claims.json", "assets.json", "requests.json", "score.json", "report.md"):
        if (output_dir / name).exists():
            raise ValueError(f"refusing to overwrite existing {name}")
    runtime = tool_runtime
    if runtime is None and not harvest_only and os.environ.get("JAQ_SANDBOX_CONTAINER"):
        runtime = StaticToolRuntime.from_environment(store)
    if runtime is None and client is None and not harvest_only:
        raise RuntimeError("controller did not provide the Radare2 static sandbox runtime")
    investigator: Investigator | PiInvestigator | None = None
    try:
        if client is None:
            if harvest_only:
                research_path = output_dir / "research.json"
                try:
                    research_checkpoint = json.loads(research_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as error:
                    raise RuntimeError("harvest retry requires a valid research.json") from error
                investigator = PiInvestigator(store, EvidenceOnlyRuntime(), output_dir)
                claims = investigator.harvest(research_checkpoint)
            else:
                if runtime is None:
                    raise RuntimeError("controller did not provide the Radare2 static sandbox runtime")
                investigator = PiInvestigator(store, runtime, output_dir)
                claims = investigator.run(task)
        else:
            if harvest_only:
                raise ValueError("harvest_only is unavailable with the legacy injected model client")
            investigator = Investigator(
                store, model_client=client,
                config=investigator_config or InvestigatorConfig.from_env(),
                tool_runtime=runtime,
            )
            claims = investigator.run(task)
    finally:
        if runtime is not None:
            runtime.close()
    if investigator is None:  # pragma: no cover - construction failures re-raise
        raise RuntimeError("investigator was not initialized")

    claims_only = {"schema_version": claims["schema_version"], "claims": claims["claims"]}
    judge = Judge(
        store,
        model_client=judge_client,
        config=judge_config or JudgeConfig.from_env(),
    )
    judgments = judge.run(claims_only)
    usage = {"investigator": dict(investigator.last_run.usage if investigator.last_run else {})}
    if judge.last_usage:
        usage["judge"] = dict(judge.last_usage)
    score = verify_and_score(
        claims["claims"],
        store,
        judgments=judgments["judgments"],
        usage=usage,
    )

    contents = {
        "claims.json": json.dumps(claims_only, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        "assets.json": json.dumps({
            "schema_version": "1.0",
            "assets": claims.get("assets", []),
            "categories": _group_assets(claims.get("assets", [])),
        }, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        "requests.json": json.dumps({"schema_version": "1.0", "action_requests": claims.get("action_requests", [])}, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        "score.json": json.dumps(score.to_dict(), ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        "report.md": render_report(claims["claims"], score, store) + _render_operational(claims),
    }
    targets = [output_dir / name for name in contents]
    if any(path.exists() for path in targets):
        raise ValueError("investigator output files already exist; refusing to overwrite")
    published: list[Path] = []
    try:
        for name, content in contents.items():
            target = output_dir / name
            _write_private(target, content)
            published.append(target)
    except Exception:
        for target in published:
            try:
                target.unlink()
            except FileNotFoundError:
                pass
        raise
    return {"claims": claims, "judgments": judgments, "score": score.to_dict()}


def finalize_research_only(evidence_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    evidence_path = _resolve_evidence_path(str(evidence_path))
    output_dir = Path(output_dir)
    if output_dir.is_symlink() or not output_dir.is_dir():
        raise ValueError("output must be an existing real run directory")
    research_path = output_dir / "research.json"
    if research_path.exists():
        raise ValueError("research.json already exists; use --harvest-only")
    store = CanonicalEvidenceStore(evidence_path)
    investigator = PiInvestigator(store, EvidenceOnlyRuntime(), output_dir)
    checkpoint = investigator.recover_rejected_research_checkpoint()
    if checkpoint is None:
        checkpoint = investigator.finalize_persisted_research().submission
    investigator.write_research_checkpoint(research_path, checkpoint)
    return checkpoint


def _render_operational(investigation: Mapping[str, Any]) -> str:
    safe = lambda value: html.escape(str(value), quote=True).replace("\n", " ")
    sensitive = {"api_key", "bearer_token", "oauth_credential", "username_password", "private_key", "encryption_key", "database_connection"}
    def display(item: Mapping[str, Any]) -> str:
        value = str(item.get("value"))
        if item.get("type") in sensitive:
            return value + " sha256:" + hashlib.sha256(value.encode()).hexdigest()
        return value
    lines = ["\n## Operational assets\n"]
    assets = investigation.get("assets", [])
    groups = _group_assets(assets)
    for category in _ASSET_CATEGORY_ORDER:
        lines.append(f"### {_ASSET_CATEGORY_LABELS[category]}\n")
        records = groups[category]
        if records:
            lines.extend(
                f"- <code>{safe(item.get('type'))}</code> <code>{safe(display(item))}</code> — {safe(item.get('role'))} (confidence {safe(item.get('confidence'))})"
                for item in records
            )
        else:
            lines.append("- None identified.")
        lines.append("")
    lines.append("\n## Pending action requests\n")
    requests = investigation.get("action_requests", [])
    lines.extend(
        f"- <code>{safe(item.get('id'))}</code> <code>{safe(item.get('kind'))}</code> — {safe(item.get('reason'))} (<code>pending_authorization</code>)"
        for item in requests
    )
    if not requests:
        lines.append("- None.")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    # Go's process wrapper invokes ``python -m jaq_investigator --evidence``.
    # Accept an optional descriptive subcommand for humans without exposing a
    # model selector outside environment/configuration.
    args_list = list(sys.argv[1:] if argv is None else argv)
    if args_list and args_list[0] in {"investigate", "analyze"}:
        args_list = args_list[1:]
    parser = build_parser()
    args = parser.parse_args(args_list)
    try:
        # Reuse the canonical immutable loader so malformed observations and
        # schema-version drift fail before any provider call. The investigator
        # itself still sees only typed in-memory operations.
        if args.finalize_research_only:
            finalize_research_only(args.evidence, args.output)
        else:
            run_pipeline(args.evidence, args.output, task=args.task, harvest_only=args.harvest_only)
        return 0
    except (ModelError, PiHarnessError, ValueError, OSError, RuntimeError) as error:
        # Keep provider/sample data and credentials out of CLI logs. ModelError
        # messages are already normalized; local validation messages are bounded.
        print(f"jaq-investigator: {error}", file=sys.stderr)
        return 2


__all__ = ["build_parser", "finalize_research_only", "main", "run_pipeline"]
