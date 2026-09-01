"""Small controller-facing CLI for the Python investigator boundary."""

from __future__ import annotations

import argparse
import html
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
from .pi_harness import PiHarnessError, PiInvestigator
from .report import render_report
from .runtime import StaticToolRuntime
from .verifier import verify_and_score


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
    if runtime is None and os.environ.get("JAQ_SANDBOX_CONTAINER"):
        runtime = StaticToolRuntime.from_environment(store)
    if runtime is None and client is None:
        raise RuntimeError("controller did not provide the Radare2 static sandbox runtime")
    investigator: Investigator | PiInvestigator | None = None
    try:
        if client is None:
            if runtime is None:
                raise RuntimeError("controller did not provide the Radare2 static sandbox runtime")
            investigator = PiInvestigator(store, runtime, output_dir)
        else:
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
        "assets.json": json.dumps({"schema_version": "1.0", "assets": claims.get("assets", [])}, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
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


def _render_operational(investigation: Mapping[str, Any]) -> str:
    safe = lambda value: html.escape(str(value), quote=True).replace("\n", " ")
    lines = ["\n## Operational assets\n"]
    assets = investigation.get("assets", [])
    lines.extend(
        f"- <code>{safe(item.get('type'))}</code> <code>{safe(item.get('value'))}</code> — {safe(item.get('role'))} (confidence {safe(item.get('confidence'))})"
        for item in assets
    )
    if not assets:
        lines.append("- None identified.")
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
        run_pipeline(args.evidence, args.output, task=args.task)
        return 0
    except (ModelError, PiHarnessError, ValueError, OSError, RuntimeError) as error:
        # Keep provider/sample data and credentials out of CLI logs. ModelError
        # messages are already normalized; local validation messages are bounded.
        print(f"jaq-investigator: {error}", file=sys.stderr)
        return 2


__all__ = ["build_parser", "main", "run_pipeline"]
