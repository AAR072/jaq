"""Host-side Pi SDK investigator with a Python JAQ tool broker."""

from __future__ import annotations

from dataclasses import dataclass, replace
import json
import math
import os
import re
from pathlib import Path, PureWindowsPath
import signal
import subprocess
import sys
import tempfile
import threading
from typing import Any, Mapping, Sequence

from .investigator import Investigator, InvestigatorConfig, InvestigatorRun, validate_claims
from .prompts import (
    HARVESTER_SYSTEM_PROMPT,
    INVESTIGATION_SCHEMA,
    INVESTIGATOR_SYSTEM_PROMPT,
    INVESTIGATOR_TOOLS,
    RESEARCH_FINALIZER_SYSTEM_PROMPT,
    RESEARCH_SCHEMA,
    build_investigator_messages,
)


MAX_FRAME_BYTES = 8 << 20
MAX_STDERR_BYTES = 64 << 10
MAX_HARVEST_EVIDENCE_BYTES = 48_000
MAX_HARVEST_EVIDENCE_ITEM_BYTES = 4_000
MAX_RESEARCH_FINALIZER_EVIDENCE_BYTES = 180_000
MAX_RESEARCH_FINALIZER_ITEM_BYTES = 1_600
_PROGRESS_PHASES = {"research", "research_finalize", "harvest"}
_PROGRESS_EVENTS = {
    "phase_started", "model_progress", "tool_started", "finalizing",
    "submission_attempt", "submission_rejected", "submission_accepted",
    "phase_completed",
}


def _emit_progress(frame: Mapping[str, Any]) -> None:
    if not set(frame).issubset({
        "type", "phase", "event", "provider_calls", "tool_calls",
        "cost_usd", "tool", "attempt",
    }):
        raise PiHarnessError("Pi progress frame has unsupported fields")
    phase = frame.get("phase")
    event = frame.get("event")
    provider_calls = frame.get("provider_calls")
    tool_calls = frame.get("tool_calls")
    cost = frame.get("cost_usd")
    if not isinstance(phase, str) or not isinstance(event, str) or phase not in _PROGRESS_PHASES or event not in _PROGRESS_EVENTS:
        raise PiHarnessError("Pi progress frame is invalid")
    if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in (provider_calls, tool_calls)):
        raise PiHarnessError("Pi progress counters are invalid")
    if (
        not isinstance(cost, (int, float)) or isinstance(cost, bool)
        or (isinstance(cost, float) and not math.isfinite(cost))
        or not 0 <= cost <= 1000
    ):
        raise PiHarnessError("Pi progress cost is invalid")
    prefix = f"[{phase}]"
    if event == "phase_started":
        message = f"{prefix} started"
    elif event == "model_progress":
        message = f"{prefix} model calls={provider_calls} tools={tool_calls} cost=${float(cost):.5f}"
    elif event == "tool_started":
        tool = frame.get("tool")
        if not isinstance(tool, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,99}", tool):
            raise PiHarnessError("Pi progress tool name is invalid")
        message = f"{prefix} tool #{tool_calls}: {tool}"
    elif event == "finalizing":
        message = f"{prefix} preparing checkpoint at cost=${float(cost):.5f}"
    elif event == "submission_attempt":
        attempt = frame.get("attempt")
        if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
            raise PiHarnessError("Pi progress attempt is invalid")
        message = f"{prefix} submission attempt #{attempt}"
    elif event == "submission_rejected":
        message = f"{prefix} submission rejected; correcting"
    elif event == "submission_accepted":
        message = f"{prefix} submission accepted"
    else:
        message = f"{prefix} completed calls={provider_calls} tools={tool_calls} cost=${float(cost):.5f}"
    transport_prefix = "JAQ_PROGRESS " if os.environ.get("JAQ_PROGRESS_TRANSPORT") == "1" else "jaq: "
    print(transport_prefix + message, file=sys.stderr, flush=True)


class PiHarnessError(RuntimeError):
    """The host-side Pi session failed or violated its protocol."""


class PiHarnessBudgetError(PiHarnessError):
    """Pi stopped before another provider/tool call because a budget was exhausted."""


class EvidenceOnlyRuntime:
    """Runtime boundary for harvest: no static or arbitrary-command tools."""

    def model_tools(self) -> tuple[()]:
        return ()

    def execute(self, name: str, arguments: Mapping[str, Any]) -> Any:
        raise PiHarnessError(f"runtime tool {name!r} is unavailable during harvest")

    def close(self) -> None:
        return None


def _positive_int_env(name: str, default: int, maximum: int) -> int:
    raw = os.environ.get(name)
    try:
        value = default if raw is None else int(raw)
    except ValueError as exc:
        raise PiHarnessError(f"{name} must be an integer") from exc
    if not 1 <= value <= maximum:
        raise PiHarnessError(f"{name} must be between 1 and {maximum}")
    return value


def _optional_positive_int_env(name: str, maximum: int) -> int | None:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return None
    try:
        value = int(raw)
    except ValueError as exc:
        raise PiHarnessError(f"{name} must be an integer") from exc
    if not 1 <= value <= maximum:
        raise PiHarnessError(f"{name} must be between 1 and {maximum}")
    return value


def _positive_float_env(name: str, default: float, maximum: float) -> float:
    raw = os.environ.get(name)
    try:
        value = default if raw is None else float(raw)
    except ValueError as exc:
        raise PiHarnessError(f"{name} must be a number") from exc
    if not 0 < value <= maximum:
        raise PiHarnessError(f"{name} must be between 0 and {maximum}")
    return value


@dataclass(frozen=True)
class PiHarnessConfig:
    model: str
    node: str
    script: Path
    session_dir: Path
    thinking_level: str
    max_model_calls: int | None
    max_tool_calls: int | None
    max_total_tokens: int | None
    max_cost_usd: float
    max_output_tokens: int
    tool_preview_chars: int
    max_context_tokens: int
    keep_recent_tokens: int

    @classmethod
    def from_env(cls, output_dir: Path) -> "PiHarnessConfig":
        model = os.environ.get("JAQ_INVESTIGATOR_MODEL", "").strip()
        if not model or "/" not in model:
            raise PiHarnessError("JAQ_INVESTIGATOR_MODEL must be a provider/model string")
        project_root = Path(os.environ.get("JAQ_PROJECT_ROOT", Path(__file__).resolve().parents[2]))
        script = Path(os.environ.get("JAQ_PI_HARNESS", project_root / "agent" / "pi_harness.mjs"))
        if not script.is_absolute() or not script.is_file():
            raise PiHarnessError("JAQ Pi harness script is unavailable")
        thinking = os.environ.get("JAQ_INVESTIGATOR_THINKING", "high").strip().lower()
        if thinking not in {"off", "minimal", "low", "medium", "high", "xhigh", "max"}:
            raise PiHarnessError("JAQ_INVESTIGATOR_THINKING is invalid")
        return cls(
            model=model,
            node=os.environ.get("JAQ_NODE", "node"),
            script=script,
            session_dir=output_dir / "model-session",
            thinking_level=thinking,
            max_model_calls=_optional_positive_int_env("JAQ_MAX_MODEL_CALLS", 100_000),
            max_tool_calls=_optional_positive_int_env("JAQ_MAX_TOOL_CALLS", 1_000_000),
            max_total_tokens=_optional_positive_int_env("JAQ_MAX_TOTAL_TOKENS", 100_000_000),
            max_cost_usd=_positive_float_env("JAQ_MAX_COST_USD", 0.10, 1000.0),
            max_output_tokens=_positive_int_env("JAQ_MAX_OUTPUT_TOKENS", 32_768, 100_000),
            tool_preview_chars=_positive_int_env("JAQ_TOOL_PREVIEW_CHARS", 2_400, 64_000),
            max_context_tokens=_positive_int_env("JAQ_MAX_CONTEXT_TOKENS", 64_000, 2_000_000),
            keep_recent_tokens=_positive_int_env("JAQ_KEEP_RECENT_TOKENS", 12_000, 500_000),
        )

    def init_frame(
        self,
        *,
        mode: str,
        tool_definitions: Sequence[Mapping[str, Any]],
        output_schema: Mapping[str, Any],
        system_prompt: str,
        task: str,
    ) -> dict[str, Any]:
        return {
            "type": "init",
            "mode": mode,
            "model": self.model,
            "thinking_level": self.thinking_level,
            "system_prompt": system_prompt,
            "task": task,
            "session_dir": str(self.session_dir),
            "tool_definitions": [dict(item) for item in tool_definitions],
            "output_schema": dict(output_schema),
            "budgets": {
                "max_model_calls": self.max_model_calls,
                "max_tool_calls": self.max_tool_calls,
                "max_total_tokens": self.max_total_tokens,
                "max_cost_usd": self.max_cost_usd,
                "max_output_tokens": self.max_output_tokens,
                "tool_preview_chars": self.tool_preview_chars,
            },
            "compaction": {
                "max_context_tokens": self.max_context_tokens,
                "keep_recent_tokens": self.keep_recent_tokens,
            },
        }

    def for_phase(self, phase: str) -> "PiHarnessConfig":
        if phase == "research":
            return replace(self, session_dir=self.session_dir / "research")
        if phase == "research_finalize":
            return replace(
                self,
                session_dir=self.session_dir / "research-finalize",
                thinking_level="off",
                max_model_calls=_positive_int_env("JAQ_RESEARCH_FINALIZE_MAX_MODEL_CALLS", 5, 100),
                max_tool_calls=_positive_int_env("JAQ_RESEARCH_FINALIZE_MAX_TOOL_CALLS", 4, 100),
                max_total_tokens=_positive_int_env("JAQ_RESEARCH_FINALIZE_MAX_TOTAL_TOKENS", 180_000, 100_000_000),
                max_cost_usd=_positive_float_env("JAQ_RESEARCH_FINALIZE_MAX_COST_USD", 0.02, 1000.0),
            )
        if phase != "harvest":
            raise PiHarnessError("unknown Pi harness phase")
        model = os.environ.get("JAQ_HARVESTER_MODEL", self.model).strip()
        if not model or "/" not in model:
            raise PiHarnessError("JAQ_HARVESTER_MODEL must be a provider/model string")
        thinking = os.environ.get("JAQ_HARVESTER_THINKING", "off").strip().lower()
        if thinking not in {"off", "minimal", "low", "medium", "high", "xhigh", "max"}:
            raise PiHarnessError("JAQ_HARVESTER_THINKING is invalid")
        return replace(
            self,
            model=model,
            session_dir=self.session_dir / "harvest",
            thinking_level=thinking,
            max_model_calls=_positive_int_env("JAQ_HARVEST_MAX_MODEL_CALLS", 5, 100),
            max_tool_calls=_positive_int_env("JAQ_HARVEST_MAX_TOOL_CALLS", 16, 1000),
            max_total_tokens=_positive_int_env("JAQ_HARVEST_MAX_TOTAL_TOKENS", 180_000, 100_000_000),
            max_cost_usd=_positive_float_env("JAQ_HARVEST_MAX_COST_USD", 0.03, 1000.0),
            max_output_tokens=_positive_int_env("JAQ_HARVEST_MAX_OUTPUT_TOKENS", 32_768, 100_000),
        )


class _BoundedStderr:
    def __init__(self) -> None:
        self.data = bytearray()
        self.truncated = False
        self.lock = threading.Lock()

    def drain(self, stream: Any) -> None:
        while True:
            chunk = stream.read(4096)
            if not chunk:
                return
            if isinstance(chunk, str):
                chunk = chunk.encode("utf-8", errors="replace")
            with self.lock:
                remaining = MAX_STDERR_BYTES - len(self.data)
                if remaining > 0:
                    self.data.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    self.truncated = True

    def text(self) -> str:
        with self.lock:
            value = bytes(self.data).decode("utf-8", errors="replace")
        return " ".join(value.split())[:MAX_STDERR_BYTES]


class PiToolBroker:
    """Expose the existing validated evidence/runtime operations to Pi."""

    def __init__(self, store: Any, runtime: Any) -> None:
        self.store = store
        self.runtime = runtime
        self.legacy = Investigator(
            store,
            model_client=object(),
            config=InvestigatorConfig(model="pi/host", max_tool_output_chars=4_000_000),
            tool_runtime=runtime,
        )

    def definitions(self, mode: str) -> list[dict[str, Any]]:
        if mode not in {"research", "research_finalize", "harvest"}:
            raise PiHarnessError("unknown Pi tool mode")
        definitions: list[dict[str, Any]] = []
        seen: set[str] = set()
        source_tools = [*INVESTIGATOR_TOOLS, *self.runtime.model_tools()] if mode == "research" else []
        for item in source_tools:
            function = item.get("function") if isinstance(item, Mapping) else None
            if not isinstance(function, Mapping):
                raise PiHarnessError("JAQ tool catalog contains an invalid definition")
            name = function.get("name")
            if not isinstance(name, str) or name in seen:
                raise PiHarnessError("JAQ tool catalog contains an invalid or duplicate name")
            seen.add(name)
            definitions.append({
                "name": name,
                "description": str(function.get("description", "")),
                "parameters": dict(function.get("parameters", {})),
            })
        return definitions

    @staticmethod
    def _leaf_values(value: Any) -> list[Any]:
        if isinstance(value, Mapping):
            result: list[Any] = []
            for item in value.values(): result.extend(PiToolBroker._leaf_values(item))
            return result
        if isinstance(value, (list, tuple)):
            result = []
            for item in value: result.extend(PiToolBroker._leaf_values(item))
            return result
        return [value]

    def execute(self, name: str, arguments: Any) -> Any:
        if not isinstance(name, str) or not isinstance(arguments, Mapping):
            raise PiHarnessError("Pi supplied an invalid tool request")
        return self.legacy._execute_tool(name, dict(arguments))

    def validate_research(self, payload: Any) -> dict[str, Any]:
        expected = {
            "schema_version", "research_complete", "summary",
            "important_evidence_ids", "unresolved_questions", "coverage",
        }
        if not isinstance(payload, Mapping) or set(payload) != expected:
            raise PiHarnessError("research checkpoint has missing or unsupported fields")
        if payload.get("schema_version") != "1.0" or payload.get("research_complete") is not True:
            raise PiHarnessError("research checkpoint is not complete or has an unsupported version")
        summary = payload.get("summary")
        evidence_ids = payload.get("important_evidence_ids")
        unresolved = payload.get("unresolved_questions")
        coverage = payload.get("coverage")
        if not isinstance(summary, str) or not summary.strip() or len(summary) > 16_000:
            raise PiHarnessError("research summary must be nonempty and at most 16000 characters")
        if not isinstance(evidence_ids, list) or len(evidence_ids) > 200 or len(set(evidence_ids)) != len(evidence_ids):
            raise PiHarnessError("research evidence IDs must be a bounded unique array")
        missing_evidence = [
            str(item) for item in evidence_ids
            if not isinstance(item, str) or self.store.get(item) is None
        ]
        if missing_evidence:
            raise PiHarnessError(
                "research checkpoint cites missing evidence IDs: " + ", ".join(missing_evidence[:10])
            )
        if not isinstance(unresolved, list) or len(unresolved) > 100 or any(
            not isinstance(item, str) or not item.strip() or len(item) > 1000 for item in unresolved
        ):
            raise PiHarnessError("research unresolved questions must be a bounded string array")
        canonical_coverage = self._validate_research_coverage(coverage)
        covered_ids = {
            evidence_id
            for section in (
                canonical_coverage["application_entrypoints"],
                canonical_coverage["analyzed_functions"],
                canonical_coverage["deobfuscation_attempts"],
                canonical_coverage["recovered_artifacts"],
            )
            for record in section
            for evidence_id in record["evidence_ids"]
        }
        covered_ids.update(canonical_coverage["call_graph_evidence_ids"])
        if not covered_ids.issubset(set(evidence_ids)):
            raise PiHarnessError("research important_evidence_ids must include all coverage evidence")
        return {
            "schema_version": "1.0",
            "research_complete": True,
            "summary": summary.strip(),
            "important_evidence_ids": list(evidence_ids),
            "unresolved_questions": [item.strip() for item in unresolved],
            "coverage": canonical_coverage,
        }

    def _validate_research_coverage(self, coverage: Any) -> dict[str, Any]:
        expected = {
            "application_entrypoints", "analyzed_functions",
            "call_graph_evidence_ids", "deobfuscation_attempts",
            "recovered_artifacts",
        }
        allowed = expected | {"analysis_evidence_ids"}
        if not isinstance(coverage, Mapping) or not expected.issubset(coverage) or not set(coverage).issubset(allowed):
            raise PiHarnessError("research coverage has missing or unsupported fields")

        def records(name: str, fields: set[str], minimum: int, maximum: int) -> list[dict[str, Any]]:
            value = coverage.get(name)
            if not isinstance(value, list) or not minimum <= len(value) <= maximum:
                raise PiHarnessError(f"research coverage {name} must contain {minimum}..{maximum} records")
            result: list[dict[str, Any]] = []
            for record in value:
                if not isinstance(record, Mapping) or set(record) != fields:
                    raise PiHarnessError(f"research coverage {name} record is malformed")
                evidence_ids = record.get("evidence_ids")
                if not isinstance(evidence_ids, list) or not evidence_ids or any(
                    not isinstance(item, str) or self.store.get(item) is None for item in evidence_ids
                ):
                    raise PiHarnessError(f"research coverage {name} cites missing evidence")
                if any(
                    not isinstance(record.get(field), str) or not record[field].strip()
                    for field in fields - {"evidence_ids"}
                ):
                    raise PiHarnessError(f"research coverage {name} has an empty field")
                result.append(dict(record))
            return result

        entrypoints = records("application_entrypoints", {"name", "address", "evidence_ids"}, 1, 20)
        functions = records("analyzed_functions", {"name", "address", "purpose", "evidence_ids"}, 3, 100)
        attempts = records(
            "deobfuscation_attempts", {"technique", "status", "outcome", "evidence_ids"}, 1, 50
        )
        if any(item["status"] not in {"recovered", "partial", "failed", "not_needed"} for item in attempts):
            raise PiHarnessError("research coverage has an invalid deobfuscation status")
        artifacts = records("recovered_artifacts", {"description", "path", "evidence_ids"}, 0, 50)
        call_ids = coverage.get("call_graph_evidence_ids")
        if not isinstance(call_ids, list) or not 1 <= len(call_ids) <= 100 or any(
            not isinstance(item, str) or self.store.get(item) is None for item in call_ids
        ):
            raise PiHarnessError("research coverage call_graph_evidence_ids are invalid")

        events: list[tuple[str, str, Mapping[str, Any], str]] = []
        result_ids: set[str] = set()
        for observation in self.store.observations:
            provenance = observation.provenance
            metadata = observation.metadata
            if not isinstance(provenance, Mapping) or provenance.get("stage") != "agent-tool-result":
                continue
            tool_name = metadata.get("tool_name") if isinstance(metadata, Mapping) else None
            status = metadata.get("status") if isinstance(metadata, Mapping) else None
            parents = provenance.get("parent_observation_ids")
            if not isinstance(tool_name, str) or not isinstance(status, str) or not isinstance(parents, list) or len(parents) != 1:
                continue
            request = self.store.get(parents[0])
            raw_request = request.raw_value if request is not None else None
            request_provenance = request.provenance if request is not None else None
            if (
                not isinstance(request_provenance, Mapping)
                or request_provenance.get("stage") != "agent-tool-request"
                or not isinstance(raw_request, Mapping)
                or raw_request.get("tool") != tool_name
            ):
                continue
            arguments = raw_request.get("arguments") if isinstance(raw_request, Mapping) else None
            if not isinstance(arguments, Mapping):
                arguments = {}
            events.append((tool_name, status, arguments, observation.id))
            result_ids.add(observation.id)

        missing: list[str] = []
        analysis_result_ids = {
            observation_id for name, status, _, observation_id in events
            if name == "r2_analyze" and status == "ok"
        }
        analysis_result_ids.update({
            observation_id for name, status, arguments, observation_id in events
            if name == "run_static_command" and status == "ok"
            and isinstance(arguments.get("command"), str)
            and re.search(r"(?:^|[;&|]\s*|\b)r2\b[^\n]*(?:\s-A\b|\s-AAA?\b)", arguments["command"])
        })
        if not analysis_result_ids:
            missing.append("a successful r2_analyze or equivalent r2 -A result")
        code_tools = {"r2_decompile_function", "r2_disassemble_function", "r2_disassemble"}
        code_results_by_address: dict[str, set[str]] = {}
        for name, status, arguments, observation_id in events:
            if name not in code_tools or status != "ok" or not arguments.get("address"):
                continue
            code_results_by_address.setdefault(str(arguments["address"]).lower(), set()).add(observation_id)
        def code_record_matches(record: Mapping[str, Any]) -> bool:
            address = str(record["address"]).lower()
            cited = set(record["evidence_ids"])
            if code_results_by_address.get(address, set()).intersection(cited):
                return True
            for name, status, arguments, observation_id in events:
                if name != "run_static_command" or status != "ok" or observation_id not in cited:
                    continue
                command = arguments.get("command")
                if (
                    isinstance(command, str)
                    and (
                        (
                            address in command.lower()
                            and re.search(r"\b(?:pdr|pdf|pd|objdump|monodis|ildasm)\b", command, re.IGNORECASE)
                        )
                        or re.search(
                            r"(?:/work/cil(?:/|\b)|\.il\b|cil2?\.py\b|dumprun\.py\b|monodis\b|ildasm\b)",
                            command,
                            re.IGNORECASE,
                        )
                    )
                ):
                    return True
            return False

        if sum(1 for item in functions if code_record_matches(item)) < 3:
            missing.append("at least three analyzed_functions addresses backed by code-analysis tool results")
        if not any(code_record_matches(item) for item in entrypoints):
            missing.append("an application entrypoint backed by disassembly/decompilation")
        call_tools = {"r2_xrefs_to", "r2_list_functions_tree"}
        call_result_ids = {
            observation_id for name, status, _, observation_id in events
            if name in call_tools and status == "ok"
        }
        call_result_ids.update({
            observation_id for name, status, arguments, observation_id in events
            if name == "run_static_command" and status == "ok"
            and isinstance(arguments.get("command"), str)
            and re.search(
                r"(?:\b(?:pdr|pdf|axt|agc|objdump|monodis|ildasm)\b|/work/cil(?:/|\b)|\.il\b|cil2?\.py\b|dumprun\.py\b)",
                arguments["command"],
                re.IGNORECASE,
            )
        })
        if not call_result_ids.intersection(call_ids):
            missing.append("successful call-tree or cross-reference analysis")
        if any(not set(record["evidence_ids"]).intersection(result_ids) for record in attempts):
            missing.append("a deobfuscation assessment backed by a persisted tool result")
        if missing:
            raise PiHarnessError("research is incomplete: " + "; ".join(missing))
        return {
            "application_entrypoints": entrypoints,
            "analyzed_functions": functions,
            "call_graph_evidence_ids": list(call_ids),
            "deobfuscation_attempts": attempts,
            "recovered_artifacts": artifacts,
        }

    def validate_claims(self, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, Mapping) or set(payload) != {"schema_version", "claims", "assets", "action_requests"}:
            raise PiHarnessError("investigation must contain schema_version, claims, assets, and action_requests")
        canonical_claims = validate_claims(
            {"schema_version": payload.get("schema_version"), "claims": payload.get("claims")},
            evidence_store=self.store,
        )
        assets = self._validate_records(payload.get("assets"), "asset", 500)
        requests = self._validate_records(payload.get("action_requests"), "request", 100, requests=True)
        covered: set[tuple[str, str]] = set()
        verified_assets: list[dict[str, Any]] = []
        for asset in assets:
            normalized = asset.get("normalized_value")
            if asset.get("type") == "payload_hash" and isinstance(normalized, Mapping) and len(normalized) == 1:
                normalized = next(iter(normalized.values()))
            if asset.get("type") == "registry_path" and isinstance(normalized, str):
                normalized = normalized.lower()
                if normalized.startswith(("software\\", "system\\")):
                    normalized = "hklm\\" + normalized
            key = (str(asset.get("type")), json.dumps(normalized, ensure_ascii=False, sort_keys=True))
            if key in covered: raise PiHarnessError("duplicate normalized asset")
            leaves: list[Any] = []
            for evidence_id in asset["evidence_ids"]:
                observation = self.store.get(evidence_id)
                leaves.extend(self._leaf_values(observation.raw_value)); leaves.extend(self._leaf_values(observation.normalized_value))
            asserted = self._leaf_values(asset.get("value"))
            if asset.get("type") == "service_name" and len(asserted) == 1 and isinstance(asserted[0], str):
                asserted = [item.strip() for item in asserted[0].split(";") if item.strip()]
            if asset.get("type") == "configuration" and len(asserted) == 1 and isinstance(asserted[0], str) and "," in asserted[0]:
                asserted = [item.strip() for item in asserted[0].split(",") if item.strip()]
            if asset.get("type") == "configuration" and len(asserted) == 1 and isinstance(asserted[0], str) and "\n" in asserted[0]:
                asserted = [item.strip() for item in asserted[0].splitlines() if item.strip()]
            exact_lines = {
                (re.match(r"^\d+\s+(['\"])(.*)\1$", line.strip()).group(2)
                 if re.match(r"^\d+\s+(['\"])(.*)\1$", line.strip()) else line.strip())
                for leaf in leaves if isinstance(leaf, str) for line in leaf.splitlines()
            }
            exact_lines |= {
                match.group(1)
                for leaf in leaves if isinstance(leaf, str) for line in leaf.splitlines()
                if (match := re.search(r"['\"]([^'\"]{1,2048})['\"]\s*$", line.strip()))
            }
            if asset.get("type") == "filename":
                exact_lines |= {PureWindowsPath(item).name for item in exact_lines}
            if asset.get("type") == "configuration":
                exact_lines |= {item.lstrip(".") for item in exact_lines}
            if asset.get("type") == "command":
                command_lines = {
                    re.sub(r"^\d+\s+['\"]", "", line.strip()).rstrip("'\"")
                    for leaf in leaves if isinstance(leaf, str) for line in leaf.splitlines()
                }
                supported = bool(asserted) and all(item in command_lines for item in asserted)
            else:
                supported = bool(asserted) and all(
                    item in leaves or item in exact_lines
                    or (asset.get("type") in {"path", "filename"} and isinstance(item, str) and any(line.endswith(item) for line in exact_lines))
                    for item in asserted
                )
            if not supported:
                continue
            covered.add(key)
            verified_assets.append(asset)
        return {"schema_version": "1.0", "claims": canonical_claims["claims"], "assets": verified_assets, "action_requests": requests}

    def _validate_records(self, records: Any, label: str, maximum: int, requests: bool = False) -> list[dict[str, Any]]:
        if not isinstance(records, list) or len(records) > maximum:
            raise PiHarnessError(f"{label} records must be a bounded array")
        canonical: list[dict[str, Any]] = []
        seen: set[str] = set()
        for record in records:
            if not isinstance(record, Mapping) or record.get("schema_version") != "1.0":
                raise PiHarnessError(f"invalid {label} record")
            item_schema = (
                INVESTIGATION_SCHEMA["properties"]["action_requests"]["items"]
                if requests else INVESTIGATION_SCHEMA["properties"]["assets"]["items"]
            )
            if set(record) != set(item_schema["required"]):
                raise PiHarnessError(f"{label} has missing or unsupported fields")
            record_id = record.get("id")
            evidence_ids = record.get("evidence_ids")
            if not isinstance(record_id, str) or not record_id or record_id in seen:
                raise PiHarnessError(f"invalid or duplicate {label} id")
            if not isinstance(evidence_ids, list) or not evidence_ids or any(
                not isinstance(item, str) or self.store.get(item) is None for item in evidence_ids
            ):
                raise PiHarnessError(f"{label} cites missing evidence")
            if requests and record.get("status") != "pending_authorization":
                raise PiHarnessError("action requests must remain pending_authorization")
            if requests:
                if record.get("kind") not in item_schema["properties"]["kind"]["enum"] or not isinstance(record.get("target"), Mapping):
                    raise PiHarnessError("invalid action request kind or target")
                if not isinstance(record.get("reason"), str) or not record["reason"].strip() or not isinstance(record.get("requested_observations"), list):
                    raise PiHarnessError("invalid action request details")
                if record.get("kind") == "dynamic_analysis":
                    recovery_outputs = {
                        "deobfuscated_payload", "unpacked_payload", "decrypted_payload",
                        "decrypted_configuration", "runtime_key_material",
                        "memory_mapped_image", "injected_code",
                    }
                    requested = {str(item).strip().lower().replace(" ", "_") for item in record["requested_observations"]}
                    if not requested.intersection(recovery_outputs):
                        # Broad behavior-confirmation requests are optional
                        # model output, not a reason to discard an otherwise
                        # valid dossier. Leave them out of requests.json.
                        continue
            else:
                confidence = record.get("confidence")
                if record.get("type") not in item_schema["properties"]["type"]["enum"] or not isinstance(record.get("role"), str):
                    raise PiHarnessError("invalid asset type or role")
                if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not 0 <= confidence <= 1:
                    raise PiHarnessError("invalid asset confidence")
            seen.add(record_id)
            canonical.append(dict(record))
        return canonical


@dataclass(frozen=True)
class PiHarnessResult:
    submission: dict[str, Any]
    usage: dict[str, Any]
    session: dict[str, Any]

    @property
    def claims(self) -> dict[str, Any]:
        """Compatibility view for harvest callers."""
        return self.submission


class PiHarnessRunner:
    """Drive the Pi child over a bounded controller-owned JSONL protocol."""

    _BUDGET_CODES = {"MODEL_CALL_BUDGET", "TOKEN_BUDGET", "COST_BUDGET", "TOOL_CALL_BUDGET"}

    def __init__(self, config: PiHarnessConfig) -> None:
        self.config = config

    @staticmethod
    def _write_frame(stream: Any, value: Mapping[str, Any]) -> None:
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n"
        if len(encoded.encode("utf-8")) > MAX_FRAME_BYTES:
            raise PiHarnessError("Pi protocol frame exceeds the size limit")
        stream.write(encoded)
        stream.flush()

    @staticmethod
    def _read_frame(stream: Any) -> dict[str, Any] | None:
        line = stream.readline(MAX_FRAME_BYTES + 1)
        if line == "":
            return None
        if len(line.encode("utf-8")) > MAX_FRAME_BYTES or not line.endswith("\n"):
            raise PiHarnessError("Pi emitted an oversized or unterminated protocol frame")
        try:
            frame = json.loads(line)
        except json.JSONDecodeError as exc:
            raise PiHarnessError("Pi emitted malformed protocol JSON") from exc
        if not isinstance(frame, dict):
            raise PiHarnessError("Pi protocol frame must be an object")
        return frame

    @staticmethod
    def _stop(process: subprocess.Popen[str]) -> None:
        if process.poll() is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (OSError, ProcessLookupError):
            process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                process.kill()

    def run(
        self,
        broker: PiToolBroker,
        *,
        mode: str,
        output_schema: Mapping[str, Any],
        system_prompt: str,
        task: str,
    ) -> PiHarnessResult:
        if mode not in {"research", "research_finalize", "harvest"}:
            raise PiHarnessError("unknown Pi harness phase")
        self.config.session_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
        tool_definitions = broker.definitions(mode)
        allowed_tool_names = {item["name"] for item in tool_definitions}
        process = subprocess.Popen(
            [self.config.node, str(self.config.script)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            close_fds=True,
            start_new_session=True,
            env=os.environ.copy(),
        )
        if process.stdin is None or process.stdout is None or process.stderr is None:
            self._stop(process)
            raise PiHarnessError("could not open Pi protocol pipes")
        diagnostics = _BoundedStderr()
        stderr_thread = threading.Thread(target=diagnostics.drain, args=(process.stderr,), daemon=True)
        stderr_thread.start()
        try:
            self._write_frame(
                process.stdin,
                self.config.init_frame(
                    mode=mode,
                    tool_definitions=tool_definitions,
                    output_schema=output_schema,
                    system_prompt=system_prompt,
                    task=task,
                ),
            )
            while True:
                frame = self._read_frame(process.stdout)
                if frame is None:
                    code = process.wait(timeout=2)
                    raise PiHarnessError(
                        f"Pi exited before completing the dossier (status {code}): {diagnostics.text()}"
                    )
                kind = frame.get("type")
                if kind == "progress":
                    if frame.get("phase") != mode:
                        raise PiHarnessError("Pi progress phase does not match the active phase")
                    _emit_progress(frame)
                    continue
                if kind == "request":
                    request_id = frame.get("id")
                    operation = frame.get("operation")
                    payload = frame.get("payload")
                    if not isinstance(request_id, int) or not isinstance(payload, dict):
                        raise PiHarnessError("Pi sent an invalid broker request")
                    try:
                        if operation == "execute_tool":
                            tool_name = payload.get("name")
                            if tool_name not in allowed_tool_names:
                                raise PiHarnessError(f"tool {tool_name!r} is unavailable during {mode}")
                            result = broker.execute(tool_name, payload.get("arguments"))
                        elif operation == "validate_claims" and mode == "harvest":
                            result = broker.validate_claims(payload.get("claims"))
                        elif operation == "validate_research" and mode in {"research", "research_finalize"}:
                            result = broker.validate_research(payload.get("research"))
                        else:
                            raise PiHarnessError("Pi requested an unknown broker operation")
                    except Exception as error:
                        self._write_frame(process.stdin, {
                            "type": "response", "id": request_id, "ok": False,
                            "error": {"type": error.__class__.__name__, "message": " ".join(str(error).split())[:500]},
                        })
                    else:
                        self._write_frame(process.stdin, {
                            "type": "response", "id": request_id, "ok": True, "result": result,
                        })
                    continue
                if kind == "error":
                    error = frame.get("error") if isinstance(frame.get("error"), dict) else {}
                    code = error.get("code")
                    message = str(error.get("message", "Pi harness failed"))[:1000]
                    if code in self._BUDGET_CODES:
                        raise PiHarnessBudgetError(message)
                    raise PiHarnessError(message)
                if kind == "complete":
                    submission = (
                        broker.validate_research(frame.get("submission"))
                        if mode in {"research", "research_finalize"}
                        else broker.validate_claims(frame.get("submission"))
                    )
                    usage = frame.get("usage")
                    session = frame.get("session")
                    if not isinstance(usage, dict) or not isinstance(session, dict):
                        raise PiHarnessError("Pi completion metadata is malformed")
                    return PiHarnessResult(submission=submission, usage=usage, session=session)
                raise PiHarnessError("Pi emitted an unknown protocol frame")
        finally:
            try:
                process.stdin.close()
            except (OSError, ValueError):
                pass
            self._stop(process)
            stderr_thread.join(timeout=1)
            for stream in (process.stdout, process.stderr):
                try:
                    stream.close()
                except (OSError, ValueError):
                    pass


class PiInvestigator:
    """Production investigator role backed by Pi SDK and JAQ-owned tools."""

    def __init__(self, store: Any, runtime: Any, output_dir: Path) -> None:
        self.store = store
        self.runtime = runtime
        self.output_dir = output_dir
        self.config = PiHarnessConfig.from_env(output_dir)
        self.last_run: InvestigatorRun | None = None

    def _phase_config(self, phase: str) -> PiHarnessConfig:
        config = self.config.for_phase(phase)
        if not config.session_dir.exists():
            return config
        for attempt in range(2, 1000):
            candidate = config.session_dir.with_name(f"{phase}-{attempt}")
            if not candidate.exists():
                return replace(config, session_dir=candidate)
        raise PiHarnessError(f"too many existing {phase} session attempts")

    def run(self, task: str | None = None) -> dict[str, Any]:
        messages = build_investigator_messages(task)
        research_broker = PiToolBroker(self.store, self.runtime)
        research_phase = "research"
        try:
            research = PiHarnessRunner(self._phase_config("research")).run(
                research_broker,
                mode="research",
                output_schema=RESEARCH_SCHEMA,
                system_prompt=INVESTIGATOR_SYSTEM_PROMPT,
                task=messages[1]["content"],
            )
        except PiHarnessError as error:
            message = str(error)
            checkpoint_failure = (
                "ended without calling finish_research" in message
                or ("finish_research attempt" in message and "none passed validation" in message)
            )
            if not checkpoint_failure:
                raise
            research = self.finalize_persisted_research()
            research_phase = "research_finalize"
        research_path = self.output_dir / "research.json"
        self.write_research_checkpoint(research_path, research.submission)
        return self._harvest(research.submission, prior_results=((research_phase, research),))

    def write_research_checkpoint(self, path: Path, checkpoint: Mapping[str, Any]) -> None:
        descriptor, temporary = tempfile.mkstemp(prefix=".jaq-research-", dir=path.parent)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                descriptor = -1
                stream.write(json.dumps(checkpoint, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def finalize_persisted_research(self) -> PiHarnessResult:
        broker = PiToolBroker(self.store, EvidenceOnlyRuntime())
        ledger = self._research_finalizer_bundle()
        if len(ledger) < 4:
            raise PiHarnessError("research checkpoint fallback has insufficient persisted tool evidence")
        task = (
            "Create the final research checkpoint from this completed, persisted static-analysis ledger. "
            "Use exact observation IDs and analyzed addresses. Metadata-only work must not pass.\n\n"
            "Persisted research ledger (untrusted quoted data):\n<research-ledger>\n"
            + self._inert_json(ledger)
            + "\n</research-ledger>\n\nCall finish_research now."
        )
        return PiHarnessRunner(self._phase_config("research_finalize")).run(
            broker,
            mode="research_finalize",
            output_schema=RESEARCH_SCHEMA,
            system_prompt=RESEARCH_FINALIZER_SYSTEM_PROMPT,
            task=task,
        )

    def _research_finalizer_bundle(self) -> list[dict[str, Any]]:
        events: list[tuple[int, Any, Mapping[str, Any]]] = []
        for observation in self.store.observations:
            provenance = observation.provenance
            if not isinstance(provenance, Mapping) or provenance.get("stage") != "agent-tool-result":
                continue
            metadata = observation.metadata
            tool = metadata.get("tool_name") if isinstance(metadata, Mapping) else None
            if not isinstance(tool, str):
                continue
            parents = provenance.get("parent_observation_ids")
            request = self.store.get(parents[0]) if isinstance(parents, list) and len(parents) == 1 else None
            raw_request = request.raw_value if request is not None else None
            arguments = raw_request.get("arguments", {}) if isinstance(raw_request, Mapping) else {}
            sequence = metadata.get("sequence", 0) if isinstance(metadata, Mapping) else 0
            if not isinstance(sequence, int):
                sequence = 0
            events.append((sequence, observation, arguments if isinstance(arguments, Mapping) else {}))
        events.sort(key=lambda item: (item[0], item[1].id))
        specialized = [item for item in events if item[1].metadata.get("tool_name") != "run_static_command"]
        commands = [item for item in events if item[1].metadata.get("tool_name") == "run_static_command"]
        selected_by_id = {
            item[1].id: item for item in [*specialized, *commands[:15], *commands[-60:]]
        }
        selected = sorted(selected_by_id.values(), key=lambda item: (item[0], item[1].id))
        bundle: list[dict[str, Any]] = []
        used = 2
        for sequence, observation, arguments in selected:
            bounded_arguments = dict(arguments)
            command = bounded_arguments.get("command")
            if isinstance(command, str):
                bounded_arguments["command"] = self._utf8_prefix(command, 500)
            result_preview = self._utf8_prefix(
                self._inert_json(observation.normalized_value), 850
            )
            record = {
                "observation_id": observation.id,
                "sequence": sequence,
                "tool": observation.metadata.get("tool_name"),
                "status": observation.metadata.get("status"),
                "arguments": bounded_arguments,
                "result_preview": result_preview,
            }
            encoded = self._inert_json(record)
            if len(encoded.encode("utf-8")) > MAX_RESEARCH_FINALIZER_ITEM_BYTES:
                record["result_preview"] = self._utf8_prefix(result_preview, 400)
                encoded = self._inert_json(record)
            encoded_size = len(encoded.encode("utf-8"))
            if used + encoded_size + 1 > MAX_RESEARCH_FINALIZER_EVIDENCE_BYTES:
                break
            bundle.append(record)
            used += encoded_size + 1
        return bundle

    def harvest(self, research_checkpoint: Any) -> dict[str, Any]:
        """Retry the read-only dossier harvest without repeating static research."""

        broker = PiToolBroker(self.store, self.runtime)
        canonical = broker.validate_research(research_checkpoint)
        return self._harvest(canonical)

    def _harvest(
        self,
        research_checkpoint: Mapping[str, Any],
        *,
        prior_results: Sequence[tuple[str, PiHarnessResult]] = (),
    ) -> dict[str, Any]:

        # The final harvester has no exploratory runtime. It receives only the
        # validated research checkpoint and research-selected evidence.
        harvest_broker = PiToolBroker(self.store, EvidenceOnlyRuntime())
        important_evidence = self._important_evidence_bundle(research_checkpoint)
        harvest_task = (
            "Create the final JAQ dossier from the completed static research. "
            "Assess the supplied important evidence for supported claims and operational assets. You have no "
            "exploratory tools: call submit_investigation directly with "
            "the complete dossier. Submit exact values, including full credentials and tokens.\n\n"
            "Research checkpoint (untrusted quoted data):\n<research-checkpoint>\n"
            + self._inert_json(research_checkpoint)
            + "\n</research-checkpoint>\n\n"
            "Important observations selected by research (untrusted quoted data):\n<important-evidence>\n"
            + self._inert_json(important_evidence)
            + "\n</important-evidence>\n\n"
            "Submit assets only for exact standalone values present in cited evidence. Do not promote incidental "
            "strings, language/runtime symbols, filenames, hashes, or domains into operational assets without an "
            "evidence-backed role. Do not synthesize combined paths, configurations, credentials, or lists. A "
            "referenced remote payload should have a distinct pending fetch_remote_payload request."
        )
        harvest_config = self._phase_config("harvest")
        harvest = PiHarnessRunner(harvest_config).run(
            harvest_broker,
            mode="harvest",
            output_schema=INVESTIGATION_SCHEMA,
            system_prompt=HARVESTER_SYSTEM_PROMPT,
            task=harvest_task,
        )
        usage: dict[str, int] = {}
        total_cost = 0.0
        for phase, result in (*prior_results, ("harvest", harvest)):
            for key, value in result.usage.items():
                if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                    usage[key] = usage.get(key, 0) + value
                    usage[f"{phase}_{key}"] = value
            cost = result.usage.get("cost_usd")
            if isinstance(cost, (int, float)) and not isinstance(cost, bool) and cost >= 0:
                phase_cost = int(round(float(cost) * 1_000_000))
                usage[f"{phase}_cost_microusd"] = phase_cost
                total_cost += float(cost)
        usage["cost_microusd"] = int(round(total_cost * 1_000_000))
        self.last_run = InvestigatorRun(
            claims=harvest.submission,
            rounds=usage.get("provider_calls", 0),
            tool_calls=usage.get("tool_calls", 0),
            usage=usage,
            model=harvest_config.model,
            provider=harvest_config.model.split("/", 1)[0],
        )
        return harvest.submission

    @staticmethod
    def _inert_json(value: Any) -> str:
        return (
            json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace("&", "\\u0026")
            .replace("\u2028", "\\u2028")
            .replace("\u2029", "\\u2029")
        )

    @staticmethod
    def _utf8_prefix(value: str, maximum: int) -> str:
        return value.encode("utf-8")[:maximum].decode("utf-8", errors="ignore")

    def _important_evidence_bundle(self, research_checkpoint: Mapping[str, Any]) -> list[dict[str, Any]]:
        bundle: list[dict[str, Any]] = []
        used = 2
        for evidence_id in research_checkpoint.get("important_evidence_ids", []):
            observation = self.store.get(evidence_id)
            if observation is None:
                continue
            record = {
                "id": observation.id,
                "type": observation.type,
                "raw_value": observation.raw_value,
                "normalized_value": observation.normalized_value,
                "artifact_location": observation.artifact_location,
                "metadata": dict(observation.metadata),
            }
            encoded = self._inert_json(record)
            encoded_size = len(encoded.encode("utf-8"))
            if encoded_size > MAX_HARVEST_EVIDENCE_ITEM_BYTES:
                record = {
                    "id": observation.id,
                    "type": observation.type,
                    "truncated": True,
                    "value_preview": self._utf8_prefix(
                        encoded, MAX_HARVEST_EVIDENCE_ITEM_BYTES - 400
                    ),
                }
                encoded = self._inert_json(record)
                encoded_size = len(encoded.encode("utf-8"))
            if used + encoded_size + 1 > MAX_HARVEST_EVIDENCE_BYTES:
                break
            bundle.append(record)
            used += encoded_size + 1
        return bundle


__all__ = [
    "EvidenceOnlyRuntime",
    "PiHarnessBudgetError",
    "PiHarnessConfig",
    "PiHarnessError",
    "PiHarnessResult",
    "PiHarnessRunner",
    "PiInvestigator",
    "PiToolBroker",
]
