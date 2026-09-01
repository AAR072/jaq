"""Host-side Pi SDK investigator with a Python JAQ tool broker."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import signal
import subprocess
import threading
from typing import Any, Mapping, Sequence

from .investigator import Investigator, InvestigatorConfig, InvestigatorRun, validate_claims
from .prompts import INVESTIGATION_SCHEMA, INVESTIGATOR_SYSTEM_PROMPT, INVESTIGATOR_TOOLS, build_investigator_messages


MAX_FRAME_BYTES = 8 << 20
MAX_STDERR_BYTES = 64 << 10


class PiHarnessError(RuntimeError):
    """The host-side Pi session failed or violated its protocol."""


class PiHarnessBudgetError(PiHarnessError):
    """Pi stopped before another provider/tool call because a budget was exhausted."""


def _positive_int_env(name: str, default: int, maximum: int) -> int:
    raw = os.environ.get(name)
    try:
        value = default if raw is None else int(raw)
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
    max_model_calls: int
    max_tool_calls: int
    max_total_tokens: int
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
            max_model_calls=_positive_int_env("JAQ_MAX_MODEL_CALLS", 12, 100),
            max_tool_calls=_positive_int_env("JAQ_MAX_TOOL_CALLS", 40, 1000),
            max_total_tokens=_positive_int_env("JAQ_MAX_TOTAL_TOKENS", 500_000, 100_000_000),
            max_cost_usd=_positive_float_env("JAQ_MAX_COST_USD", 0.10, 1000.0),
            max_output_tokens=_positive_int_env("JAQ_MAX_OUTPUT_TOKENS", 8_000, 100_000),
            tool_preview_chars=_positive_int_env("JAQ_TOOL_PREVIEW_CHARS", 2_400, 64_000),
            max_context_tokens=_positive_int_env("JAQ_MAX_CONTEXT_TOKENS", 64_000, 2_000_000),
            keep_recent_tokens=_positive_int_env("JAQ_KEEP_RECENT_TOKENS", 12_000, 500_000),
        )

    def init_frame(
        self,
        *,
        tool_definitions: Sequence[Mapping[str, Any]],
        system_prompt: str,
        task: str,
    ) -> dict[str, Any]:
        return {
            "type": "init",
            "model": self.model,
            "thinking_level": self.thinking_level,
            "system_prompt": system_prompt,
            "task": task,
            "session_dir": str(self.session_dir),
            "tool_definitions": [dict(item) for item in tool_definitions],
            "claims_schema": INVESTIGATION_SCHEMA,
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

    def definitions(self) -> list[dict[str, Any]]:
        definitions: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in [*INVESTIGATOR_TOOLS, *self.runtime.model_tools()]:
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

    def execute(self, name: str, arguments: Any) -> Any:
        if not isinstance(name, str) or not isinstance(arguments, Mapping):
            raise PiHarnessError("Pi supplied an invalid tool request")
        return self.legacy._execute_tool(name, dict(arguments))

    def validate_claims(self, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, Mapping) or set(payload) != {"schema_version", "claims", "assets", "action_requests"}:
            raise PiHarnessError("investigation must contain schema_version, claims, assets, and action_requests")
        canonical_claims = validate_claims(
            {"schema_version": payload.get("schema_version"), "claims": payload.get("claims")},
            evidence_store=self.store,
        )
        assets = self._validate_records(payload.get("assets"), "asset", 500)
        requests = self._validate_records(payload.get("action_requests"), "request", 100, requests=True)
        return {"schema_version": "1.0", "claims": canonical_claims["claims"], "assets": assets, "action_requests": requests}

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
    claims: dict[str, Any]
    usage: dict[str, Any]
    session: dict[str, Any]


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

    def run(self, broker: PiToolBroker, *, system_prompt: str, task: str) -> PiHarnessResult:
        self.config.session_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
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
                    tool_definitions=broker.definitions(), system_prompt=system_prompt, task=task,
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
                if kind == "request":
                    request_id = frame.get("id")
                    operation = frame.get("operation")
                    payload = frame.get("payload")
                    if not isinstance(request_id, int) or not isinstance(payload, dict):
                        raise PiHarnessError("Pi sent an invalid broker request")
                    try:
                        if operation == "execute_tool":
                            result = broker.execute(payload.get("name"), payload.get("arguments"))
                        elif operation == "validate_claims":
                            result = broker.validate_claims(payload.get("claims"))
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
                    claims = broker.validate_claims(frame.get("claims"))
                    usage = frame.get("usage")
                    session = frame.get("session")
                    if not isinstance(usage, dict) or not isinstance(session, dict):
                        raise PiHarnessError("Pi completion metadata is malformed")
                    return PiHarnessResult(claims=claims, usage=usage, session=session)
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

    def run(self, task: str | None = None) -> dict[str, Any]:
        messages = build_investigator_messages(task)
        operational_task = messages[1]["content"]
        pi_system_prompt = INVESTIGATOR_SYSTEM_PROMPT + (
            "\n\nPi harness override: do not return claims as assistant text. "
            "When the evidence is sufficient, call submit_investigation with claims, assets, and action_requests."
        )
        result = PiHarnessRunner(self.config).run(
            PiToolBroker(self.store, self.runtime),
            system_prompt=pi_system_prompt,
            task=operational_task,
        )
        usage: dict[str, int] = {}
        for key, value in result.usage.items():
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                usage[key] = value
        cost = result.usage.get("cost_usd")
        if isinstance(cost, (int, float)) and not isinstance(cost, bool) and cost >= 0:
            usage["cost_microusd"] = int(round(float(cost) * 1_000_000))
        self.last_run = InvestigatorRun(
            claims=result.claims,
            rounds=usage.get("provider_calls", 0),
            tool_calls=usage.get("tool_calls", 0),
            usage=usage,
            model=self.config.model,
            provider=self.config.model.split("/", 1)[0],
        )
        return result.claims


__all__ = [
    "PiHarnessBudgetError",
    "PiHarnessConfig",
    "PiHarnessError",
    "PiHarnessResult",
    "PiHarnessRunner",
    "PiInvestigator",
    "PiToolBroker",
]
