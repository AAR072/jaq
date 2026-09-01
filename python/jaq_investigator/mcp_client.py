"""Small, bounded MCP JSON-RPC client used by the static agent.

The client intentionally implements only the MCP lifecycle and tools
primitive.  It does not expose resources, prompts, sampling, roots, HTTP, or
server-initiated requests.  A controller supplies the transport; model data
never chooses the process, container, environment, or filesystem path.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import json
import os
import selectors
import signal
import subprocess
import threading
import time
import inspect
from typing import Any, Protocol, runtime_checkable
import re


MCP_PROTOCOL_VERSION = "2025-06-18"
DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_LINE_BYTES = 1 << 20
DEFAULT_MAX_PAGES = 32
DEFAULT_MAX_TOOLS = 256
DEFAULT_MAX_PAGE_BYTES = 256 << 10
DEFAULT_MAX_SCHEMA_BYTES = 32 << 10
DEFAULT_MAX_ARGUMENT_BYTES = 64 << 10
DEFAULT_MAX_STDERR_BYTES = 64 << 10
DEFAULT_MAX_NOTIFICATIONS = 64


class MCPError(RuntimeError):
    """Base error crossing the MCP boundary."""


class MCPTransportError(MCPError):
    """The underlying transport could not send, receive, or close."""


class MCPProtocolError(MCPError):
    """The peer returned a malformed, unsupported, or unsafe MCP message."""


class MCPFrameError(MCPProtocolError):
    """A stdio frame was not one bounded UTF-8 JSON object."""


class MCPTimeoutError(MCPTransportError):
    """A bounded MCP request or read timed out."""


class MCPRemoteError(MCPProtocolError):
    """The MCP peer returned a JSON-RPC error response."""

    def __init__(self, code: Any, message: str, data: Any = None) -> None:
        self.code = code
        self.data = data
        safe_message = str(message).replace("\r", " ").replace("\n", " ")[:500]
        super().__init__(f"MCP error {code!r}: {safe_message}")


@dataclass(frozen=True)
class MCPToolSpec:
    """A bounded discovered tool description.

    The description is retained as server data for diagnostics, but callers
    must not forward it directly to a model.  The agent uses its own static
    descriptions and schemas for model-facing tools.
    """

    name: str
    input_schema: Mapping[str, Any]
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": dict(self.input_schema),
        }


class MCPToolResult(Mapping[str, Any]):
    """A JSON-shaped bounded ``tools/call`` result."""

    def __init__(
        self,
        value: Mapping[str, Any],
        *,
        truncated: bool = False,
    ) -> None:
        self._value = dict(value)
        self.truncated = truncated

    def __getitem__(self, key: str) -> Any:
        return self._value[key]

    def __iter__(self):
        return iter(self._value)

    def __len__(self) -> int:
        return len(self._value)

    def to_dict(self) -> dict[str, Any]:
        return dict(self._value)

    @property
    def content(self) -> Any:
        return self._value.get("content", [])

    @property
    def structured_content(self) -> Any:
        return self._value.get("structuredContent")

    @property
    def is_error(self) -> bool:
        return bool(self._value.get("isError", False))


@runtime_checkable
class Transport(Protocol):
    """Injected line transport; implementations own process isolation."""

    def start(self) -> None:
        ...

    def send(self, message: Mapping[str, Any]) -> None:
        ...

    def receive(self, timeout: float, max_bytes: int) -> bytes | str | Mapping[str, Any]:
        ...

    def close(self, grace_timeout: float = 1.0) -> None:
        ...


# Short alias used by callers that call the abstraction a transport protocol.
MCPTransport = Transport


def _json_bytes(value: Any, *, field: str, max_bytes: int | None = None) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as exc:
        raise MCPProtocolError(f"{field} must be JSON-compatible") from exc
    if max_bytes is not None and len(encoded) > max_bytes:
        raise MCPFrameError(f"{field} exceeds the {max_bytes}-byte bound")
    return encoded


def _same_json_id(left: Any, right: Any) -> bool:
    # bool is a subclass of int in Python, but JSON-RPC IDs must retain type.
    return type(left) is type(right) and left == right


def _validate_container_name(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value):
        raise ValueError("container must be a Docker container name, not a path or shell expression")
    return value


def _safe_controller_args(values: Sequence[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes, bytearray)):
        raise ValueError("controller MCP flags must be a sequence of arguments")
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value or "\x00" in value or "\r" in value or "\n" in value:
            raise ValueError("controller MCP flags must be nonempty strings without NUL/newlines")
        if re.search(r"(?i)(api[_-]?key|token|secret|password|credential)", value):
            raise ValueError("provider credentials must not be passed as MCP flags")
        normalized.append(value)
    return tuple(normalized)


class DockerExecMCPTransport:
    """Run the fixed r2mcp stdio server inside a controller-selected container."""

    def __init__(
        self,
        container: str,
        *,
        flags: Sequence[str] = (),
        fixed_flags: Sequence[str] | None = None,
        docker_binary: str = "docker",
        max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
        max_stderr_bytes: int = DEFAULT_MAX_STDERR_BYTES,
    ) -> None:
        self.container = _validate_container_name(container)
        if fixed_flags is not None:
            if flags:
                raise ValueError("supply flags or fixed_flags, not both")
            flags = fixed_flags
        self.flags = _safe_controller_args(flags)
        if (
            not isinstance(docker_binary, str)
            or not docker_binary
            or "\x00" in docker_binary
            or "\r" in docker_binary
            or "\n" in docker_binary
        ):
            raise ValueError("docker_binary must be a fixed executable name")
        self.docker_binary = docker_binary
        self.max_line_bytes = _positive_bound(max_line_bytes, "max_line_bytes")
        self.max_stderr_bytes = _positive_bound(max_stderr_bytes, "max_stderr_bytes")
        self.process: subprocess.Popen[bytes] | None = None
        self.command: tuple[str, ...] = (
            self.docker_binary,
            "exec",
            "-i",
            self.container,
            "r2mcp",
            *self.flags,
        )
        self._selector: selectors.BaseSelector | None = None
        self._stdin_lock = threading.Lock()
        self._stderr_thread: threading.Thread | None = None
        self._stderr_buffer = bytearray()
        self._stderr_truncated = False
        self._stdout_buffer = bytearray()
        self._started = False

    @property
    def argv(self) -> tuple[str, ...]:
        return self.command

    @property
    def stderr(self) -> str:
        return bytes(self._stderr_buffer).decode("utf-8", errors="replace")

    @property
    def stderr_truncated(self) -> bool:
        return self._stderr_truncated

    def start(self) -> None:
        if self._started and self.process is not None and self.process.poll() is None:
            return
        if self._started:
            raise MCPTransportError("MCP transport cannot be restarted after process exit")
        # Do not inherit provider credentials into the docker client/container.
        # Docker daemon selection is intentionally controller-owned and is not
        # model-configurable; the fixed client environment needs only locale and
        # a standard executable search path.
        safe_env = {"PATH": os.environ.get("PATH", os.defpath), "LC_ALL": "C.UTF-8"}
        for name in ("HOME", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "XDG_CONFIG_HOME"):
            value = os.environ.get(name)
            if value:
                safe_env[name] = value
        try:
            self.process = subprocess.Popen(
                list(self.command),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
                start_new_session=True,
                env=safe_env,
            )
        except OSError as exc:
            raise MCPTransportError("could not start docker r2mcp transport") from exc
        self._started = True
        self._stdout_buffer.clear()
        if self.process.stdout is None or self.process.stdin is None:
            self.close(grace_timeout=0)
            raise MCPTransportError("docker r2mcp transport did not expose stdio pipes")
        if self.process.stderr is not None:
            self._stderr_thread = threading.Thread(
                target=self._drain_stderr,
                args=(self.process.stderr,),
                name="jaq-r2mcp-stderr",
                daemon=True,
            )
            self._stderr_thread.start()
        self._selector = selectors.DefaultSelector()
        self._selector.register(self.process.stdout, selectors.EVENT_READ)

    def _drain_stderr(self, stream: Any) -> None:
        while True:
            try:
                chunk = stream.read(4096)
            except (OSError, ValueError):
                return
            if not chunk:
                return
            if isinstance(chunk, str):
                chunk = chunk.encode("utf-8", errors="replace")
            if not isinstance(chunk, (bytes, bytearray)):
                continue
            if len(self._stderr_buffer) < self.max_stderr_bytes:
                remaining = self.max_stderr_bytes - len(self._stderr_buffer)
                self._stderr_buffer.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    self._stderr_truncated = True
            else:
                self._stderr_truncated = True

    def send(self, message: Mapping[str, Any]) -> None:
        if not self._started or self.process is None or self.process.stdin is None:
            raise MCPTransportError("MCP transport is not started")
        encoded = _json_bytes(message, field="MCP message", max_bytes=self.max_line_bytes - 1) + b"\n"
        with self._stdin_lock:
            try:
                self.process.stdin.write(encoded)
                self.process.stdin.flush()
            except (BrokenPipeError, OSError, ValueError) as exc:
                raise MCPTransportError("MCP transport stdin is closed") from exc

    def receive(self, timeout: float, max_bytes: int) -> bytes:
        if not self._started or self.process is None or self.process.stdout is None or self._selector is None:
            raise MCPTransportError("MCP transport is not started")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("MCP receive timeout must be positive")
        limit = min(self.max_line_bytes, _positive_bound(max_bytes, "max_bytes"))
        stream = self.process.stdout
        fd = stream.fileno()
        deadline = time.monotonic() + float(timeout)
        while True:
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                raise MCPTimeoutError("MCP stdio receive timed out")
            newline = self._stdout_buffer.find(b"\n")
            if newline >= 0:
                frame = bytes(self._stdout_buffer[: newline + 1])
                del self._stdout_buffer[: newline + 1]
                if len(frame) > limit:
                    raise MCPFrameError(f"MCP frame exceeds the {limit}-byte bound")
                return frame
            if len(self._stdout_buffer) > limit:
                raise MCPFrameError(f"MCP frame exceeds the {limit}-byte bound")
            events = self._selector.select(remaining_time)
            if not events:
                raise MCPTimeoutError("MCP stdio receive timed out")
            try:
                chunk = os.read(fd, min(4096, limit - len(self._stdout_buffer) + 1))
            except OSError as exc:
                raise MCPTransportError("MCP stdout read failed") from exc
            if not chunk:
                if self._stdout_buffer:
                    raise MCPFrameError("MCP peer closed stdout with an unterminated frame")
                raise MCPTransportError("MCP peer closed stdout")
            self._stdout_buffer.extend(chunk)

    def close(self, grace_timeout: float = 1.0) -> None:
        process = self.process
        selector = self._selector
        self._selector = None
        if selector is not None:
            try:
                selector.close()
            except Exception:
                pass
        if process is None:
            return
        if process.stdin is not None:
            try:
                process.stdin.close()
            except (OSError, ValueError):
                pass
        try:
            process.wait(timeout=max(0.0, float(grace_timeout)))
        except subprocess.TimeoutExpired:
            self._terminate_process(process)
        except (OSError, ValueError):
            pass
        if self._stderr_thread is not None:
            self._stderr_thread.join(timeout=max(0.1, float(grace_timeout)))
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except (OSError, ValueError):
                    pass
        self._stdout_buffer.clear()
        self.process = None

    @staticmethod
    def _terminate_process(process: subprocess.Popen[bytes]) -> None:
        try:
            if process.pid:
                os.killpg(process.pid, signal.SIGTERM)
            else:
                process.terminate()
        except (OSError, ProcessLookupError):
            try:
                process.terminate()
            except (OSError, ProcessLookupError):
                pass
        try:
            process.wait(timeout=0.5)
            return
        except (subprocess.TimeoutExpired, OSError, ValueError):
            pass
        try:
            if process.pid:
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except (OSError, ProcessLookupError):
            try:
                process.kill()
            except (OSError, ProcessLookupError):
                pass
        try:
            process.wait(timeout=0.5)
        except (subprocess.TimeoutExpired, OSError, ValueError):
            pass

    # Explicit aliases simplify tiny test transports and controller adapters.
    write = send
    read = receive


def _positive_bound(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


class MCPClient:
    """A synchronous, single-session MCP client with strict bounded I/O."""

    def __init__(
        self,
        transport: Transport,
        *,
        protocol_version: str = MCP_PROTOCOL_VERSION,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
        max_pages: int = DEFAULT_MAX_PAGES,
        max_tools: int = DEFAULT_MAX_TOOLS,
        max_page_bytes: int = DEFAULT_MAX_PAGE_BYTES,
        max_schema_bytes: int = DEFAULT_MAX_SCHEMA_BYTES,
        max_argument_bytes: int = DEFAULT_MAX_ARGUMENT_BYTES,
        max_notifications: int = DEFAULT_MAX_NOTIFICATIONS,
    ) -> None:
        if not isinstance(transport, Transport):
            # Runtime Protocol checks are useful for production but fakes may
            # intentionally be duck-typed. Keep the check structural and
            # produce a clear error before any process is started.
            required = ("start", "send", "receive", "close")
            if any(not callable(getattr(transport, name, None)) for name in required):
                raise TypeError("transport must implement start/send/receive/close")
        if not isinstance(protocol_version, str) or protocol_version != MCP_PROTOCOL_VERSION:
            raise ValueError(f"only MCP protocol {MCP_PROTOCOL_VERSION!r} is supported")
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.transport = transport
        self.protocol_version = protocol_version
        self.timeout_seconds = float(timeout_seconds)
        self.max_line_bytes = _positive_bound(max_line_bytes, "max_line_bytes")
        self.max_pages = _positive_bound(max_pages, "max_pages")
        self.max_tools = _positive_bound(max_tools, "max_tools")
        self.max_page_bytes = _positive_bound(max_page_bytes, "max_page_bytes")
        self.max_schema_bytes = _positive_bound(max_schema_bytes, "max_schema_bytes")
        self.max_argument_bytes = _positive_bound(max_argument_bytes, "max_argument_bytes")
        self.max_notifications = _positive_bound(max_notifications, "max_notifications")
        self._next_id = 1
        self._started = False
        self._initialized = False
        self._closed = False
        self._tools: dict[str, MCPToolSpec] = {}
        self.server_info: Mapping[str, Any] = {}
        self.server_capabilities: Mapping[str, Any] = {}
        self.negotiated_protocol_version: str | None = None
        self._notifications: list[Mapping[str, Any]] = []

    @property
    def initialized(self) -> bool:
        return self._initialized

    @property
    def tools(self) -> tuple[MCPToolSpec, ...]:
        return tuple(self._tools[name] for name in sorted(self._tools))

    @property
    def notifications(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(self._notifications)

    def initialize(self) -> Mapping[str, Any]:
        if self._initialized:
            return {
                "protocolVersion": self.negotiated_protocol_version,
                "serverInfo": dict(self.server_info),
                "capabilities": dict(self.server_capabilities),
            }
        if self._closed:
            raise MCPTransportError("MCP client is closed")
        if not self._started:
            self.transport.start()
            self._started = True
        request_id = self._allocate_id()
        try:
            response = self._request(
                request_id,
                "initialize",
                {
                    "protocolVersion": self.protocol_version,
                    "capabilities": {},
                "clientInfo": {"name": "jaq-investigator", "version": "0.2.0"},
                },
            )
            result = response.get("result")
            if not isinstance(result, Mapping):
                raise MCPProtocolError("initialize result must be an object")
            selected = result.get("protocolVersion")
            if selected != self.protocol_version:
                raise MCPProtocolError(
                    f"MCP protocol mismatch: server selected {selected!r}, client supports {self.protocol_version!r}"
                )
            capabilities = result.get("capabilities")
            if not isinstance(capabilities, Mapping) or not isinstance(capabilities.get("tools"), Mapping):
                raise MCPProtocolError("MCP server did not advertise the tools capability")
            server_info = result.get("serverInfo")
            if not isinstance(server_info, Mapping):
                raise MCPProtocolError("MCP initialize result is missing serverInfo")
            self.negotiated_protocol_version = selected
            self.server_info = dict(server_info)
            self.server_capabilities = dict(capabilities)
            self._send_notification("notifications/initialized")
            self._initialized = True
            return dict(result)
        except Exception:
            self._abort()
            raise

    def list_tools(self) -> tuple[MCPToolSpec, ...]:
        self._require_initialized()
        try:
            found: dict[str, MCPToolSpec] = {}
            cursor: str | None = None
            seen_cursors: set[str] = set()
            for _ in range(self.max_pages):
                params: dict[str, Any] = {} if cursor is None else {"cursor": cursor}
                response = self._request(self._allocate_id(), "tools/list", params)
                result = response.get("result")
                if not isinstance(result, Mapping):
                    raise MCPProtocolError("tools/list result must be an object")
                _json_bytes(result, field="tools/list result", max_bytes=self.max_page_bytes)
                raw_tools = result.get("tools")
                if not isinstance(raw_tools, list):
                    raise MCPProtocolError("tools/list result must contain a tools array")
                if len(found) + len(raw_tools) > self.max_tools:
                    raise MCPFrameError(f"tools/list exceeds the {self.max_tools}-tool bound")
                for raw_tool in raw_tools:
                    spec = self._parse_tool_spec(raw_tool)
                    if spec.name in found:
                        raise MCPProtocolError(f"tools/list returned duplicate tool {spec.name!r}")
                    found[spec.name] = spec
                next_cursor = result.get("nextCursor")
                if next_cursor is None:
                    self._tools = found
                    return self.tools
                if not isinstance(next_cursor, str) or not next_cursor or len(next_cursor) > 512:
                    raise MCPProtocolError("tools/list nextCursor must be a bounded nonempty string")
                if next_cursor in seen_cursors or next_cursor == cursor:
                    raise MCPProtocolError("tools/list pagination cursor repeated")
                seen_cursors.add(next_cursor)
                cursor = next_cursor
            raise MCPFrameError(f"tools/list exceeded the {self.max_pages}-page bound")
        except Exception:
            self._abort()
            raise

    def _parse_tool_spec(self, raw_tool: Any) -> MCPToolSpec:
        if not isinstance(raw_tool, Mapping):
            raise MCPProtocolError("tools/list returned a non-object tool")
        name = raw_tool.get("name")
        if not isinstance(name, str) or not name or len(name) > 200:
            raise MCPProtocolError("MCP tool name must be a bounded nonempty string")
        input_schema = raw_tool.get("inputSchema")
        if not isinstance(input_schema, Mapping):
            raise MCPProtocolError(f"MCP tool {name!r} has no inputSchema object")
        _json_bytes(input_schema, field=f"schema for {name}", max_bytes=self.max_schema_bytes)
        description = raw_tool.get("description", "")
        if description is None:
            description = ""
        if not isinstance(description, str) or len(description.encode("utf-8")) > self.max_schema_bytes:
            raise MCPProtocolError(f"description for {name!r} exceeds the bounded tool metadata size")
        return MCPToolSpec(name=name, input_schema=dict(input_schema), description=description)

    def call_tool(self, name: str, arguments: Mapping[str, Any] | None = None) -> MCPToolResult:
        self._require_initialized()
        if not isinstance(name, str) or not name or len(name) > 200:
            raise MCPProtocolError("tool name must be a bounded nonempty string")
        if not self._tools:
            raise MCPProtocolError("call tools/list before calling a tool")
        if name not in self._tools:
            raise MCPProtocolError(f"tool {name!r} was not advertised by the MCP server")
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, Mapping):
            raise MCPProtocolError("tool arguments must be an object")
        _json_bytes(arguments, field="tool arguments", max_bytes=self.max_argument_bytes)
        try:
            response = self._request(
                self._allocate_id(),
                "tools/call",
                {"name": name, "arguments": dict(arguments)},
            )
            result = response.get("result")
            if not isinstance(result, Mapping):
                raise MCPProtocolError("tools/call result must be an object")
            _json_bytes(result, field="tools/call result", max_bytes=self.max_page_bytes)
            content = result.get("content")
            if not isinstance(content, list):
                raise MCPProtocolError("tools/call result must contain a content array")
            is_error = result.get("isError", False)
            if not isinstance(is_error, bool):
                raise MCPProtocolError("tools/call isError must be boolean when supplied")
            return MCPToolResult(dict(result))
        except MCPRemoteError:
            # A valid tool-level error (bad address, missing function, etc.)
            # does not corrupt the Radare session; let the investigator try a
            # different static strategy.
            raise
        except Exception:
            self._abort()
            raise

    def _allocate_id(self) -> int:
        value = self._next_id
        self._next_id += 1
        return value

    def _send_notification(self, method: str, params: Mapping[str, Any] | None = None) -> None:
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params:
            message["params"] = dict(params)
        self.transport.send(message)

    def _request(self, request_id: int, method: str, params: Mapping[str, Any]) -> Mapping[str, Any]:
        self.transport.send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": dict(params)})
        deadline = time.monotonic() + self.timeout_seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._cancel_request(request_id, method)
                raise MCPTimeoutError(f"MCP request {method!r} timed out")
            try:
                incoming = self._decode_incoming(self.transport.receive(remaining, self.max_line_bytes))
            except MCPTimeoutError:
                self._cancel_request(request_id, method)
                raise
            if "method" in incoming:
                if "id" in incoming:
                    raise MCPProtocolError("server-initiated MCP requests are not supported")
                self._record_notification(incoming)
                continue
            if "id" not in incoming or not _same_json_id(incoming.get("id"), request_id):
                raise MCPProtocolError(f"MCP response ID mismatch for {method!r}")
            if "result" in incoming and "error" in incoming:
                raise MCPProtocolError("MCP response contains both result and error")
            if "error" in incoming:
                error = incoming["error"]
                if not isinstance(error, Mapping):
                    raise MCPProtocolError("MCP error must be an object")
                raise MCPRemoteError(error.get("code"), str(error.get("message", "unknown error")), error.get("data"))
            if "result" not in incoming:
                raise MCPProtocolError("MCP response contains neither result nor error")
            return incoming

    def _cancel_request(self, request_id: int, method: str) -> None:
        # MCP forbids cancelling initialize. For all other bounded requests,
        # best-effort cancellation lets a cooperative server stop work before
        # the transport is closed by the caller.
        if method == "initialize":
            return
        try:
            self._send_notification(
                "notifications/cancelled",
                {"requestId": request_id, "reason": "request timeout"},
            )
        except Exception:
            pass

    def _decode_incoming(self, value: bytes | str | Mapping[str, Any]) -> Mapping[str, Any]:
        if isinstance(value, Mapping):
            decoded: Any = dict(value)
        elif isinstance(value, bytes):
            if len(value) > self.max_line_bytes:
                raise MCPFrameError(f"MCP frame exceeds the {self.max_line_bytes}-byte bound")
            try:
                text = value.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise MCPFrameError("MCP frame is not valid UTF-8") from exc
            if not text.endswith("\n"):
                raise MCPFrameError("MCP frame must be newline-delimited")
            decoded = self._decode_text(text[:-1])
        elif isinstance(value, str):
            if len(value.encode("utf-8")) > self.max_line_bytes:
                raise MCPFrameError(f"MCP frame exceeds the {self.max_line_bytes}-byte bound")
            if not value.endswith("\n"):
                raise MCPFrameError("MCP frame must be newline-delimited")
            decoded = self._decode_text(value[:-1])
        else:
            raise MCPFrameError("MCP transport returned an unsupported frame type")
        if not isinstance(decoded, Mapping):
            raise MCPFrameError("MCP frame must be one JSON object, not a batch or scalar")
        _json_bytes(decoded, field="MCP frame", max_bytes=self.max_line_bytes)
        if decoded.get("jsonrpc") != "2.0":
            raise MCPProtocolError("MCP frame must declare jsonrpc 2.0")
        if "id" in decoded and isinstance(decoded.get("id"), (dict, list)):
            raise MCPProtocolError("MCP request/response ID must be a scalar")
        return dict(decoded)

    @staticmethod
    def _decode_text(text: str) -> Any:
        if not text:
            raise MCPFrameError("MCP frame is empty")
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise MCPFrameError("MCP frame is not valid JSON") from exc

    def _record_notification(self, message: Mapping[str, Any]) -> None:
        if len(self._notifications) >= self.max_notifications:
            return
        # Keep a detached bounded JSON value; callers must still treat it as
        # hostile server data and must not feed it to the model as instructions.
        try:
            encoded = _json_bytes(message, field="MCP notification", max_bytes=self.max_line_bytes)
            self._notifications.append(json.loads(encoded))
        except MCPError:
            raise

    def _require_initialized(self) -> None:
        if not self._initialized:
            raise MCPProtocolError("MCP client is not initialized")

    def _abort(self) -> None:
        try:
            self.close(grace_timeout=0.2)
        except Exception:
            pass

    def close(self, grace_timeout: float = 1.0) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            try:
                parameters = inspect.signature(self.transport.close).parameters
            except (TypeError, ValueError):
                parameters = {"grace_timeout": object()}
            if parameters:
                self.transport.close(grace_timeout)
            else:
                self.transport.close()
        finally:
            self._started = False
            self._initialized = False

    def __enter__(self) -> "MCPClient":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()


__all__ = [
    "MCP_PROTOCOL_VERSION",
    "MCPError",
    "MCPTransportError",
    "MCPProtocolError",
    "MCPFrameError",
    "MCPTimeoutError",
    "MCPRemoteError",
    "MCPToolSpec",
    "MCPToolResult",
    "Transport",
    "MCPTransport",
    "DockerExecMCPTransport",
    "MCPClient",
]
