"""Controller-bound Radare2 MCP and arbitrary static-command runtime."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import math
import os
import time
from typing import Any

from .evidence import EvidenceStore
from .mcp_client import DockerExecMCPTransport, MCPClient
from .sandbox import DockerStaticSandbox


_EMPTY = {"type": "object", "additionalProperties": False, "properties": {}}
_ADDRESS_PAGE = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "address": {"type": "string", "minLength": 1, "maxLength": 128},
        "cursor": {"type": "string", "maxLength": 512},
        "page_size": {"type": "integer", "minimum": 1, "maximum": 200},
    },
    "required": ["address"],
}
_ADDRESS_ONLY = {
    "type": "object",
    "additionalProperties": False,
    "properties": {"address": {"type": "string", "minLength": 1, "maxLength": 128}},
    "required": ["address"],
}
_LIST = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "cursor": {"type": "string", "maxLength": 512},
        "page_size": {"type": "integer", "minimum": 1, "maximum": 200},
        "count": {"type": "boolean"},
    },
}


def _tool(name: str, description: str, schema: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {"name": name, "description": description, "parameters": dict(schema)},
    }


_R2_FACADES: dict[str, tuple[str, str, Mapping[str, Any]]] = {
    "r2_show_info": ("show_info", "Return Radare2 metadata for the fixed PE.", _EMPTY),
    "r2_analyze": (
        "analyze",
        "Run or deepen Radare2 static analysis for the fixed PE.",
        {
            "type": "object", "additionalProperties": False,
            "properties": {
                "level": {"type": "integer", "minimum": 0, "maximum": 4},
                "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 120},
            },
        },
    ),
    "r2_list_functions": (
        "list_functions", "List functions recovered by the current static analysis state.",
        {
            "type": "object", "additionalProperties": False,
            "properties": {
                "only_named": {"type": "boolean"}, "count": {"type": "boolean"},
                "start": {"type": "integer", "minimum": 0},
                "max_length": {"type": "integer", "minimum": 1, "maximum": 500},
            },
        },
    ),
    "r2_list_functions_tree": ("list_functions_tree", "List recovered functions and successors.", _LIST),
    "r2_list_imports": ("list_imports", "List imported symbols.", _LIST),
    "r2_list_exports": ("list_exports", "List exported symbols.", _LIST),
    "r2_list_libraries": ("list_libraries", "List linked libraries.", _LIST),
    "r2_list_sections": ("list_sections", "List PE sections and permissions.", _LIST),
    "r2_list_symbols": ("list_symbols", "List symbols and addresses.", _LIST),
    "r2_list_entrypoints": ("list_entrypoints", "List entry points and constructors.", _EMPTY),
    "r2_list_strings": ("list_strings", "List strings recovered from data sections.", _LIST),
    "r2_list_all_strings": ("list_all_strings", "Scan the complete PE for strings.", _LIST),
    "r2_get_function_prototype": ("get_function_prototype", "Get a function prototype by address.", _ADDRESS_ONLY),
    "r2_decompile_function": ("decompile_function", "Decompile one selected function.", _ADDRESS_PAGE),
    "r2_disassemble_function": ("disassemble_function", "Disassemble one selected function.", _ADDRESS_PAGE),
    "r2_disassemble": (
        "disassemble", "Disassemble instructions at an address without trusting function boundaries.",
        {
            "type": "object", "additionalProperties": False,
            "properties": {
                "address": {"type": "string", "minLength": 1, "maxLength": 128},
                "num_instructions": {"type": "integer", "minimum": 1, "maximum": 500},
            }, "required": ["address"],
        },
    ),
    "r2_xrefs_to": ("xrefs_to", "Find structured cross-references to an address.", _ADDRESS_ONLY),
    "r2_lookup_address": ("lookup_address", "Describe the symbol or object at an address.", _ADDRESS_ONLY),
    "r2_lookup_export": (
        "lookup_export", "Resolve an export name.",
        {"type": "object", "additionalProperties": False, "properties": {"name": {"type": "string", "minLength": 1, "maxLength": 256}}, "required": ["name"]},
    ),
    "r2_lookup_symbol": ("lookup_symbol", "Resolve an address to a symbol.", _ADDRESS_ONLY),
    "r2_hexdump": (
        "hexdump", "Read bounded bytes from the fixed PE through Radare2.",
        {"type": "object", "additionalProperties": False, "properties": {"address": {"type": "string", "minLength": 1, "maxLength": 128}, "size": {"type": "string", "minLength": 1, "maxLength": 32}}, "required": ["address", "size"]},
    ),
    "r2_search": (
        "search", "Search the fixed PE for a bounded string, hex, wide, or numeric value.",
        {
            "type": "object", "additionalProperties": False,
            "properties": {
                "query": {"type": "string", "minLength": 1, "maxLength": 512},
                "type": {"type": "string", "enum": ["string", "hex", "wide", "value"]},
                "value_size": {"type": "integer", "enum": [1, 2, 4, 8]},
            }, "required": ["query"],
        },
    ),
}

_R2MCP_FLAGS: tuple[str, ...] = (
    "-n", "-N", "-C", "structured", "-s", "/input", "-g", "disk",
    *sum((("-e", official) for official, _, _ in _R2_FACADES.values()), ()),
    "-e", "open_file",
)

_COMMAND_TOOL = _tool(
    "run_static_command",
    "Run an arbitrary offline shell command inside /work in the disposable static sandbox.",
    {
        "type": "object", "additionalProperties": False,
        "properties": {
            "command": {"type": "string", "minLength": 1, "maxLength": 65536},
            "timeout_seconds": {"type": "number", "minimum": 1, "maximum": 600},
            "max_output_bytes": {"type": "integer", "minimum": 1, "maximum": 4194304},
        },
        "required": ["command"],
    },
)

_STATIC_FATAL_DIAGNOSTICS = (
    "capa: default embedded rules not found",
    "capa: provide your own rule set",
)


class StaticToolRuntime:
    """Persist-before-return facade over one r2mcp session and shell sandbox."""

    def __init__(
        self,
        *,
        container: str,
        evidence: EvidenceStore,
        sample_sha256: str,
        radare_version: str,
        mcp_version: str,
        mcp_client: MCPClient | None = None,
        sandbox: DockerStaticSandbox | None = None,
    ) -> None:
        self.container = container
        self.evidence = evidence
        self.sample_sha256 = sample_sha256
        self.radare_version = radare_version
        self.mcp_version = mcp_version
        self.mcp = mcp_client or MCPClient(
            DockerExecMCPTransport(container, flags=_R2MCP_FLAGS), timeout_seconds=130
        )
        self.sandbox = sandbox or DockerStaticSandbox(container)
        self.sequence = 0
        self._closed = False
        try:
            self._initialize()
        except Exception:
            self.close()
            raise

    @classmethod
    def from_environment(cls, evidence: EvidenceStore) -> "StaticToolRuntime":
        values = {
            "container": os.environ.get("JAQ_SANDBOX_CONTAINER", ""),
            "sample_sha256": os.environ.get("JAQ_SAMPLE_SHA256", ""),
            "radare_version": os.environ.get("JAQ_RADARE2_VERSION", ""),
            "mcp_version": os.environ.get("JAQ_R2MCP_VERSION", ""),
        }
        if not all(values.values()):
            raise RuntimeError("controller did not configure the static tool runtime")
        return cls(evidence=evidence, **values)

    def _initialize(self) -> None:
        initialized = self.mcp.initialize()
        server_info = initialized.get("serverInfo")
        if not isinstance(server_info, Mapping) or server_info.get("version") != self.mcp_version:
            actual = server_info.get("version") if isinstance(server_info, Mapping) else None
            raise RuntimeError(
                f"r2mcp version mismatch: expected {self.mcp_version!r}, got {actual!r}"
            )
        advertised = {tool.name for tool in self.mcp.list_tools()}
        required = {"open_file", *(item[0] for item in _R2_FACADES.values())}
        missing = sorted(required - advertised)
        if missing:
            raise RuntimeError("r2mcp is missing required tools: " + ", ".join(missing))
        version_probe = self._execute_recorded(
            "static-sandbox",
            "verify_radare2_version",
            {"command": "radare2 -v", "timeout_seconds": 10, "max_output_bytes": 4096},
        )
        version_result = version_probe.get("untrusted_static_result")
        stdout = version_result.get("stdout") if isinstance(version_result, Mapping) else None
        if version_probe.get("status") != "ok" or not isinstance(stdout, str) or not stdout.startswith(
            f"radare2 {self.radare_version}"
        ):
            raise RuntimeError(f"radare2 version mismatch: expected {self.radare_version!r}")
        # Verify the immutable image's pinned capa assets before any provider
        # call. Per-sample scans remain investigator-directed because very
        # large obfuscated binaries can take minutes; scan failures are still
        # recorded and cannot become negative evidence.
        capa_health = self._execute_recorded(
            "static-sandbox",
            "capa_health_check",
            {
                "command": (
                    "test $(find /opt/jaq/capa-rules -type f -name '*.yml' | wc -l) -ge 1000 "
                    "&& test $(find /opt/jaq/capa-signatures -type f -name '*.sig' | wc -l) -eq 3 "
                    "&& capa --version"
                ),
                "timeout_seconds": 30,
                "max_output_bytes": 4096,
            },
        )
        if capa_health.get("status") != "ok":
            raise RuntimeError("capa health check failed before model analysis")
        self._execute_recorded(
            "static-sandbox",
            "go_profile_static_scan",
            {
                "command": "go-profile /input/sample.exe",
                "timeout_seconds": 120,
                "max_output_bytes": 2_097_152,
            },
        )
        opened = self._execute_recorded(
            "radare2-mcp", "open_file", {"file_path": "/input/sample.exe"}
        )
        if opened.get("status") != "ok":
            raise RuntimeError("r2mcp could not open the controller-mounted PE")

    def model_tools(self) -> Sequence[Mapping[str, Any]]:
        tools = [_tool(name, description, schema) for name, (_, description, schema) in _R2_FACADES.items()]
        tools.append(_COMMAND_TOOL)
        return tuple(tools)

    @staticmethod
    def _validate_arguments(schema: Mapping[str, Any], arguments: Mapping[str, Any]) -> None:
        if not isinstance(arguments, Mapping):
            raise ValueError("tool arguments must be an object")
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        unknown = set(arguments) - set(properties)
        missing = set(required) - set(arguments)
        if unknown or missing:
            raise ValueError(f"invalid tool fields: missing={sorted(missing)} unknown={sorted(unknown)}")
        for field, value in arguments.items():
            StaticToolRuntime._validate_value(field, value, properties[field])

    @staticmethod
    def _validate_value(field: str, value: Any, schema: Mapping[str, Any]) -> None:
        expected = schema.get("type")
        if expected == "string":
            valid_type = isinstance(value, str)
        elif expected == "integer":
            valid_type = isinstance(value, int) and not isinstance(value, bool)
        elif expected == "number":
            valid_type = (
                isinstance(value, (int, float))
                and not isinstance(value, bool)
                and math.isfinite(float(value))
            )
        elif expected == "boolean":
            valid_type = isinstance(value, bool)
        elif expected == "object":
            valid_type = isinstance(value, Mapping)
        else:
            raise ValueError(f"unsupported controller schema for {field!r}")
        if not valid_type:
            raise ValueError(f"tool field {field!r} must be {expected}")
        if isinstance(value, str):
            if len(value) < int(schema.get("minLength", 0)):
                raise ValueError(f"tool field {field!r} is too short")
            if "maxLength" in schema and len(value) > int(schema["maxLength"]):
                raise ValueError(f"tool field {field!r} is too long")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if "minimum" in schema and value < schema["minimum"]:
                raise ValueError(f"tool field {field!r} is below its minimum")
            if "maximum" in schema and value > schema["maximum"]:
                raise ValueError(f"tool field {field!r} exceeds its maximum")
        if "enum" in schema and value not in schema["enum"]:
            raise ValueError(f"tool field {field!r} is not an allowed value")

    def execute(self, name: str, arguments: Mapping[str, Any]) -> Mapping[str, Any]:
        if self._closed:
            raise RuntimeError("static tool runtime is closed")
        if name == "run_static_command":
            schema = _COMMAND_TOOL["function"]["parameters"]
            self._validate_arguments(schema, arguments)
            return self._execute_recorded("static-sandbox", name, arguments)
        facade = _R2_FACADES.get(name)
        if facade is None:
            raise ValueError(f"unknown static tool {name!r}")
        official, _, schema = facade
        self._validate_arguments(schema, arguments)
        return self._execute_recorded("radare2-mcp", official, arguments, model_name=name)

    def _execute_recorded(
        self,
        source: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        *,
        model_name: str | None = None,
    ) -> Mapping[str, Any]:
        self.sequence += 1
        version = self.mcp_version if source == "radare2-mcp" else "1.0"
        request = self.evidence.append_tool_request(
            source=source, version=version, tool_name=model_name or tool_name,
            arguments=arguments, sample_sha256=self.sample_sha256, sequence=self.sequence,
        )
        started = time.monotonic()
        status = "ok"
        truncated = False
        exit_code: int | None = None
        try:
            if source == "radare2-mcp":
                raw = self.mcp.call_tool(tool_name, arguments).to_dict()
                if raw.get("isError") is True:
                    status = "error"
            else:
                result = self.sandbox.run(
                    arguments["command"],
                    timeout_seconds=arguments.get("timeout_seconds", 60),
                    max_output_bytes=arguments.get("max_output_bytes", 65536),
                )
                raw = {
                    "returncode": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "timed_out": result.timed_out,
                    "truncated": result.truncated,
                }
                truncated = result.truncated
                exit_code = result.returncode
                status = "timeout" if result.timed_out else ("ok" if result.ok else "error")
                diagnostic = (result.stdout + "\n" + result.stderr).casefold()
                if any(marker in diagnostic for marker in _STATIC_FATAL_DIAGNOSTICS):
                    status = "error"
        except Exception as exc:
            raw = {"error": exc.__class__.__name__, "message": str(exc)[:500]}
            status = "error"
        duration_ms = int((time.monotonic() - started) * 1000)
        observation = self.evidence.append_tool_result(
            request_id=request.id, source=source, version=version,
            tool_name=model_name or tool_name, result=raw,
            sample_sha256=self.sample_sha256, sequence=self.sequence,
            status=status, duration_ms=duration_ms, truncated=truncated, exit_code=exit_code,
        )
        return {
            "observation_id": observation.id,
            "status": status,
            "untrusted_static_result": raw,
        }

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self.mcp.close()
        finally:
            self.sandbox.close()


__all__ = ["StaticToolRuntime"]
