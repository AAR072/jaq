from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from jaq_investigator.evidence import EvidenceStore
from jaq_investigator.mcp_client import MCPToolResult, MCPToolSpec
from jaq_investigator.runtime import StaticToolRuntime, _R2_FACADES
from jaq_investigator.sandbox import SandboxResult
from jaq_investigator.schemas import Observation


class FakeMCP:
    def __init__(self, *, version="1.8.6", open_error=False, missing_tool=None):
        self.calls = []
        self.closed = False
        self.version = version
        self.open_error = open_error
        self.missing_tool = missing_tool

    def initialize(self):
        return {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "r2mcp", "version": self.version}}

    def list_tools(self):
        names = {"open_file", *(item[0] for item in _R2_FACADES.values())}
        names.discard(self.missing_tool)
        return tuple(MCPToolSpec(name, {"type": "object"}) for name in sorted(names))

    def call_tool(self, name, arguments):
        self.calls.append((name, dict(arguments)))
        return MCPToolResult({
            "content": [{"type": "text", "text": f"{name}:ok"}],
            "structuredContent": {"name": name},
            "isError": self.open_error and name == "open_file",
        })

    def close(self):
        self.closed = True


class FakeSandbox:
    def __init__(self):
        self.commands = []
        self.closed = False

    def run(self, command, timeout_seconds=60, max_output_bytes=65536):
        self.commands.append(command)
        stdout = "radare2 6.2.0 0 @ linux-x86-64\n" if command == "radare2 -v" else "decoded"
        return SandboxResult(command, ("docker", "exec"), 0, stdout, "", 0.01)

    def close(self):
        self.closed = True


class BrokenCapaSandbox(FakeSandbox):
    def run(self, command, timeout_seconds=60, max_output_bytes=65536):
        if "capa --version" in command:
            self.commands.append(command)
            return SandboxResult(
                command, ("docker", "exec"), 0,
                "ERROR capa: default embedded rules not found!\n", "", 0.01,
            )
        return super().run(command, timeout_seconds, max_output_bytes)


class RuntimeTest(unittest.TestCase):
    def store(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "observations.jsonl"
        observation = Observation(
            id="obs-native", type="artifact.hash.sha256", raw_value="a" * 64,
            normalized_value="a" * 64,
            artifact_location={"artifact": "sample"},
            analyzer={"name": "jaq-pe", "version": "0.1.0"},
            provenance={"source": "fixture"},
        )
        path.write_text(json.dumps(observation.to_dict()) + "\n", encoding="utf-8")
        return EvidenceStore(path), path

    def test_tool_results_are_persisted_before_return(self):
        store, path = self.store()
        mcp, sandbox = FakeMCP(), FakeSandbox()
        runtime = StaticToolRuntime(
            container="jaq-sandbox-test", evidence=store, sample_sha256="a" * 64,
            radare_version="6.2.0", mcp_version="1.8.6", mcp_client=mcp, sandbox=sandbox,
        )
        radare = runtime.execute("r2_show_info", {})
        command = runtime.execute("run_static_command", {"command": "python3 -c 'print(1)'"})
        self.assertTrue(store.get(radare["observation_id"]))
        self.assertTrue(store.get(command["observation_id"]))
        lines = path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 13)  # native + request/result for version, capa, Go profile, open, r2, command
        self.assertEqual(mcp.calls[0], ("open_file", {"file_path": "/input/sample.exe"}))
        self.assertEqual(sandbox.commands, [
            "radare2 -v",
            "test $(find /opt/jaq/capa-rules -type f -name '*.yml' | wc -l) -ge 1000 && test $(find /opt/jaq/capa-signatures -type f -name '*.sig' | wc -l) -eq 3 && capa --version",
            "go-profile /input/sample.exe",
            "python3 -c 'print(1)'",
        ])
        runtime.close()
        self.assertTrue(mcp.closed and sandbox.closed)

    def test_model_tool_catalog_uses_project_descriptions(self):
        store, _ = self.store()
        runtime = StaticToolRuntime(
            container="jaq-sandbox-test", evidence=store, sample_sha256="a" * 64,
            radare_version="6.2.0", mcp_version="1.8.6", mcp_client=FakeMCP(), sandbox=FakeSandbox(),
        )
        tools = runtime.model_tools()
        names = {tool["function"]["name"] for tool in tools}
        self.assertIn("run_static_command", names)
        self.assertIn("r2_decompile_function", names)
        self.assertNotIn("run_command", names)
        runtime.close()

    def test_fatal_capa_diagnostic_is_error_even_with_zero_exit(self):
        store, _ = self.store()
        sandbox = BrokenCapaSandbox()
        with self.assertRaisesRegex(RuntimeError, "capa health check failed"):
            StaticToolRuntime(
                container="jaq-sandbox-test", evidence=store, sample_sha256="a" * 64,
                radare_version="6.2.0", mcp_version="1.8.6",
                mcp_client=FakeMCP(), sandbox=sandbox,
            )
        capa_results = [
            item for item in store.observations
            if item.metadata.get("tool_name") == "capa_health_check" and item.type.endswith("tool_result")
        ]
        self.assertEqual(len(capa_results), 1)
        self.assertEqual(capa_results[0].metadata["status"], "error")
        self.assertTrue(sandbox.closed)

    def test_tool_arguments_are_strictly_typed_and_bounded(self):
        store, _ = self.store()
        runtime = StaticToolRuntime(
            container="jaq-sandbox-test", evidence=store, sample_sha256="a" * 64,
            radare_version="6.2.0", mcp_version="1.8.6", mcp_client=FakeMCP(), sandbox=FakeSandbox(),
        )
        invalid = (
            ("r2_analyze", {"level": True}),
            ("r2_analyze", {"timeout_seconds": 121}),
            ("r2_search", {"query": "x", "type": "regex"}),
            ("run_static_command", {"command": 7}),
            ("run_static_command", {"command": "true", "max_output_bytes": 0}),
        )
        for name, arguments in invalid:
            with self.subTest(name=name, arguments=arguments):
                with self.assertRaises(ValueError):
                    runtime.execute(name, arguments)
        runtime.close()

    def test_initialization_failure_closes_runtime_dependencies(self):
        for mcp in (
            FakeMCP(version="unexpected"),
            FakeMCP(missing_tool="open_file"),
            FakeMCP(open_error=True),
        ):
            with self.subTest(version=mcp.version, missing=mcp.missing_tool, open_error=mcp.open_error):
                store, _ = self.store()
                sandbox = FakeSandbox()
                with self.assertRaises(RuntimeError):
                    StaticToolRuntime(
                        container="jaq-sandbox-test", evidence=store, sample_sha256="a" * 64,
                        radare_version="6.2.0", mcp_version="1.8.6", mcp_client=mcp, sandbox=sandbox,
                    )
                self.assertTrue(mcp.closed and sandbox.closed)


if __name__ == "__main__":
    unittest.main()
