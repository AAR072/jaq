"""Bounded command execution through a fixed Docker static-analysis sandbox.

The model may provide an arbitrary shell *string* to ``run`` by design.  The
string is still passed as one argument to a container-side ``/bin/bash -lc``;
the host never parses it and the host process never runs it directly.  The
controller must supply a rootless, network-disabled, disposable JAQ
container.  This module deliberately exposes no dynamic-analysis-specific
API.
"""

from __future__ import annotations

from dataclasses import dataclass
import base64
import math
import os
from pathlib import PurePosixPath
import signal
import shlex
import subprocess
import threading
import time
from typing import Any, Mapping, Sequence

from .mcp_client import _validate_container_name


DEFAULT_TIMEOUT_SECONDS = 60.0
DEFAULT_MAX_OUTPUT_BYTES = 64 << 10
MAX_COMMAND_CHARS = 64 << 10
MAX_TIMEOUT_SECONDS = 600.0
MAX_OUTPUT_BYTES = 4 << 20
MAX_SCRATCH_PATH_CHARS = 512
MAX_WRITE_BYTES = 32 << 10


class SandboxError(RuntimeError):
    """Base error for sandbox setup and execution failures."""


class SandboxConfigurationError(SandboxError, ValueError):
    """The controller supplied an invalid container or bound."""


class SandboxExecutionError(SandboxError):
    """The fixed Docker command could not be started."""


@dataclass(frozen=True)
class SandboxResult:
    """Stable bounded result returned by one container command."""

    command: str
    argv: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    truncated: bool = False

    @property
    def exit_code(self) -> int | None:
        return self.returncode

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    @property
    def output_truncated(self) -> bool:
        return self.truncated

    @property
    def duration_ms(self) -> int:
        return int(round(self.duration_seconds * 1000))

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "argv": list(self.argv),
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_seconds": self.duration_seconds,
            "timed_out": self.timed_out,
            "truncated": self.truncated,
        }


class _OutputCollector:
    """Collect both streams under one byte budget while readers keep draining."""

    def __init__(self, max_bytes: int) -> None:
        self.max_bytes = max_bytes
        self._lock = threading.Lock()
        self._total = 0
        self._buffers = {"stdout": bytearray(), "stderr": bytearray()}
        self.truncated = False

    def append(self, stream_name: str, chunk: bytes) -> None:
        if not chunk:
            return
        with self._lock:
            remaining = self.max_bytes - self._total
            if remaining <= 0:
                self.truncated = True
                return
            accepted = chunk[:remaining]
            self._buffers[stream_name].extend(accepted)
            self._total += len(accepted)
            if len(accepted) < len(chunk):
                self.truncated = True

    def text(self, stream_name: str) -> str:
        return bytes(self._buffers[stream_name]).decode("utf-8", errors="replace")


class DockerStaticSandbox:
    """Run controller-mediated shell commands only inside one JAQ container."""

    def __init__(
        self,
        container: str,
        *,
        docker_binary: str = "docker",
        max_command_chars: int = MAX_COMMAND_CHARS,
    ) -> None:
        try:
            self.container = _validate_container_name(container)
        except ValueError as exc:
            raise SandboxConfigurationError(str(exc)) from exc
        if (
            not isinstance(docker_binary, str)
            or not docker_binary
            or "\x00" in docker_binary
            or "\r" in docker_binary
            or "\n" in docker_binary
        ):
            raise SandboxConfigurationError("docker_binary must be a fixed executable name")
        if isinstance(max_command_chars, bool) or not isinstance(max_command_chars, int) or max_command_chars < 1:
            raise SandboxConfigurationError("max_command_chars must be positive")
        self.docker_binary = docker_binary
        self.max_command_chars = max_command_chars
        self._closed = False

    @staticmethod
    def _validate_timeout(value: float) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise SandboxConfigurationError("timeout_seconds must be a number")
        timeout = float(value)
        if not math.isfinite(timeout) or timeout <= 0 or timeout > MAX_TIMEOUT_SECONDS:
            raise SandboxConfigurationError(
                f"timeout_seconds must be between 0 and {MAX_TIMEOUT_SECONDS}"
            )
        return timeout

    @staticmethod
    def _validate_output_bound(value: int) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > MAX_OUTPUT_BYTES:
            raise SandboxConfigurationError(
                f"max_output_bytes must be between 1 and {MAX_OUTPUT_BYTES}"
            )
        return value

    def _command_argv(self, command: str, timeout: float) -> tuple[str, ...]:
        return (
            self.docker_binary,
            "exec",
            "--workdir",
            "/work",
            self.container,
            "timeout",
            "--signal=TERM",
            "--kill-after=1s",
            str(timeout),
            "/bin/bash",
            "-lc",
            "set -o pipefail\n" + command,
        )

    def run(
        self,
        command: str,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    ) -> SandboxResult:
        """Run one arbitrary static command inside the fixed container.

        ``command`` is deliberately not parsed or restricted here.  It is a
        single argv element after the fixed container-side shell and cannot
        become a host shell command.  The higher-level agent is responsible
        for deciding which static utilities to offer to a model.
        """

        if self._closed:
            raise SandboxExecutionError("static sandbox is closed")
        if not isinstance(command, str) or not command or "\x00" in command:
            raise SandboxConfigurationError("command must be a nonempty string without NUL")
        if len(command.encode("utf-8")) > self.max_command_chars:
            raise SandboxConfigurationError(
                f"command exceeds the {self.max_command_chars}-character bound"
            )
        timeout = self._validate_timeout(timeout_seconds)
        output_bound = self._validate_output_bound(max_output_bytes)
        argv = self._command_argv(command, timeout)
        # The Docker client gets a minimal environment. No provider key or
        # model credential is forwarded to the container.
        safe_env = {"PATH": os.environ.get("PATH", os.defpath), "LC_ALL": "C.UTF-8"}
        for name in ("HOME", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "XDG_CONFIG_HOME"):
            value = os.environ.get(name)
            if value:
                safe_env[name] = value
        started = time.monotonic()
        try:
            process = subprocess.Popen(
                list(argv),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
                start_new_session=True,
                env=safe_env,
            )
        except OSError as exc:
            raise SandboxExecutionError("could not start docker static sandbox command") from exc

        collector = _OutputCollector(output_bound)
        readers: list[threading.Thread] = []
        for stream_name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            if stream is None:
                continue
            reader = threading.Thread(
                target=self._read_stream,
                args=(stream_name, stream, collector),
                name=f"jaq-sandbox-{stream_name}",
                daemon=True,
            )
            reader.start()
            readers.append(reader)

        timed_out = False
        try:
            process.wait(timeout=timeout + 0.5)
        except subprocess.TimeoutExpired:
            timed_out = True
            self._terminate_process(process)
        except OSError:
            timed_out = True
            self._terminate_process(process)
        for reader in readers:
            reader.join(timeout=1.0)
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except (OSError, ValueError):
                    pass
        returncode = process.poll()
        if returncode is None:
            returncode = getattr(process, "returncode", None)
        # GNU/coreutils timeout uses 124 for a command that exceeded its
        # deadline. Keep this marker even when the outer Docker client exits
        # normally after the inner timeout terminates the command.
        if returncode == 124:
            timed_out = True
        duration = round(max(0.0, time.monotonic() - started), 6)
        return SandboxResult(
            command=command,
            argv=argv,
            returncode=returncode,
            stdout=collector.text("stdout"),
            stderr=collector.text("stderr"),
            duration_seconds=duration,
            timed_out=timed_out,
            truncated=collector.truncated,
        )

    @staticmethod
    def _read_stream(stream_name: str, stream: Any, collector: _OutputCollector) -> None:
        while True:
            try:
                chunk = stream.read(4096)
            except (OSError, ValueError):
                return
            if not chunk:
                return
            if isinstance(chunk, str):
                chunk = chunk.encode("utf-8", errors="replace")
            if isinstance(chunk, (bytes, bytearray)):
                collector.append(stream_name, bytes(chunk))

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

    @staticmethod
    def _validate_scratch_path(relative_path: str) -> str:
        if (
            not isinstance(relative_path, str)
            or not relative_path
            or len(relative_path) > MAX_SCRATCH_PATH_CHARS
            or "\x00" in relative_path
            or "\\" in relative_path
        ):
            raise SandboxConfigurationError("scratch path must be a bounded relative POSIX path")
        path = PurePosixPath(relative_path)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise SandboxConfigurationError("scratch path must stay below /work")
        return str(path)

    def write_file(
        self,
        relative_path: str,
        content: str,
        *,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> SandboxResult:
        """Write bounded UTF-8 text into scratch using a generated command."""

        path = self._validate_scratch_path(relative_path)
        if not isinstance(content, str) or len(content.encode("utf-8")) > MAX_WRITE_BYTES:
            raise SandboxConfigurationError(f"content exceeds the {MAX_WRITE_BYTES}-byte bound")
        encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
        parent = str(PurePosixPath(path).parent)
        command = (
            f"mkdir -p -- {shlex.quote(parent)} && "
            f"printf %s {shlex.quote(encoded)} | base64 -d > {shlex.quote(path)}"
        )
        return self.run(command, timeout_seconds=timeout_seconds, max_output_bytes=4096)

    def read_file(
        self,
        relative_path: str,
        max_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
        *,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> SandboxResult:
        """Read bounded scratch data through the fixed container command."""

        path = self._validate_scratch_path(relative_path)
        max_bytes = self._validate_output_bound(max_bytes)
        command = f"head -c {max_bytes:d} -- {shlex.quote(path)}"
        return self.run(command, timeout_seconds=timeout_seconds, max_output_bytes=max_bytes)

    def close(self) -> None:
        # The sandbox is a per-run command facade; Docker commands are
        # individually reaped, so close only prevents accidental reuse.
        self._closed = True


__all__ = [
    "DEFAULT_TIMEOUT_SECONDS",
    "DEFAULT_MAX_OUTPUT_BYTES",
    "MAX_COMMAND_CHARS",
    "SandboxError",
    "SandboxConfigurationError",
    "SandboxExecutionError",
    "SandboxResult",
    "DockerStaticSandbox",
]
