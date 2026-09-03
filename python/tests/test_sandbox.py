import io
import os
import subprocess
import unittest
from unittest import mock

from jaq_investigator.sandbox import (
    DockerStaticSandbox,
    SandboxConfigurationError,
    SandboxExecutionError,
)


class FakeProcess:
    def __init__(self, *, stdout=b"out", stderr=b"err", returncode=0, wait_side_effect=None, pid=None):
        self.stdin = io.BytesIO()
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.returncode = returncode
        self.pid = pid
        self.wait_side_effect = list(wait_side_effect or [])
        self.terminated = False
        self.killed = False

    def wait(self, timeout=None):
        if self.wait_side_effect:
            value = self.wait_side_effect.pop(0)
            if isinstance(value, BaseException):
                raise value
            return value
        return self.returncode

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15

    def kill(self):
        self.killed = True
        self.returncode = -9


class SandboxTests(unittest.TestCase):
    def test_arbitrary_command_is_one_container_argv_and_not_host_shell(self):
        process = FakeProcess()
        with mock.patch("jaq_investigator.sandbox.subprocess.Popen", return_value=process) as popen:
            result = DockerStaticSandbox("jaq-static").run(
                "python3 -c 'print(1)' && objdump -x sample.exe",
                timeout_seconds=3,
                max_output_bytes=1000,
            )
        argv = popen.call_args.args[0]
        self.assertEqual(
            argv,
            [
                "docker",
                "exec",
                "--workdir",
                "/work",
                "jaq-static",
                "timeout",
                "--signal=TERM",
                "--kill-after=1s",
                "3.0",
                "/bin/bash",
                "-lc",
                "set -o pipefail\npython3 -c 'print(1)' && objdump -x sample.exe",
            ],
        )
        self.assertFalse(popen.call_args.kwargs["shell"])
        self.assertEqual(result.stdout, "out")
        self.assertEqual(result.stderr, "err")
        self.assertTrue(result.ok)
        self.assertNotIn("DEEPSEEK_API_KEY", popen.call_args.kwargs["env"])

    def test_pipefail_prevents_analyzer_errors_from_being_masked(self):
        sandbox = DockerStaticSandbox("jaq-static")
        argv = sandbox._command_argv("analyzer sample.exe 2>&1 | head -100", 30.0)
        self.assertEqual(argv[-1], "set -o pipefail\nanalyzer sample.exe 2>&1 | head -100")

    def test_output_is_bounded_across_concurrent_stdout_and_stderr(self):
        process = FakeProcess(stdout=b"1234567890", stderr=b"abcdefghij")
        with mock.patch("jaq_investigator.sandbox.subprocess.Popen", return_value=process):
            result = DockerStaticSandbox("jaq-static").run("file sample.exe", max_output_bytes=10)
        self.assertLessEqual(len(result.stdout.encode()) + len(result.stderr.encode()), 10)
        self.assertTrue(result.truncated)

    def test_timeout_terminates_process_and_returns_stable_result(self):
        process = FakeProcess(
            stdout=b"partial",
            stderr=b"waiting",
            returncode=-15,
            wait_side_effect=[subprocess.TimeoutExpired("docker", 1), None],
            pid=None,
        )
        with mock.patch("jaq_investigator.sandbox.subprocess.Popen", return_value=process):
            result = DockerStaticSandbox("jaq-static").run("python3 long_static.py", timeout_seconds=1)
        self.assertTrue(result.timed_out)
        self.assertFalse(result.ok)
        self.assertTrue(process.terminated or process.killed)

    def test_container_and_bounds_are_validated(self):
        with self.assertRaises(SandboxConfigurationError):
            DockerStaticSandbox("../host")
        sandbox = DockerStaticSandbox("jaq-static")
        with self.assertRaises(SandboxConfigurationError):
            sandbox.run("true", timeout_seconds=0)
        with self.assertRaises(SandboxConfigurationError):
            sandbox.run("true", max_output_bytes=0)
        with self.assertRaises(SandboxConfigurationError):
            sandbox.run("\x00")
        with self.assertRaises(SandboxConfigurationError):
            sandbox.write_file("../outside.py", "x")

    def test_write_and_read_helpers_use_relative_work_paths(self):
        processes = [FakeProcess(returncode=0), FakeProcess(stdout=b"hello", returncode=0)]
        with mock.patch("jaq_investigator.sandbox.subprocess.Popen", side_effect=processes) as popen:
            write_result = DockerStaticSandbox("jaq-static").write_file("scratch/a.py", "print(1)")
            read_result = DockerStaticSandbox("jaq-static").read_file("scratch/a.py", max_bytes=100)
        self.assertTrue(write_result.ok)
        self.assertEqual(read_result.stdout, "hello")
        self.assertEqual(popen.call_args_list[0].args[0][4], "jaq-static")
        self.assertEqual(popen.call_args_list[1].args[0][4], "jaq-static")
        self.assertIn("scratch/a.py", popen.call_args_list[1].args[0][-1])

    def test_start_failure_is_normalized(self):
        with mock.patch(
            "jaq_investigator.sandbox.subprocess.Popen",
            side_effect=OSError("docker missing"),
        ):
            with self.assertRaises(SandboxExecutionError):
                DockerStaticSandbox("jaq-static").run("true")

    def test_close_prevents_reuse(self):
        sandbox = DockerStaticSandbox("jaq-static")
        sandbox.close()
        with self.assertRaises(SandboxExecutionError):
            sandbox.run("true")


if __name__ == "__main__":
    unittest.main()
