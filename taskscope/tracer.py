"""
tracer.py - OS-level and Runtime Execution Tracing for TaskScope-TUI.

Captures the Execution Closure (files, configs, caches, and subprocesses)
touched during command execution using `strace` on Linux, with a graceful
fallback tracer for non-Linux or unprivileged environments.
"""

import os
import re
import shlex
import shutil
import subprocess
import tempfile
import sys
from dataclasses import dataclass, field
from typing import List, Set, Optional, Dict, Any


@dataclass
class ExecutionTrace:
    command: str
    returncode: int
    accessed_paths: List[str] = field(default_factory=list)
    subprocesses: List[str] = field(default_factory=list)
    trace_method: str = "strace"
    raw_event_count: int = 0
    stdout: str = ""
    stderr: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "command": self.command,
            "returncode": self.returncode,
            "accessed_paths": self.accessed_paths,
            "subprocesses": self.subprocesses,
            "trace_method": self.trace_method,
            "raw_event_count": self.raw_event_count,
        }


class ExecutionTracer:
    """
    Executes a target command and captures all file and subprocess access.
    """

    # System noise paths that can optionally be filtered out
    SYSTEM_IGNORE_PREFIXES = (
        "/proc/",
        "/sys/",
        "/dev/",
        "/etc/ld.so",
        "/lib/",
        "/usr/lib/",
    )

    def __init__(self, filter_system_libs: bool = True):
        self.filter_system_libs = filter_system_libs
        self.strace_path = shutil.which("strace")

    def trace(self, cmd_str: str) -> ExecutionTrace:
        """
        Traces the execution of `cmd_str`. Uses `strace` if available,
        otherwise falls back to python/subproc runtime inspection.
        """
        if self.strace_path:
            return self._trace_with_strace(cmd_str)
        else:
            return self._trace_fallback(cmd_str)

    def _trace_with_strace(self, cmd_str: str) -> ExecutionTrace:
        """Runs the command under `strace` and parses syscall outputs."""
        trace_file = tempfile.NamedTemporaryFile(delete=False, suffix=".strace")
        trace_file_path = trace_file.name
        trace_file.close()

        # Safely tokenize command
        cmd_args = shlex.split(cmd_str) if isinstance(cmd_str, str) else cmd_str
        strace_cmd = [
            self.strace_path,
            "-f",
            "-q",
            "-s",
            "1024",
            "-e",
            "trace=open,openat,execve,creat",
            "-o",
            trace_file_path,
            "--",
        ] + cmd_args

        try:
            proc = subprocess.run(
                strace_cmd,
                capture_output=True,
                text=True,
            )
            stdout = proc.stdout
            stderr = proc.stderr
            returncode = proc.returncode

            # Parse the strace log
            accessed_paths, subprocesses, event_count = self._parse_strace_log(trace_file_path)

            return ExecutionTrace(
                command=cmd_str if isinstance(cmd_str, str) else " ".join(cmd_str),
                returncode=returncode,
                accessed_paths=sorted(list(accessed_paths)),
                subprocesses=sorted(list(subprocesses)),
                trace_method="strace (OS Kernel)",
                raw_event_count=event_count,
                stdout=stdout,
                stderr=stderr,
            )
        finally:
            if os.path.exists(trace_file_path):
                os.remove(trace_file_path)

    def parse_strace_text(self, log_text: str):
        """Parses strace log lines directly from string (useful for testing or dry-runs)."""
        accessed_paths: Set[str] = set()
        subprocesses: Set[str] = set()
        event_count = 0

        # Regex patterns for syscalls
        openat_pattern = re.compile(r'openat\([^,]+,\s*"([^"]+)"')
        open_pattern = re.compile(r'open\("([^"]+)"')
        creat_pattern = re.compile(r'creat\("([^"]+)"')
        execve_pattern = re.compile(r'execve\("([^"]+)"')

        for line in log_text.splitlines():
            event_count += 1

            # Check execve
            m_exec = execve_pattern.search(line)
            if m_exec:
                subprocesses.add(m_exec.group(1))
                continue

            # Check open / openat / creat
            m_path = openat_pattern.search(line) or open_pattern.search(line) or creat_pattern.search(line)
            if m_path:
                raw_path = m_path.group(1)
                normalized = self._normalize_path(raw_path)
                if normalized and not self._is_ignored(normalized):
                    accessed_paths.add(normalized)

        return accessed_paths, subprocesses, event_count

    def _parse_strace_log(self, log_path: str):
        """Extracts file paths and subprocess calls from an strace log file."""
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            log_text = f.read()
        return self.parse_strace_text(log_text)

    def _trace_fallback(self, cmd_str: str) -> ExecutionTrace:
        """
        Fallback tracer for non-Linux platforms or environments without `strace`.
        Executes command directly and performs filesystem footprint analysis.
        """
        cmd_args = shlex.split(cmd_str) if isinstance(cmd_str, str) else cmd_str

        # Execute target command
        proc = subprocess.run(
            cmd_args,
            capture_output=True,
            text=True,
        )

        accessed_paths: Set[str] = set()
        subprocesses: Set[str] = set()

        # Extract explicit files/directories mentioned in arguments
        for arg in cmd_args:
            if os.path.exists(arg):
                abs_p = os.path.abspath(arg)
                if os.path.isdir(abs_p):
                    # Inspect directory contents
                    for root, dirs, files in os.walk(abs_p):
                        for f in files:
                            accessed_paths.add(os.path.join(root, f))
                else:
                    accessed_paths.add(abs_p)

        # Look for implicit Python project closure files in working directory
        cwd = os.getcwd()
        for implicit_file in ["conftest.py", "pytest.ini", "pyproject.toml", "setup.py", ".env"]:
            target = os.path.join(cwd, implicit_file)
            if os.path.exists(target):
                accessed_paths.add(target)

        # Look for cache directories in cwd
        for cache_dir in ["__pycache__", ".pytest_cache", ".venv"]:
            target_dir = os.path.join(cwd, cache_dir)
            if os.path.exists(target_dir):
                for root, _, files in os.walk(target_dir):
                    for f in files:
                        accessed_paths.add(os.path.join(root, f))

        subprocesses.add(cmd_args[0])

        return ExecutionTrace(
            command=cmd_str if isinstance(cmd_str, str) else " ".join(cmd_str),
            returncode=proc.returncode,
            accessed_paths=sorted(list(accessed_paths)),
            subprocesses=sorted(list(subprocesses)),
            trace_method="Fallback Runtime Inspector (No strace)",
            raw_event_count=len(accessed_paths),
            stdout=proc.stdout,
            stderr=proc.stderr,
        )

    def _normalize_path(self, path: str) -> str:
        """Resolves relative paths and symlinks to clean absolute paths."""
        try:
            return os.path.abspath(os.path.expanduser(path))
        except Exception:
            return path

    def _is_ignored(self, path: str) -> bool:
        """Filters out standard OS shared libraries if `filter_system_libs` is set."""
        if not self.filter_system_libs:
            return False
        return any(path.startswith(prefix) for prefix in self.SYSTEM_IGNORE_PREFIXES)


if __name__ == "__main__":
    # Self-test when executed directly
    tracer = ExecutionTracer()
    print(f"[+] Initialized ExecutionTracer (strace available: {bool(tracer.strace_path)})")

    # 1. Test strace regex parser with mock output
    sample_strace_log = """
    12345 execve("/usr/bin/python3", ["python3", "-m", "pytest", "tests/"], 0x7ff...) = 0
    12345 openat(AT_FDCWD, "/home/user/project/conftest.py", O_RDONLY) = 3
    12345 openat(AT_FDCWD, "/home/user/project/__pycache__/conftest.cpython-312.pyc", O_RDONLY) = 4
    12345 openat(AT_FDCWD, "/home/user/project/tests/test_auth.py", O_RDONLY) = 5
    12345 openat(AT_FDCWD, "/home/user/project/.env", O_RDONLY) = 6
    12345 openat(AT_FDCWD, "/tmp/pytest-of-user/garbage.tmp", O_RDWR|O_CREAT) = 7
    """
    paths, subprocs, count = tracer.parse_strace_text(sample_strace_log)
    print(f"[+] Mock strace parser test:")
    print(f"    - Raw events parsed: {count}")
    print(f"    - Subprocesses discovered: {list(subprocs)}")
    print(f"    - Discovered Execution Closure ({len(paths)} paths):")
    for p in sorted(list(paths)):
        print(f"        * {p}")

    # 2. Test execution of simple command
    test_cmd = "python3 -c \"import sys; print('Python version:', sys.version.split()[0])\""
    trace_res = tracer.trace(test_cmd)

    print(f"\n[+] Real Command Execution Test:")
    print(f"    - Command: {trace_res.command}")
    print(f"    - Method: {trace_res.trace_method}")
    print(f"    - Returncode: {trace_res.returncode}")
    print(f"    - Stdout: {trace_res.stdout.strip()}")