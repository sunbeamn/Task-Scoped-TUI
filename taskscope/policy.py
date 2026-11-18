"""
policy.py - Sufficiency-Tightness Auditor for TaskScope-TUI.

Implements Sufficiency-Tightness Decomposition:
1. Sufficiency (Auto-Approval): Identifies routine runtime execution closure
   dependencies (e.g., conftest.py, __pycache__, /tmp buffers, pytest.ini).
2. Tightness Audit (Security Classification): Detects sensitive surfaces
   (.env files, SSH keys, cloud credentials, root configs) and flags them for
   human escalation.
"""

import os
import re
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any


class PolicyStatus(Enum):
    AUTO_ALLOWED = "AUTO_ALLOWED"          # Routine closure dependency (Sufficiency)
    SYSTEM_ROUTINE = "SYSTEM_ROUTINE"      # OS libraries & interpreter binaries
    SENSITIVE_ESCALATION = "ESCALATION"    # High-risk path flagged for Tightness Audit


@dataclass
class PathAudit:
    path: str
    status: PolicyStatus
    reason: str
    is_sensitive: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "status": self.status.value,
            "reason": self.reason,
            "is_sensitive": self.is_sensitive,
        }


@dataclass
class PolicyResult:
    command: str
    total_paths_audited: int
    allowed_paths: List[PathAudit] = field(default_factory=list)
    system_paths: List[PathAudit] = field(default_factory=list)
    flagged_paths: List[PathAudit] = field(default_factory=list)

    @property
    def requires_escalation(self) -> bool:
        return len(self.flagged_paths) > 0

    def summary(self) -> Dict[str, Any]:
        return {
            "command": self.command,
            "total_paths": self.total_paths_audited,
            "allowed_count": len(self.allowed_paths),
            "system_count": len(self.system_paths),
            "flagged_count": len(self.flagged_paths),
            "requires_escalation": self.requires_escalation,
        }


class PolicyAuditor:
    """
    Audits execution closure paths against Sufficiency and Tightness rules.
    """

    # 1. High-risk patterns that trigger Tightness Escalation
    SENSITIVE_PATTERNS = [
        (re.compile(r"(^|/)\.env(\..+)?$", re.IGNORECASE), "Environment secrets file (.env)"),
        (re.compile(r"(^|/)\.ssh(/|$)", re.IGNORECASE), "SSH credentials directory"),
        (re.compile(r"(^|/)\.aws(/|$)", re.IGNORECASE), "AWS cloud credentials directory"),
        (re.compile(r"(^|/)\.gnupg(/|$)", re.IGNORECASE), "GPG key ring"),
        (re.compile(r".*\.(pem|key|pkcs12|pfx|crt)$", re.IGNORECASE), "Cryptographic private key / certificate"),
        (re.compile(r"(^|/)(secrets|credentials|passwords|token|apiKey)\.(json|yaml|yml|toml|ini|txt|py)$", re.IGNORECASE), "Explicit secret / credential file"),
        (re.compile(r"^/etc/(passwd|shadow|sudoers)", re.IGNORECASE), "Core system authentication file"),
        (re.compile(r"(^|/)\.bash_history|\.zsh_history$", re.IGNORECASE), "User shell history log"),
    ]

    # 2. Known routine execution closure patterns (Sufficiency Auto-Approval)
    ROUTINE_CLOSURE_PATTERNS = [
        (re.compile(r"(^|/)__pycache__(/|$)"), "Python bytecode cache directory"),
        (re.compile(r".*\.pyc$"), "Compiled Python bytecode"),
        (re.compile(r"(^|/)conftest\.py$"), "pytest root configuration"),
        (re.compile(r"(^|/)pytest\.ini$"), "pytest setup config"),
        (re.compile(r"(^|/)pyproject\.toml$"), "Python project configuration"),
        (re.compile(r"(^|/)setup\.(py|cfg)$"), "Python package build config"),
        (re.compile(r"(^|/)\.pytest_cache(/|$)"), "pytest runtime cache"),
        (re.compile(r"(^|/)\.venv(/|$)"), "Local virtual environment"),
        (re.compile(r"^/tmp(/|$)"), "Temporary execution buffer (/tmp)"),
        (re.compile(r"^/var/tmp(/|$)"), "System temporary buffer (/var/tmp)"),
    ]

    # 3. System library prefixes
    SYSTEM_PREFIXES = (
        "/usr/lib",
        "/lib",
        "/lib64",
        "/usr/share/python",
        "/usr/bin/python",
        "/proc/",
        "/sys/",
        "/dev/",
    )

    def __init__(self, workspace_dir: Optional[str] = None):
        self.workspace_dir = os.path.abspath(workspace_dir) if workspace_dir else os.getcwd()

    def audit_closure(self, command: str, paths: List[str]) -> PolicyResult:
        """Audits a list of execution closure paths captured during dry-run tracing."""
        result = PolicyResult(
            command=command,
            total_paths_audited=len(paths),
        )

        for path in paths:
            audit = self.classify_path(path)
            if audit.status == PolicyStatus.SENSITIVE_ESCALATION:
                result.flagged_paths.append(audit)
            elif audit.status == PolicyStatus.SYSTEM_ROUTINE:
                result.system_paths.append(audit)
            else:
                result.allowed_paths.append(audit)

        return result

    def classify_path(self, path: str) -> PathAudit:
        """Classifies a single filesystem path."""
        norm_path = os.path.abspath(path)

        # Step 1: Check Tightness (Sensitive Security Surfaces)
        for pattern, reason in self.SENSITIVE_PATTERNS:
            if pattern.search(norm_path) or pattern.search(path):
                return PathAudit(
                    path=norm_path,
                    status=PolicyStatus.SENSITIVE_ESCALATION,
                    reason=f"Tightness Audit Flag: {reason}",
                    is_sensitive=True,
                )

        # Step 2: Check Sufficiency (Known Routine Closure Patterns)
        for pattern, reason in self.ROUTINE_CLOSURE_PATTERNS:
            if pattern.search(norm_path) or pattern.search(path):
                return PathAudit(
                    path=norm_path,
                    status=PolicyStatus.AUTO_ALLOWED,
                    reason=f"Sufficiency Auto-Approved: {reason}",
                    is_sensitive=False,
                )

        # Step 3: Check System Paths
        if any(norm_path.startswith(prefix) for prefix in self.SYSTEM_PREFIXES):
            return PathAudit(
                path=norm_path,
                status=PolicyStatus.SYSTEM_ROUTINE,
                reason="System Library / Binary Execution",
                is_sensitive=False,
            )

        # Step 4: Check Workspace Proximity
        if norm_path.startswith(self.workspace_dir):
            return PathAudit(
                path=norm_path,
                status=PolicyStatus.AUTO_ALLOWED,
                reason="In-Workspace Routine Access",
                is_sensitive=False,
            )

        # Step 5: Unrecognized Out-of-Workspace Access -> Default to Escalation
        return PathAudit(
            path=norm_path,
            status=PolicyStatus.SENSITIVE_ESCALATION,
            reason="Out-of-Workspace Access (Tightness Breach)",
            is_sensitive=True,
        )


if __name__ == "__main__":
    auditor = PolicyAuditor(workspace_dir="/home/user/project")
    test_paths = [
        "/home/user/project/conftest.py",
        "/home/user/project/__pycache__/conftest.cpython-312.pyc",
        "/home/user/project/tests/test_auth.py",
        "/home/user/project/.env",
        "/tmp/pytest-of-user/garbage.tmp",
        "/etc/passwd",
        "/usr/lib/python3.12/os.py",
        "/home/user/.ssh/id_rsa",
    ]
    res = auditor.audit_closure("pytest tests/", test_paths)
    print(f"[+] Policy Auditor Test: {res.summary()}")
    print(f"    - Flagged Paths: {[f.path for f in res.flagged_paths]}")