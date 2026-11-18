"""
main.py - CLI Entrypoint for TaskScope-TUI.
"""

import os
import sys
import argparse
from taskscope.tracer import ExecutionTracer
from taskscope.policy import PolicyAuditor
from taskscope.tui import TaskScopeTUI


def run_taskscope(command: str, workspace_dir: str = None) -> int:
    workspace = os.path.abspath(workspace_dir) if workspace_dir else os.getcwd()
    
    tracer = ExecutionTracer(filter_system_libs=True)
    auditor = PolicyAuditor(workspace_dir=workspace)
    tui = TaskScopeTUI()

    engine_method = "strace (OS Kernel)" if tracer.strace_path else "Fallback Runtime Inspector (No strace)"
    tui.render_header(command, engine_method)

    trace_result = tracer.trace(command)
    policy_result = auditor.audit_closure(command, trace_result.accessed_paths)

    tui.render_closure_table(policy_result)

    if policy_result.requires_escalation:
        authorized = tui.prompt_escalation(policy_result)
        if not authorized:
            tui.render_summary_panel(policy_result, success=False)
            return 1

    tui.render_summary_panel(policy_result, success=True)
    return trace_result.returncode


def main():
    parser = argparse.ArgumentParser(
        description="🛡️ TaskScope-TUI: Task-Scoped Authorization & Execution Tracer"
    )
    parser.add_argument(
        "command",
        type=str,
        help="Target command string to execute under TaskScope protection (e.g., 'pytest tests/')"
    )
    parser.add_argument(
        "--workspace",
        "-w",
        type=str,
        default=None,
        help="Root workspace directory for tightness boundary checks (defaults to CWD)"
    )

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    exit_code = run_taskscope(args.command, args.workspace)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()