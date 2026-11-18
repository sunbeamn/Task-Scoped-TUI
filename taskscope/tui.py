"""
tui.py - Rich Terminal UI for TaskScope-TUI.
"""

import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.style import Style

from taskscope.policy import PolicyResult, PolicyStatus, PathAudit

console = Console()


class TaskScopeTUI:
    def render_header(self, command: str, engine_method: str):
        grid = Table.grid(expand=True)
        grid.add_column(justify="left")
        grid.add_row("[bold cyan]🛡️  TaskScope-TUI[/bold cyan] | Task-Scoped Authorization & Execution Tracer")
        grid.add_row(f"[bold yellow]Target Command:[/bold yellow] [white]{command}[/white]")
        grid.add_row(f"[dim]Engine Method: {engine_method}[/dim]")
        
        panel = Panel(grid, border_style="cyan", title="[bold]TaskScope Security Governance[/bold]")
        console.print(panel)

    def render_closure_table(self, policy_result: PolicyResult):
        table = Table(title="🔍 Discovered Execution Closure (Runtime Dependencies)", expand=True)
        table.add_column("Status", style="bold", width=18)
        table.add_column("Discovered Path", style="dim", width=42)
        table.add_column("Audit Reason & Classification", style="white")

        all_audits = (
            policy_result.flagged_paths +
            policy_result.allowed_paths +
            policy_result.system_paths
        )

        for audit in all_audits:
            if audit.status == PolicyStatus.SENSITIVE_ESCALATION:
                status_text = "[bold red]🚨 ESCALATION[/bold red]"
            elif audit.status == PolicyStatus.AUTO_ALLOWED:
                status_text = "[bold green]✅ AUTO_ALLOWED[/bold green]"
            else:
                status_text = "[dim blue]⚙️  SYSTEM[/dim blue]"
            
            table.add_row(status_text, audit.path, audit.reason)

        console.print(table)

    def prompt_escalation(self, policy_result: PolicyResult) -> bool:
        flagged_list = "\n".join([f"  • [bold red]{a.path}[/bold red] ({a.reason})" for a in policy_result.flagged_paths])
        
        escalation_text = (
            f"[bold red]⚠️  SECURITY BOUNDARY BREACH DETECTED[/bold red]\n\n"
            f"The execution tracer intercepted access requests to high-risk or out-of-workspace paths:\n"
            f"{flagged_list}\n\n"
            f"[dim yellow][TaskScope Protection]: Statical prompt rules omitted this boundary. Human approval required.[/dim yellow]"
        )
        
        panel = Panel(
            escalation_text,
            title="[bold red]╔════ 🚨 [TASK-CALIBRATED RE-ENGAGEMENT CARD] ════╗[/bold red]",
            border_style="red",
            expand=True
        )
        console.print(panel)

        if not sys.stdin.isatty():
            console.print("[yellow][!] Non-interactive shell detected. Defaulting to STRICT ENFORCEMENT (Access Blocked).[/yellow]")
            return False

        try:
            response = console.input("\n[bold yellow]Authorize access to these flagged path(s)? (y/N): [/bold yellow]").strip().lower()
            return response == "y"
        except (KeyboardInterrupt, EOFError):
            return False

    def render_summary_panel(self, policy_result: PolicyResult, success: bool):
        console.print(f"\n[bold]📊 Execution Closure Summary:[/bold]")
        console.print(f"  • Total Paths Audited: {policy_result.total_paths_audited}")
        console.print(f"  • Auto-Approved Closure: {len(policy_result.allowed_paths)} (Sufficiency)")
        console.print(f"  • System Libraries: {len(policy_result.system_paths)}")
        console.print(f"  • Flagged Escalations: {len(policy_result.flagged_paths)}")

        if success:
            panel = Panel("[bold green]✅ EXECUTION AUTHORIZED & COMPLETED[/bold green]", border_style="green")
        else:
            panel = Panel("[bold red]⛔ EXECUTION BLOCKED (Tightness Policy Enforced)[/bold red]", border_style="red")
        
        console.print(panel)