# TaskScope-TUI

**Task-Scoped Authorization Engine & Terminal UI for Autonomous AI Coding Agents**

TaskScope-TUI is a runtime permission governance engine and terminal user interface (TUI) designed for AI coding agents. Rather than relying on static LLM prompt guardrails or broad developer credentials, TaskScope-TUI dynamically traces an agent's **Execution Closure** at the OS kernel level and applies **Sufficiency-Tightness Decomposition** to enforce minimal, task-calibrated security boundaries [1, 2].

---

## The Problem: Verification Gap & Approval Fatigue

Standard authorization models fail when applied to AI coding agents for three fundamental reasons:

1. **Prompt Guardrails Are Non-Controls:** Prompt instructions describing intended behavior cannot restrict system access, as non-deterministic agents load tool contexts dynamically and can be bypassed via prompt injection or reasoning failures [1, 3, 4]. True security enforcement must exist below the prompt at the OS kernel level [1].
2. **Static Approvals Cause Banner Blindness:** Forcing developers to manually approve every file read or command invocation leads to severe approval fatigue and verification load [5, 6]. Users develop high confidence in plausible outputs and routinely approve actions without generating diagnostic evidence, missing silent security defects [6].
3. **Execution Closure vs. Static Permission Lists:** A top-level command like `pytest tests/` appears to only access `/tests/`. In reality, execution transitively touches hidden runtime dependencies—such as `conftest.py`, `pytest.ini`, bytecode caches (`__pycache__`), and temporary system buffers (`/tmp`) [7]. Static prompt policies miss these hidden nodes, causing execution failures unless over-broad permissions are granted [2, 7].

---

## Technical Architecture & Theoretical Foundation

TaskScope-TUI operationalizes recent research from **AuthBench** (Yan et al., 2026) and **Agent Oversight HCI Studies** (Dissanayake et al., 2026) into a four-stage execution pipeline [2, 6]:

### Execution Pipeline

1. **Task Input & Command Invocations:** The user or agent issues a terminal command (e.g., `python -m taskscope.main "pytest"`).
2. **Kernel-Level Execution Tracing (`tracer.py`):** The system intercepts system calls (`open`, `openat`, `creat`, `execve`) via `strace` or runtime inspection to capture the complete, transitive Execution Closure at runtime [7, 8].
3. **Sufficiency-Tightness Decomposition (`policy.py`):** 
   - *Sufficiency (Coverage):* Automatically approves routine build and test dependencies (`__pycache__`, `conftest.py`, `/tmp`) to keep ordinary work frictionless [2].
   - *Tightness Audit:* Scans traced paths against security rules to flag sensitive surfaces (`.env`, SSH keys, cloud credentials) or out-of-workspace paths [2].
4. **Task-Calibrated Re-engagement TUI (`tui.py`):** Routine closure paths pass without prompting, while security boundary breaches display an escalation prompt reserving human attention strictly for real risk events [6].

### Key Security Concepts

- **Execution Closure:** The complete, transitive set of files, subprocesses, configuration files, and temporary buffers required for a command to execute successfully [7].
- **Sufficiency-Tightness Decomposition:** Establishing a coverage-oriented policy by observing runtime dependencies (**Sufficiency**), then auditing each granted path for sensitivity and scope (**Tightness**) [2].
- **Task-Calibrated Re-engagement:** Reserving human oversight exclusively for consequential security boundary changes, eliminating continuous popups during routine operations [6].

---

## Project Structure

```text
taskscope-tui/
├── taskscope/
│   ├── __init__.py       # Package exports and versioning
│   ├── tracer.py         # OS kernel & runtime execution tracer
│   ├── policy.py         # Sufficiency-Tightness policy auditor
│   ├── tui.py            # Rich terminal UI & escalation prompt
│   └── main.py           # CLI orchestrator & entrypoint
├── sample_app.py         # Test runner script exposing routine & sensitive files
├── conftest.py           # Sample pytest configuration file
├── requirements.txt      # Dependencies (rich)
└── README.md             # System documentation
Quickstart & Installation
Prerequisites
Python: 3.10 or higher
Operating System: Linux (recommended for full strace kernel tracing) or macOS/Windows (uses fallback runtime inspector)
System Utilities: strace (optional, for OS-level tracing)
Installation
# Clone the repository
git clone https://github.com/sunbeamn/Task-Scoped-TUI.git
cd taskscope-tui

# Install dependencies
pip install -r requirements.txt
Usage
Run any target command under TaskScope-TUI protection:
python -m taskscope.main "python sample_app.py"
To specify a custom workspace root for tightness audits:
python -m taskscope.main --workspace /path/to/project "pytest tests/"
Operational Behavior
When executing commands, TaskScope-TUI performs the following sequence:
Telemetry Dashboard: Renders an active status panel showing the target command and execution tracing engine.
Discovered Execution Closure: Displays a clean table listing every path touched during execution, categorized as AUTO_ALLOWED, SYSTEM, or ESCALATION.
Task-Calibrated Re-engagement Card: If sensitive files (such as .env or out-of-workspace credentials) are accessed, an escalation prompt requests explicit human confirmation.
Research & Academic References
TaskScope-TUI is grounded in theoretical and empirical findings from current literature:
AuthBench & Sufficiency-Tightness Decomposition: Yan et al. (2026). Do Coding Agents Understand Least-Privilege Authorization? arXiv:2605.14859. Showed that LLM reasoning settles into broad-but-exposed or tight-but-brittle attractors, and that decomposing policy discovery from tightness auditing improves task success by up to 15.8 percentage points.
Human Oversight & Verification Load: Dissanayake et al. (2026). Looks Fine to Me: Understanding Oversight in Agentic Interactions. arXiv:2610.27801. Demonstrated that users accept plausible agent outputs without thorough evaluation, establishing the need for task-calibrated re-engagement.
Kernel-Enforced Agent Sandboxing: Factory Droid Exec & OS-level Sandboxing documentation (2026).