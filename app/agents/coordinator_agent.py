"""
Coordinator Agent
──────────────────
Manages the LangGraph workflow:
  • Validates inputs
  • Decides execution order
  • Handles failures/retries for each node
  • Collects outputs and generates execution summary
"""
import logging
import traceback
from typing import Callable

logger = logging.getLogger(__name__)

MAX_RETRIES = 2


def _safe_run(node_fn: Callable, state: dict, retries: int = MAX_RETRIES) -> dict:
    """Execute a node function with retry logic; logs errors and continues."""
    name = node_fn.__name__
    for attempt in range(1, retries + 2):
        try:
            return node_fn(state)
        except Exception as e:
            tb = traceback.format_exc()
            logger.warning("[Coordinator] %s failed (attempt %d/%d): %s", name, attempt, retries + 1, e)
            logger.debug(tb)
            if attempt == retries + 1:
                state.setdefault("errors", []).append(
                    f"{name} failed after {retries + 1} attempts: {e}"
                )
                state["processing_steps"].append(f"{name}: FAILED — {e}")
    return state


def run_coordinator(state: dict) -> dict:
    """
    LangGraph node: coordinator_agent.
    Called after parse_input; validates state and prepares workflow execution.
    """
    logger.info("[Coordinator] Initialising workflow…")

    # Validate required state keys
    required = ["job_id", "files", "parsed_content", "processing_steps"]
    for key in required:
        if key not in state:
            state[key] = [] if key in ("files", "processing_steps") else ""

    if not state.get("parsed_content") and not state.get("files"):
        state.setdefault("errors", []).append("No input content or files provided.")
        logger.error("[Coordinator] No content to process.")

    state["processing_steps"].append("coordinator: workflow initialised")
    logger.info("[Coordinator] Workflow ready. %d file(s) in scope.", len(state.get("files", [])))
    return state


def build_execution_summary(state: dict) -> str:
    """Return a human-readable execution summary from the state."""
    steps = state.get("processing_steps", [])
    errors = state.get("errors", [])
    threats = len(state.get("threats", []))
    vulns = len(state.get("vulnerabilities", []))
    score = state.get("risk_score", 0)
    level = state.get("risk_level", "Unknown")

    lines = [
        "=== Execution Summary ===",
        f"Steps completed : {len(steps)}",
        f"Errors          : {len(errors)}",
        f"Threats found   : {threats}",
        f"CVEs retrieved  : {vulns}",
        f"Risk score      : {score} ({level})",
    ]
    if errors:
        lines.append("Error details:")
        for e in errors:
            lines.append(f"  - {e}")
    return "\n".join(lines)
