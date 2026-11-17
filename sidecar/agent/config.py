"""Conservative, configurable limits for one investigation."""
from __future__ import annotations

import os
from dataclasses import dataclass


def _int_env(name: str, default: int) -> int:
    try:
        return max(0, int(os.getenv(name, default)))
    except ValueError:
        return default


@dataclass(frozen=True)
class AgentConfig:
    # Every MCP call counts, including retries, so retries cannot bypass the cap.
    max_tool_calls: int = 14
    # LangGraph recursion limit: hard stop on the number of node executions.
    max_graph_steps: int = 40
    max_evidence_items: int = 40
    # Bounded retries for read-only tools only (never for action tools).
    read_retries: int = 1
    retry_backoff_s: float = 0.25
    # Client-side timeout per MCP call; the server also enforces its own (15 s).
    tool_timeout_s: float = 20.0
    # How many distinct destinations to look up after get_connections.
    max_destinations: int = 3
    # Max model calls per investigation (assessment + one repair + policy).
    max_llm_calls: int = 4

    @classmethod
    def from_env(cls) -> AgentConfig:
        return cls(
            max_tool_calls=_int_env("DOXSHIELD_AGENT_MAX_TOOL_CALLS", cls.max_tool_calls),
            max_graph_steps=_int_env("DOXSHIELD_AGENT_MAX_STEPS", cls.max_graph_steps),
            max_evidence_items=_int_env("DOXSHIELD_AGENT_MAX_EVIDENCE", cls.max_evidence_items),
        )
