"""DoxShield M4: a single, bounded LangGraph privacy-investigation agent.

Workflow: triage → investigate (tool loop) → assess → propose_actions →
await_approval (human interrupt) → execute → report.

LangChain/LangSmith tracing is forced off here: DoxShield sends no telemetry, and
LangGraph pulls in ``langsmith`` as a transitive dependency.
"""
import os

for _var in ("LANGSMITH_TRACING", "LANGCHAIN_TRACING_V2", "LANGCHAIN_TRACING"):
    os.environ[_var] = "false"
