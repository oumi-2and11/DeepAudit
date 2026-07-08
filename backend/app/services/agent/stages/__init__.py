"""
Deterministic pre/post stages that run around the LLM-driven Agents.

These are *not* Agents — no LLM calls happen here. They are fixed pipeline steps
whose outputs are fed into the Agent context as "known facts".
"""

from .preflight import run_preflight, PreflightResult

__all__ = ["run_preflight", "PreflightResult"]
