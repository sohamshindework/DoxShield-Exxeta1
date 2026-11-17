"""Structured tool errors."""
from __future__ import annotations


class ToolError(Exception):
    """A tool failure with a machine-readable code and a safe message."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message

    def as_dict(self) -> dict:
        return {"error": {"code": self.code, "message": self.message}}
