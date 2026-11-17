"""Seed knowledge lookups for the MCP tools.

These files are small, sourced and dated seeds. M5 expands them into the full
knowledge base; the retrieval interface here stays the same.
"""
from __future__ import annotations

import json
from pathlib import Path

KNOWLEDGE_DIR = Path(__file__).resolve().parent.parent / "knowledge"


def _load(name: str) -> list[dict]:
    try:
        with open(KNOWLEDGE_DIR / name) as f:
            return json.load(f)
    except FileNotFoundError:
        return []


def search_knowledge(query: str, limit: int = 5) -> list[dict]:
    """Keyword search over the GDPR reference notes (simple term-frequency rank)."""
    terms = [t for t in query.lower().split() if t]
    scored: list[tuple[int, dict]] = []
    for note in _load("gdpr_notes.json"):
        haystack = f"{note.get('topic', '')} {note.get('text', '')}".lower()
        score = sum(haystack.count(term) for term in terms)
        if score:
            scored.append((score, note))
    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [note for _, note in scored[:limit]]


def find_eu_alternatives(category: str, limit: int = 10) -> list[dict]:
    needle = category.lower().strip()
    alts = _load("eu_alternatives.json")
    matches = [a for a in alts if needle in a.get("category", "").lower()]
    return matches[:limit]
