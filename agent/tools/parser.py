"""Lightweight helpers for slurping selected source files into LLM context."""
from __future__ import annotations

from pathlib import Path


def read_excerpt(path: Path, max_bytes: int = 8000) -> str:
    """Read up to `max_bytes` from `path`, returning text with line numbers."""
    if not path.exists():
        return f"<file missing: {path}>"
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return f"<read error: {exc}>"
    if len(text) > max_bytes:
        text = text[:max_bytes] + f"\n... [truncated at {max_bytes} bytes]\n"
    return text


def find_header(headers_dir: Path, api_hint: str) -> Path | None:
    """Best-effort: find a header that likely declares `api_hint`."""
    if not headers_dir.exists():
        return None
    needle = api_hint.lower()
    for h in headers_dir.rglob("*.h"):
        try:
            if needle in h.read_text(encoding="utf-8", errors="replace").lower():
                return h
        except OSError:
            continue
    return None
