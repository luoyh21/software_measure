"""DiagnosticAgent: use LLM to classify each warning / crash."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from ..config import Config
from ..llm import LLM, load_prompt

log = logging.getLogger("agent.diagnostic")


class DiagnosticAgent:
    def __init__(self, cfg: Config, llm: LLM):
        self.cfg = cfg
        self.llm = llm

    def run(self, static_findings: list[dict], dynamic_findings: dict,
            harness_c: Path | None) -> dict:
        static_diag = self._diagnose_static(static_findings)
        dynamic_diag = self._diagnose_dynamic(dynamic_findings, harness_c)
        out = {"static": static_diag, "dynamic": dynamic_diag}
        self.cfg.diagnoses_path.write_text(
            json.dumps(out, indent=2, ensure_ascii=False)
        )
        log.info("diagnoses written: %s", self.cfg.diagnoses_path)
        return out

    def _diagnose_static(self, findings: list[dict]) -> list[dict]:
        sys_prompt = load_prompt("static_diagnosis.md")
        results: list[dict] = []
        for finding in findings[: self.cfg.max_warnings]:
            snippet = _read_source_excerpt(
                self.cfg.target.source_dir,
                finding.get("file", ""),
                finding.get("line", 0),
            )
            user = (
                f"category: {finding.get('category')}\n"
                f"file: {finding.get('file')}\n"
                f"line: {finding.get('line')}\n"
                f"description: {finding.get('description')}\n"
                f"--- source context ---\n{snippet}\n"
            )
            try:
                diag = self.llm.chat_json(system=sys_prompt, user=user, max_tokens=400)
            except Exception as exc:
                log.warning("static diagnosis failed: %s", exc)
                diag = {"category": "other", "severity": "info",
                        "confidence": "low", "likely_root_cause": str(exc),
                        "recommended_fix": "n/a", "exploitability_note": "n/a"}
            results.append({"finding": finding, "diagnosis": diag})
        return results

    def _diagnose_dynamic(self, dyn: dict, harness_c: Path | None) -> list[dict]:
        crashes = dyn.get("crashes", [])
        if not crashes:
            return []
        sys_prompt = load_prompt("dynamic_diagnosis.md")
        harness_src = ""
        if harness_c and harness_c.exists():
            harness_src = harness_c.read_text(encoding="utf-8", errors="replace")
            if len(harness_src) > 4000:
                harness_src = harness_src[:4000] + "\n... [truncated]\n"

        results: list[dict] = []
        for crash in crashes[: self.cfg.max_crashes]:
            user = (
                f"target: {self.cfg.target.name}\n"
                f"crash_id: {crash.get('id')}\n"
                f"size: {crash.get('size')}\n"
                f"hex_preview: {crash.get('preview_hex')}\n"
                f"text_preview: {crash.get('preview_text')!r}\n"
                f"--- harness.c ---\n{harness_src}\n"
            )
            try:
                diag = self.llm.chat_json(system=sys_prompt, user=user, max_tokens=400)
            except Exception as exc:
                log.warning("dynamic diagnosis failed: %s", exc)
                diag = {"category": "other", "severity": "info",
                        "confidence": "low", "trigger_summary": str(exc),
                        "likely_root_cause": "n/a", "recommended_fix": "n/a",
                        "reproduction_hint": "n/a"}
            results.append({"crash": crash, "diagnosis": diag})
        return results


def _read_source_excerpt(source_root: Path, rel_or_abs_path: str,
                         line: int, window: int = 8) -> str:
    if not rel_or_abs_path:
        return ""
    p = Path(rel_or_abs_path)
    if not p.is_absolute():
        p = source_root / p
    if not p.exists():
        # Sometimes scan-build records partial paths; do a best-effort search.
        for cand in source_root.rglob(p.name):
            p = cand
            break
    if not p.exists():
        return ""
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    if line <= 0:
        return "\n".join(lines[:20])
    lo = max(0, line - window - 1)
    hi = min(len(lines), line + window)
    numbered = [f"{i+1:5d}: {lines[i]}" for i in range(lo, hi)]
    return "\n".join(numbered)
