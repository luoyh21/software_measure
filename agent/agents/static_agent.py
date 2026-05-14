"""StaticAgent: drive Clang Static Analyzer.

Two complementary passes:

1. **Focused** — `clang --analyze` on the planner-selected files. Fast
   (seconds per file), always produces HTML reports, useful when scan-build's
   libtool wrapping swallows results.
2. **Full** — `scan-build make` over the whole project. Slow (tens of
   minutes on curl) but covers cross-file interactions. Skipped when its
   `.done` marker is set unless `--force` was passed at the pipeline level.
"""
from __future__ import annotations

import json
import logging
import os

from ..config import Config
from ..tools import clang_sa

log = logging.getLogger("agent.static")


class StaticAgent:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    def run(self) -> list[dict]:
        plan_path = self.cfg.plan_path
        focus_files: list[str] = []
        if plan_path.exists():
            plan = json.loads(plan_path.read_text(encoding="utf-8"))
            focus_files = plan.get("static_focus_files") or []
            tgt = plan.get("target_file")
            if tgt and tgt not in focus_files:
                focus_files.insert(0, tgt)

        findings: list[dict] = []

        if focus_files:
            log.info("[focused] clang --analyze on %d files", len(focus_files))
            focused_root = clang_sa.run_clang_analyze_focused(self.cfg, focus_files)
            findings += clang_sa.parse_focused_reports(focused_root)
            log.info("[focused] %d findings", len(findings))

        skip_full = os.environ.get("AGENT_SKIP_SCAN_BUILD") == "1"
        if not skip_full:
            log.info("[full] scan-build on %s", self.cfg.target.describe())
            clang_sa.run_scan_build(self.cfg)
            findings += clang_sa.parse_reports(self.cfg.scan_reports_dir)
        else:
            log.info("[full] scan-build skipped (AGENT_SKIP_SCAN_BUILD=1)")

        out = self.cfg.workdir / "static_findings.json"
        out.write_text(json.dumps(findings, indent=2, ensure_ascii=False))
        log.info("static findings: %d (written to %s)", len(findings), out)
        return findings
