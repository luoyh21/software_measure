"""DynamicAgent: provision seeds, run afl-fuzz, harvest crashes and stats."""
from __future__ import annotations

import json
import logging
from pathlib import Path

from ..config import Config
from ..tools import afl, seeds

log = logging.getLogger("agent.dynamic")


class DynamicAgent:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    def run(self, plan: dict, harness_bin: Path) -> dict:
        warnings = afl.ensure_runtime_prereqs(dry_run=self.cfg.dry_run)
        for w in warnings:
            log.warning(w)

        seeds.provision_seeds(self.cfg.seeds_dir, plan.get("seed_strategy", "url"))

        log.info("starting afl-fuzz for %d seconds", self.cfg.fuzz_seconds)
        out_dir = afl.run_afl_fuzz(self.cfg, harness_bin, self.cfg.seeds_dir)
        stats = afl.parse_fuzzer_stats(out_dir)
        crashes = afl.collect_crashes(out_dir, limit=self.cfg.max_crashes)
        result = {
            "stats": stats,
            "crashes": crashes,
            "out_dir": str(out_dir),
            "prereq_warnings": warnings,
        }
        (self.cfg.workdir / "dynamic_findings.json").write_text(
            json.dumps(result, indent=2, ensure_ascii=False)
        )
        log.info("dynamic: %d crashes, stats keys=%s", len(crashes), list(stats)[:6])
        return result
