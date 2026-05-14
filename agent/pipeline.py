"""Pipeline orchestrator: sequences PlannerAgent → StaticAgent → HarnessAgent →
DynamicAgent → DiagnosticAgent → ReporterAgent.

Supports running just one stage via the `mode` argument. Each stage writes
its own JSON output under `cfg.workdir`, so later stages can be re-run
without redoing earlier ones.
"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

from rich.logging import RichHandler

from .agents.diagnostic_agent import DiagnosticAgent
from .agents.dynamic_agent import DynamicAgent
from .agents.harness_agent import HarnessAgent
from .agents.planner import PlannerAgent
from .agents.reporter import ReporterAgent
from .agents.static_agent import StaticAgent
from .config import Config
from .llm import LLM


def _setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        handlers=[RichHandler(rich_tracebacks=True, show_path=False)],
    )


class Pipeline:
    def __init__(self, cfg: Config):
        _setup_logging()
        self.cfg = cfg
        self.log = logging.getLogger("agent.pipeline")
        self._llm: LLM | None = None  # lazy

    def llm(self) -> LLM:
        if self._llm is None:
            self._llm = LLM(self.cfg)
        return self._llm

    # ---- helpers ----
    def _mark_done(self, stage: str) -> None:
        self.cfg.done_marker(stage).write_text("ok")

    def _is_done(self, stage: str) -> bool:
        return self.cfg.done_marker(stage).exists() and not self.cfg.force

    def _load_json(self, path: Path, default):
        if not path.exists():
            return default
        return json.loads(path.read_text(encoding="utf-8"))

    # ---- per-stage methods ----
    def _stage_plan(self) -> dict:
        if self._is_done("plan") and self.cfg.plan_path.exists():
            self.log.info("[plan] cached; skip (use --force to rerun)")
            return self._load_json(self.cfg.plan_path, {})
        self.log.info("[plan] running PlannerAgent")
        plan = PlannerAgent(self.cfg, self.llm()).run()
        self._mark_done("plan")
        return plan

    def _stage_static(self) -> list[dict]:
        if self._is_done("static"):
            self.log.info("[static] cached; skip")
            return self._load_json(self.cfg.workdir / "static_findings.json", [])
        self.log.info("[static] running StaticAgent (scan-build)")
        findings = StaticAgent(self.cfg).run()
        self._mark_done("static")
        return findings

    def _stage_harness(self, plan: dict) -> Path:
        if self._is_done("harness"):
            self.log.info("[harness] cached; skip")
            return self.cfg.harness_dir / "harness_afl"
        self.log.info("[harness] running HarnessAgent")
        harness_bin = HarnessAgent(self.cfg, self.llm()).run(plan)
        self._mark_done("harness")
        return harness_bin

    def _stage_dynamic(self, plan: dict, harness_bin: Path) -> dict:
        if self._is_done("dynamic"):
            self.log.info("[dynamic] cached; skip")
            return self._load_json(self.cfg.workdir / "dynamic_findings.json", {})
        self.log.info("[dynamic] running DynamicAgent (afl-fuzz %ds)",
                      self.cfg.fuzz_seconds)
        dyn = DynamicAgent(self.cfg).run(plan, harness_bin)
        self._mark_done("dynamic")
        return dyn

    def _stage_diagnose(self, static_findings, dynamic_findings, harness_c) -> dict:
        if self._is_done("diagnose") and self.cfg.diagnoses_path.exists():
            self.log.info("[diagnose] cached; skip")
            return self._load_json(self.cfg.diagnoses_path, {})
        self.log.info("[diagnose] running DiagnosticAgent")
        diag = DiagnosticAgent(self.cfg, self.llm()).run(
            static_findings, dynamic_findings, harness_c
        )
        self._mark_done("diagnose")
        return diag

    def _stage_report(self, plan, static_findings, dynamic_findings, diag) -> dict:
        self.log.info("[report] running ReporterAgent")
        summary = ReporterAgent(self.cfg, self.llm()).run(
            plan, static_findings, dynamic_findings, diag
        )
        self._mark_done("report")
        return summary

    # ---- public entry ----
    def run(self, mode: str) -> int:
        try:
            if mode in ("plan", "all"):
                plan = self._stage_plan()
            else:
                plan = self._load_json(self.cfg.plan_path, {
                    "target_api": self.cfg.api_hint,
                    "seed_strategy": "url",
                })

            static_findings: list[dict] = []
            dynamic_findings: dict = {}
            harness_c = self.cfg.harness_dir / "harness.c"

            if mode in ("static", "all"):
                static_findings = self._stage_static()
            else:
                static_findings = self._load_json(
                    self.cfg.workdir / "static_findings.json", []
                )

            if mode in ("harness", "dynamic", "all"):
                if mode != "harness":
                    plan = plan or self._stage_plan()
                harness_bin = self._stage_harness(plan)
            else:
                harness_bin = self.cfg.harness_dir / "harness_afl"

            if mode in ("dynamic", "all"):
                dynamic_findings = self._stage_dynamic(plan, harness_bin)
            else:
                dynamic_findings = self._load_json(
                    self.cfg.workdir / "dynamic_findings.json", {}
                )

            if mode in ("diagnose", "all"):
                diag = self._stage_diagnose(
                    static_findings, dynamic_findings,
                    harness_c if harness_c.exists() else None,
                )
            else:
                diag = self._load_json(self.cfg.diagnoses_path, {})

            if mode in ("report", "all"):
                self._stage_report(plan, static_findings, dynamic_findings, diag)

            self.log.info("done. artifacts at: %s", self.cfg.workdir)
            return 0
        except Exception:
            self.log.exception("pipeline failed")
            return 1
