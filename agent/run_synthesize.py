"""Combine static + dynamic outputs, ask the LLM to diagnose, and write report.

Usage:
    source venv/bin/activate
    python -m agent.run_synthesize --target curl
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .agents.diagnostic_agent import DiagnosticAgent
from .agents.reporter import ReporterAgent
from .config import Config
from .llm import LLM


console = Console()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Synthesize report from existing artifacts.")
    p.add_argument("--target", default="curl")
    p.add_argument("--api", default=None)
    p.add_argument("--workdir", default="work")
    p.add_argument("--max-warnings", type=int, default=20)
    p.add_argument("--max-crashes", type=int, default=20)
    p.add_argument("--force", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--asan", action="store_true")
    p.add_argument("--fuzz-seconds", type=int, default=600,
                   help="Unused; kept for Config compatibility.")
    return p.parse_args()


def _load_json(path: Path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    args = parse_args()
    cfg = Config.from_args(args)
    llm = LLM(cfg)

    plan = _load_json(cfg.plan_path, {})
    static_findings = _load_json(cfg.workdir / "static_findings.json", [])
    dynamic_findings = _load_json(cfg.workdir / "dynamic_findings.json", {})
    harness_c = cfg.harness_dir / "harness.c"

    if not plan:
        console.print("[red]plan.json missing — run static or dynamic first.[/]")
        return 1
    if not static_findings and not dynamic_findings:
        console.print("[red]no static or dynamic findings — nothing to synthesize.[/]")
        return 1

    summary = Table(title="Input artifacts", show_lines=False)
    summary.add_column("artifact", style="cyan")
    summary.add_column("path / count")
    summary.add_row("plan", str(cfg.plan_path))
    summary.add_row("static findings", f"{len(static_findings)}")
    summary.add_row("dynamic crashes",
                    f"{len(dynamic_findings.get('crashes', []))}")
    summary.add_row("harness.c", str(harness_c) if harness_c.exists() else "(missing)")
    console.print(summary)

    diag = DiagnosticAgent(cfg, llm).run(
        static_findings, dynamic_findings,
        harness_c if harness_c.exists() else None,
    )
    ReporterAgent(cfg, llm).run(plan, static_findings, dynamic_findings, diag)

    console.rule("[bold green]Synthesis finished")
    console.print(Panel(
        f"report (markdown) : {cfg.report_md}\n"
        f"report (json)     : {cfg.report_json}\n"
        f"diagnoses         : {cfg.diagnoses_path}",
        title="outputs", border_style="green",
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
