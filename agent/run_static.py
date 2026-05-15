"""Run static analysis only and keep outputs in work/static-only.

Usage:
    source venv/bin/activate
    python -m agent.run_static --target curl
"""
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .agents.planner import PlannerAgent
from .agents.static_agent import StaticAgent
from .config import Config
from .llm import LLM


console = Console()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run static analysis only.")
    p.add_argument("--target", default="curl")
    p.add_argument("--api", default=None)
    p.add_argument("--workdir", default="work")
    p.add_argument("--force", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--fuzz-seconds", type=int, default=600,
                   help="Unused here; kept for Config compatibility.")
    p.add_argument("--asan", action="store_true")
    p.add_argument("--max-warnings", type=int, default=20)
    p.add_argument("--max-crashes", type=int, default=20)
    return p.parse_args()


def _render_findings(findings: list[dict]) -> None:
    if not findings:
        console.print("[yellow]no findings.[/]")
        return
    table = Table(
        title=f"Clang Static Analyzer — {len(findings)} findings",
        show_lines=False,
    )
    table.add_column("#", justify="right", style="dim")
    table.add_column("file:line", style="cyan", no_wrap=True)
    table.add_column("category", style="bold yellow")
    table.add_column("description", overflow="fold")
    for i, f in enumerate(findings, 1):
        path = f.get("file", "")
        # Trim long absolute paths for readability.
        short = path.split("/curl/", 1)[-1] if "/curl/" in path else path
        table.add_row(
            str(i),
            f"{short}:{f.get('line', 0)}",
            f.get("category", "")[:40],
            f.get("description", "")[:120],
        )
    console.print(table)


def main() -> int:
    args = parse_args()
    cfg = Config.from_args(args)
    llm = LLM(cfg)

    console.rule("[bold cyan]Static analysis — Clang Static Analyzer")

    if not cfg.plan_path.exists() or args.force:
        console.print("[dim]running PlannerAgent …[/]")
        plan = PlannerAgent(cfg, llm).run()
    else:
        plan = json.loads(cfg.plan_path.read_text(encoding="utf-8"))

    console.print(Panel(
        f"target_file        : {plan.get('target_file')}\n"
        f"target_api         : {plan.get('target_api')}\n"
        f"static_focus_files : {plan.get('static_focus_files')}\n"
        f"clang              : {cfg.clang}\n"
        f"scan-build         : {cfg.scan_build}",
        title="Plan / tool versions", border_style="cyan",
    ))
    # Show clang version explicitly — useful for the screenshot.
    if cfg.clang.exists():
        try:
            v = subprocess.run([str(cfg.clang), "--version"],
                               capture_output=True, text=True, check=False)
            console.print(Panel(v.stdout.strip(), title="clang --version",
                                border_style="dim"))
        except OSError:
            pass

    findings = StaticAgent(cfg).run()

    _render_findings(findings)

    console.rule("[bold green]Static analysis finished")
    console.print(Panel(
        f"target     : {cfg.target.name}\n"
        f"findings   : {len(findings)}\n"
        f"json       : {cfg.workdir / 'static_findings.json'}\n"
        f"html dir   : {cfg.scan_reports_dir}",
        title="outputs", border_style="green",
    ))

    console.rule("[bold]READY FOR SCREENSHOT")
    console.print(
        "[bold yellow]Window will stay open. Press Ctrl+C to exit.[/]"
    )
    try:
        while True:
            try:
                input()
            except EOFError:
                break
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
