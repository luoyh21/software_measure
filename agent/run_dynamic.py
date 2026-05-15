"""Generate the harness and run afl-fuzz **in the foreground**.

The AFL TUI is left attached to the user's terminal so the screen can be
photographed for the assignment. After AFL exits (or the wall-clock budget
is reached) we render a Rich summary table and try to display the
afl-plot PNGs inline; we then block on input so nothing scrolls the screen.

Usage:
    source venv/bin/activate
    python -m agent.run_dynamic --target curl --fuzz-seconds 43200
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from .agents.harness_agent import HarnessAgent
from .agents.planner import PlannerAgent
from .config import Config
from .llm import LLM
from .tools import afl, seeds


console = Console()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run AFL fuzzing in the foreground.")
    p.add_argument("--target", default="curl")
    p.add_argument("--api", default=None)
    p.add_argument("--fuzz-seconds", type=int, default=43200,
                   help="Wall-clock budget; 43200 = 12h.")
    p.add_argument("--workdir", default="work")
    p.add_argument("--force", action="store_true",
                   help="Re-generate harness and rebuild instrumented lib.")
    p.add_argument("--asan", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--max-warnings", type=int, default=20)
    p.add_argument("--max-crashes", type=int, default=20)
    return p.parse_args()


def _ensure_plan(cfg: Config, llm: LLM, force: bool) -> dict:
    if cfg.plan_path.exists() and not force:
        return json.loads(cfg.plan_path.read_text(encoding="utf-8"))
    return PlannerAgent(cfg, llm).run()


def _ensure_harness(cfg: Config, llm: LLM, plan: dict, force: bool) -> Path:
    harness_bin = cfg.harness_dir / "harness_afl"
    if harness_bin.exists() and not force:
        console.print(f"[green]✓[/] harness already built: {harness_bin}")
        return harness_bin
    return HarnessAgent(cfg, llm).run(plan)


def _show_driver(harness_c: Path) -> None:
    if not harness_c.exists():
        return
    code = harness_c.read_text(encoding="utf-8")
    console.print(Panel(
        Syntax(code, "c", line_numbers=True, theme="monokai"),
        title=f"fuzz driver — {harness_c}",
        border_style="cyan",
    ))


def _run_afl_foreground(cfg: Config, harness_bin: Path,
                        seeds_dir: Path) -> int:
    out_dir = cfg.afl_out_dir
    if out_dir.exists():
        shutil.rmtree(out_dir, ignore_errors=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(cfg.afl_fuzz),
        "-i", str(seeds_dir),
        "-o", str(out_dir),
        "-t", "5000",
        "-m", "none",
        "--", str(harness_bin), "@@",
    ]
    env = dict(os.environ)
    env.setdefault("AFL_SKIP_CPUFREQ", "1")
    env.setdefault("AFL_NO_AFFINITY", "1")
    if cfg.use_asan:
        env["AFL_USE_ASAN"] = "1"

    console.print(Panel(
        " ".join(cmd) + f"\n\n[bold]wall-clock budget:[/] {cfg.fuzz_seconds}s "
                       f"(~{cfg.fuzz_seconds / 3600:.1f}h)\n"
                       "[bold]stop early:[/] press Ctrl+C — AFL stats will "
                       "still be displayed and final plot generated.",
        title="afl-fuzz (foreground; TUI will take over)",
        border_style="yellow",
    ))
    console.print("[dim]Press ENTER to start AFL …[/]")
    try:
        input()
    except EOFError:
        pass

    try:
        proc = subprocess.run(
            cmd, env=env, timeout=cfg.fuzz_seconds + 60,
        )
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        rc = 124
    except KeyboardInterrupt:
        rc = 130
    return rc


def _render_stats(stats: dict, out_dir: Path) -> None:
    table = Table(title="AFL fuzzer_stats (final)", show_lines=False)
    table.add_column("metric", style="cyan", no_wrap=True)
    table.add_column("value", style="bold")
    order = [
        "afl_version", "afl_banner", "command_line",
        "start_time", "last_update",
        "execs_done", "execs_per_sec",
        "paths_total", "paths_favored",
        "bitmap_cvg", "stability",
        "unique_crashes", "unique_hangs",
        "cycles_done", "exec_timeout",
    ]
    for k in order:
        if k in stats:
            table.add_row(k, stats[k])
    console.print(table)
    console.print(f"[green]artifacts:[/] {out_dir}")


def _try_afl_plot(cfg: Config) -> Path | None:
    plot_dir = cfg.workdir / "afl-plot"
    afl_plot = cfg.afl_dir / "afl-plot"
    if not afl_plot.exists():
        return None
    if shutil.which("gnuplot") is None:
        console.print("[yellow]gnuplot not installed — skipping afl-plot.[/]")
        return None
    if plot_dir.exists():
        shutil.rmtree(plot_dir, ignore_errors=True)
    plot_dir.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            [str(afl_plot), str(cfg.afl_out_dir), str(plot_dir)],
            check=True, capture_output=True,
        )
    except subprocess.CalledProcessError as exc:
        console.print(f"[yellow]afl-plot failed:[/] {exc.stderr.decode(errors='replace')}")
        return None
    return plot_dir


def _show_plot_inline(plot_dir: Path) -> None:
    """List generated PNGs; do not render to terminal."""
    pngs = sorted(plot_dir.glob("*.png"))
    if not pngs:
        console.print("[yellow]no PNG generated by afl-plot.[/]")
        return
    console.print(Panel(
        "\n".join(f"  {p}" for p in pngs),
        title="afl-plot images (open in any viewer for screenshots)",
        border_style="green",
    ))


def main() -> int:
    args = parse_args()
    cfg = Config.from_args(args)
    llm = LLM(cfg)

    plan = _ensure_plan(cfg, llm, args.force)
    harness_bin = _ensure_harness(cfg, llm, plan, args.force)
    _show_driver(cfg.harness_dir / "harness.c")

    seeds.provision_seeds(cfg.seeds_dir, plan.get("seed_strategy", "url"))

    rc = _run_afl_foreground(cfg, harness_bin, cfg.seeds_dir)

    console.rule("[bold green]Dynamic analysis finished")
    stats = afl.parse_fuzzer_stats(cfg.afl_out_dir)
    if stats:
        _render_stats(stats, cfg.afl_out_dir)

    # Persist findings so the synthesis step can pick them up.
    crashes = afl.collect_crashes(cfg.afl_out_dir, limit=args.max_crashes)
    (cfg.workdir / "dynamic_findings.json").write_text(
        json.dumps({"stats": stats, "crashes": crashes,
                    "out_dir": str(cfg.afl_out_dir)},
                   indent=2, ensure_ascii=False)
    )

    plot_dir = _try_afl_plot(cfg)
    if plot_dir:
        _show_plot_inline(plot_dir)

    console.rule("[bold]READY FOR SCREENSHOT")
    console.print(
        "[bold yellow]Window will stay open. Press Ctrl+C to exit.[/]\n"
        f"[dim]rc={rc}  stats={cfg.afl_out_dir / 'fuzzer_stats'}[/]"
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
