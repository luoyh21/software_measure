"""CLI entry point for the agent-driven vulnerability detection workflow."""
from __future__ import annotations

import argparse
import sys

from agent.config import Config
from agent.pipeline import Pipeline


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="software_measure",
        description="Agent-driven dynamic+static vulnerability detection.",
    )
    p.add_argument("--target", default="curl", help="Target library key (default: curl).")
    p.add_argument(
        "--mode",
        default="all",
        choices=["all", "plan", "static", "harness", "dynamic", "diagnose", "report"],
        help="Which stage(s) to run.",
    )
    p.add_argument("--api", default=None, help="Hint for the planner about which API to focus on.")
    p.add_argument("--fuzz-seconds", type=int, default=600, help="AFL wall-clock budget.")
    p.add_argument("--workdir", default="work", help="Working directory for artifacts.")
    p.add_argument("--max-warnings", type=int, default=20)
    p.add_argument("--max-crashes", type=int, default=20)
    p.add_argument("--force", action="store_true", help="Re-run stages even if marked done.")
    p.add_argument("--dry-run", action="store_true", help="Print commands without running.")
    p.add_argument("--asan", action="store_true", help="Build target with AddressSanitizer.")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    cfg = Config.from_args(args)
    pipeline = Pipeline(cfg)
    return pipeline.run(mode=args.mode)


if __name__ == "__main__":
    sys.exit(main())
