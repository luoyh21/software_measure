"""PlannerAgent: decide what to fuzz and what to statically analyze."""
from __future__ import annotations

import json
import logging
from pathlib import Path

from ..config import Config
from ..llm import LLM, load_prompt
from ..tools.parser import find_header, read_excerpt

log = logging.getLogger("agent.planner")


class PlannerAgent:
    def __init__(self, cfg: Config, llm: LLM):
        self.cfg = cfg
        self.llm = llm

    def run(self) -> dict:
        target = self.cfg.target
        readme_path = target.source_dir / "README"
        if not readme_path.exists():
            readme_path = target.source_dir / "README.md"
        readme_excerpt = read_excerpt(readme_path, max_bytes=2000)

        header = find_header(target.headers_dir, self.cfg.api_hint or target.default_api_hint)
        header_excerpt = (
            f"// header: {header}\n{read_excerpt(header, max_bytes=4000)}"
            if header else "<no header found>"
        )

        user = (
            f"library: {target.name}\n"
            f"api_hint: {self.cfg.api_hint or '(none)'}\n"
            f"--- README excerpt ---\n{readme_excerpt}\n"
            f"--- header excerpt ---\n{header_excerpt}\n"
        )
        plan = self.llm.chat_json(
            system=load_prompt("planner.md"),
            user=user,
            max_tokens=600,
        )

        plan.setdefault("target_api", self.cfg.api_hint or target.default_api_hint)
        plan.setdefault("seed_strategy", "url")
        plan.setdefault("static_focus_files", [])

        self.cfg.plan_path.parent.mkdir(parents=True, exist_ok=True)
        self.cfg.plan_path.write_text(json.dumps(plan, indent=2, ensure_ascii=False))
        log.info("plan written: %s", self.cfg.plan_path)
        return plan
