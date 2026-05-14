"""HarnessAgent: use LLM to synthesize a C harness, then compile it."""
from __future__ import annotations

import logging
import re
from pathlib import Path

from ..config import Config
from ..llm import LLM, load_prompt
from ..tools import afl
from ..tools.parser import find_header, read_excerpt

log = logging.getLogger("agent.harness")


class HarnessAgent:
    def __init__(self, cfg: Config, llm: LLM):
        self.cfg = cfg
        self.llm = llm

    def run(self, plan: dict) -> Path:
        self.cfg.harness_dir.mkdir(parents=True, exist_ok=True)
        target = self.cfg.target
        api = plan.get("target_api") or target.default_api_hint
        seed_strategy = plan.get("seed_strategy", "url")
        header = find_header(target.headers_dir, api)
        header_excerpt = (
            f"// from {header}\n{read_excerpt(header, max_bytes=4000)}"
            if header else "<no header found>"
        )

        user = (
            f"library: {target.name}\n"
            f"target_api: {api}\n"
            f"seed_strategy: {seed_strategy}\n"
            f"static_library: {target.primary_libs[0]}\n"
            f"--- header ---\n{header_excerpt}\n"
        )
        raw = self.llm.chat(
            system=load_prompt("harness.md"),
            user=user,
            max_tokens=1500,
            temperature=0.1,
        )
        c_source = _strip_code_fences(raw)
        harness_c = self.cfg.harness_dir / "harness.c"
        harness_c.write_text(c_source, encoding="utf-8")
        log.info("harness.c written (%d bytes)", len(c_source))

        primary_lib = Path(target.primary_libs[0])
        if primary_lib.exists() and not self.cfg.force:
            log.info("instrumented lib already present at %s — skipping rebuild",
                     primary_lib)
        else:
            log.info("building instrumented target lib")
            afl.build_target_instrumented(self.cfg)

        log.info("compiling harness with afl-gcc")
        harness_bin = afl.compile_harness(self.cfg, harness_c)
        log.info("harness binary: %s", harness_bin)
        return harness_bin


def _strip_code_fences(text: str) -> str:
    text = text.strip()
    m = re.match(r"^```(?:c|C)?\s*\n(.*?)\n```\s*$", text, re.DOTALL)
    return m.group(1) if m else text
