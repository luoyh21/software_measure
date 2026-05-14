"""ReporterAgent: combine all artifacts into report.md + report.json."""
from __future__ import annotations

import json
import logging
from datetime import datetime

from ..config import Config
from ..llm import LLM, load_prompt

log = logging.getLogger("agent.reporter")


class ReporterAgent:
    def __init__(self, cfg: Config, llm: LLM):
        self.cfg = cfg
        self.llm = llm

    def run(self, plan: dict, static_findings: list[dict],
            dynamic_findings: dict, diagnoses: dict) -> dict:
        summary = {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "target": self.cfg.target.name,
            "fuzz_seconds": self.cfg.fuzz_seconds,
            "plan": plan,
            "static_count": len(static_findings),
            "static_findings": static_findings,
            "dynamic_stats": dynamic_findings.get("stats", {}),
            "dynamic_crashes": dynamic_findings.get("crashes", []),
            "prereq_warnings": dynamic_findings.get("prereq_warnings", []),
            "diagnoses": diagnoses,
        }
        self.cfg.report_json.write_text(
            json.dumps(summary, indent=2, ensure_ascii=False)
        )

        markdown = self._render_markdown(summary)
        try:
            llm_md = self.llm.chat(
                system=load_prompt("report.md"),
                user=json.dumps(_compact(summary), ensure_ascii=False),
                max_tokens=1500,
                temperature=0.2,
            )
            markdown += "\n\n---\n\n## LLM 总结\n\n" + llm_md.strip() + "\n"
        except Exception as exc:
            log.warning("LLM summary failed: %s", exc)

        self.cfg.report_md.write_text(markdown, encoding="utf-8")
        log.info("report: %s", self.cfg.report_md)
        return summary

    def _render_markdown(self, s: dict) -> str:
        lines: list[str] = []
        plan = s.get("plan", {})
        lines.append(f"# software_measure report — {s['target']}")
        lines.append("")
        lines.append(f"- generated: `{s['generated_at']}`")
        lines.append(f"- fuzz duration: `{s['fuzz_seconds']}s`")
        lines.append(f"- planner target: `{plan.get('target_api')}` "
                     f"in `{plan.get('target_file')}`")
        lines.append("")
        lines.append("## 静态分析（Clang Static Analyzer）")
        lines.append(f"warnings: **{s['static_count']}**")
        lines.append("")
        for entry in s.get("diagnoses", {}).get("static", [])[:10]:
            f = entry["finding"]
            d = entry["diagnosis"]
            lines.append(
                f"- `{f.get('file')}:{f.get('line')}` — **{d.get('category')}** "
                f"({d.get('severity')}, conf={d.get('confidence')}) — "
                f"{d.get('likely_root_cause')}"
            )
        lines.append("")
        lines.append("## 动态测试（AFL）")
        stats = s.get("dynamic_stats", {})
        lines.append(f"- execs done: `{stats.get('execs_done', '?')}`")
        lines.append(f"- unique crashes: `{stats.get('unique_crashes', '?')}`")
        lines.append(f"- paths total: `{stats.get('paths_total', '?')}`")
        lines.append(f"- collected crash samples: `{len(s.get('dynamic_crashes', []))}`")
        lines.append("")
        for entry in s.get("diagnoses", {}).get("dynamic", [])[:20]:
            c = entry["crash"]
            d = entry["diagnosis"]
            lines.append(
                f"- `{c.get('id')}` ({c.get('size')} bytes) — **{d.get('category')}** "
                f"({d.get('severity')}) — {d.get('trigger_summary')}"
            )
        if s.get("prereq_warnings"):
            lines.append("")
            lines.append("## 运行环境提示")
            for w in s["prereq_warnings"]:
                lines.append(f"- {w}")
        return "\n".join(lines) + "\n"


def _compact(s: dict) -> dict:
    """Strip large/irrelevant fields before sending to the LLM."""
    return {
        "target": s["target"],
        "fuzz_seconds": s["fuzz_seconds"],
        "static_count": s["static_count"],
        "top_static": [
            {"file": e["finding"].get("file"), "line": e["finding"].get("line"),
             "category": e["diagnosis"].get("category"),
             "severity": e["diagnosis"].get("severity"),
             "root_cause": e["diagnosis"].get("likely_root_cause")}
            for e in s.get("diagnoses", {}).get("static", [])[:10]
        ],
        "dynamic_stats": s.get("dynamic_stats", {}),
        "dynamic_crashes": [
            {"id": e["crash"].get("id"),
             "category": e["diagnosis"].get("category"),
             "severity": e["diagnosis"].get("severity"),
             "trigger": e["diagnosis"].get("trigger_summary")}
            for e in s.get("diagnoses", {}).get("dynamic", [])[:20]
        ],
    }
