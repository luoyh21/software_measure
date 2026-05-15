#!/usr/bin/env bash
# 静态分析 — 运行 Clang Static Analyzer，在终端渲染告警表格供截图。
#
# 用法:
#   bash scripts/run_static.sh [target]
#
# 默认 target=curl。会自动激活 venv。
set -euo pipefail

cd "$(dirname "$0")/.."
TARGET="${1:-curl}"

if [[ ! -f venv/bin/activate ]]; then
  echo "venv missing — run: python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt" >&2
  exit 1
fi
# shellcheck disable=SC1091
source venv/bin/activate

# Default to "focused" mode (clang --analyze per planner-selected file).
# Set AGENT_SKIP_SCAN_BUILD=0 (or unset) to also run the slow full scan-build.
export AGENT_SKIP_SCAN_BUILD="${AGENT_SKIP_SCAN_BUILD:-1}"

exec python -m agent.run_static --target "$TARGET"
