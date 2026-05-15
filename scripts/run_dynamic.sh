#!/usr/bin/env bash
# 动态分析 — 运行 AFL 12h（或自定义时长），把 AFL TUI 保持在前台，
# 结束后自动生成 afl-plot，并停留在终端等待截图。
#
# 用法:
#   bash scripts/run_dynamic.sh [target] [fuzz_seconds]
#
# 例:
#   bash scripts/run_dynamic.sh curl 43200
set -euo pipefail

cd "$(dirname "$0")/.."
TARGET="${1:-curl}"
FUZZ_SECONDS="${2:-43200}"

if [[ ! -f venv/bin/activate ]]; then
  echo "venv missing — run: python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt" >&2
  exit 1
fi
# shellcheck disable=SC1091
source venv/bin/activate

exec python -m agent.run_dynamic --target "$TARGET" --fuzz-seconds "$FUZZ_SECONDS"
