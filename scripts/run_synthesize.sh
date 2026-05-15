#!/usr/bin/env bash
# 综合 Agent — 读取 work/ 下静态 + 动态产物，调用 LLM 做诊断并生成报告。
#
# 用法:
#   bash scripts/run_synthesize.sh [target]
set -euo pipefail

cd "$(dirname "$0")/.."
TARGET="${1:-curl}"

if [[ ! -f venv/bin/activate ]]; then
  echo "venv missing — run: python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt" >&2
  exit 1
fi
# shellcheck disable=SC1091
source venv/bin/activate

exec python -m agent.run_synthesize --target "$TARGET"
