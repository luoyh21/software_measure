# software_measure — Agent 驱动的漏洞挖掘工作流

软件度量课程大作业。本仓库实现了一个 **Agent 工具流**，将 **动态测试 (AFL)** 与 **静态分析 (Clang Static Analyzer)** 串联起来，
并使用 GPT-4.1-mini 完成：

1. **测试入口规划**：根据目标库 README/头文件让 LLM 选择 fuzz API；
2. **fuzz harness 自动生成**：让 LLM 写出可被 `afl-gcc` 编译的 C harness；
3. **崩溃 / 警告诊断**：LLM 对 AFL crash 输入与 Clang 静态警告打标签（类别、严重性、可能根因、修复建议）；
4. **报告自动汇总**：输出 Markdown + 结构化 JSON。

当前以 `curl` 作为首个目标库，后续可扩展到 `libpcap`、`libvpx`。

> 本次实际跑出的样例报告见 [report/curl_report.md](report/curl_report.md)。

---

## 0. 前置检查清单 ✅

在执行 `python main.py` 之前请按顺序确认下列项。任意一项不满足都可能导致流水线在长耗时阶段失败。

| # | 检查项 | 校验命令 | 期望 |
|---|---|---|---|
| 1 | Linux 系统（建议 Ubuntu 22.04+） | `uname -a` | `Linux ... x86_64` |
| 2 | Python ≥ 3.9 | `python3 --version` | `Python 3.10.x` 或更高 |
| 3 | 可用磁盘 ≥ 15 GB | `df -h .` | `Avail` 列 ≥ 15 G |
| 4 | autotools 三件套 + libtool | `which autoreconf libtoolize automake` | 三条均输出路径 |
| 5 | `gcc` / `make` / `xz` 可用 | `gcc --version && make --version && xz --version` | 均有输出 |
| 6 | AFL 已编译 | `ls afl-2.52b/afl-fuzz afl-2.52b/afl-gcc` | 两个文件都存在 |
| 7 | Clang+LLVM tarball 在位 | `ls clang+llvm-18.1.8-x86_64-linux-gnu-ubuntu-18.04.tar.xz` | 文件大小 ≈ 1 GB |
| 8 | 被测库源码在位 | `ls curl/configure.ac` | 存在 |
| 9 | AFL `core_pattern` 已设置 | `cat /proc/sys/kernel/core_pattern` | 输出 `core` |
| 10 | OpenAI 代理可达 | `curl -s -o /dev/null -w '%{http_code}\n' "$OPENAI_BASE_URL/models" -H "Authorization: Bearer $OPENAI_API_KEY"` | `200` 或 `401`（≠ `000`） |

任何一项失败，请参考下文 **§1 系统准备** 修复后再进入 **§2 安装**。

---

## 1. 系统准备

### 1.1 安装系统依赖

```bash
sudo apt update
sudo apt install -y \
    python3 python3-venv python3-pip \
    build-essential gcc make xz-utils tar \
    autoconf automake libtool pkg-config m4
```

### 1.2 配置 AFL 必需的内核参数（需要 sudo）

AFL 会在 fuzz 启动前自检；缺少这些设置时 AFL 直接拒绝运行。

```bash
# 关闭 apport / systemd-coredump 截获崩溃，让 AFL 能拿到 SIGSEGV
sudo bash -c 'echo core > /proc/sys/kernel/core_pattern'

# 可选：把 CPU 调到 performance 模式，让 fuzz 速率稳定
sudo bash -c 'cd /sys/devices/system/cpu && \
              for c in cpu*/cpufreq/scaling_governor; do echo performance > $c; done' \
    2>/dev/null || true
```

> 容器或受限环境改不了 `core_pattern`？设置环境变量 `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1` 让 AFL 跳过该自检（会牺牲 crash 收集精度）。

### 1.3 准备被测项目与工具

下表中三类外部资源 **必须自行放置到** `software_measure/` 下（已在 `.gitignore` 中排除，不入仓）。

| 路径 | 获取方式 | 用途 |
|------|---------|------|
| `curl/` | `git clone https://github.com/curl/curl.git` | 被测库源码 |
| `afl-2.52b/` | `wget http://lcamtuf.coredump.cx/afl/releases/afl-2.52b.tgz && tar xf afl-2.52b.tgz && cd afl-2.52b && make` | 必须 `make` 完，确保 `afl-fuzz`、`afl-gcc` 是可执行二进制 |
| `clang+llvm-18.1.8-x86_64-linux-gnu-ubuntu-18.04.tar.xz` | 从 https://github.com/llvm/llvm-project/releases/tag/llvmorg-18.1.8 下载预编译版 | Agent 首次运行时**自动解压**到同名目录（约 1 GB → 7 GB，5–25 分钟） |

> 若你的 Ubuntu 版本比 18.04 新且系统已有 `clang-18`，可以跳过此 tarball；修改 `agent/config.py::Config.scan_build/clang` 指向系统路径即可。但官方提供的 ubuntu-18.04 build 对老 glibc 兼容更好，推荐保留。

---

## 2. 安装 Python 依赖

```bash
cd software_measure
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# 编辑 .env，填入 OPENAI_API_KEY / OPENAI_BASE_URL
```

`.env` 期望的字段（已在 `.env.example` 中给出）：

```dotenv
OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
OPENAI_BASE_URL=https://llmapi.bc-inner.com/v1
OPENAI_MODEL=gpt-4.1-mini
```

---

## 3. 第一次运行

### 3.1 入口命令

```bash
source venv/bin/activate
python main.py --target curl --mode all --fuzz-seconds 600
```

### 3.2 预期阶段与耗时

下表的耗时基于 JuiceFS 远端 FS；本地 ext4 通常快 2–5 倍。

| 阶段 | 工作内容 | 首次耗时（JuiceFS） | 缓存后耗时 |
|---|---|---|---|
| Plan | 读 README + 头文件 → LLM 选 fuzz API | < 30 s | 缓存跳过 |
| **解压 clang+llvm** | `tar xf` 1 GB → 7 GB | **5–25 分钟** | 已解压则跳过 |
| Static (focused) | `clang --analyze` 跑 planner 选的 3 个 .c 文件 | ≈ 30 s | 缓存跳过 |
| Static (full scan-build) | `scan-build make -j2` 全工程 | **30–60 分钟** | 通过 `AGENT_SKIP_SCAN_BUILD=1` 跳过 |
| Harness | LLM 写 `harness.c` + afl-gcc 编译 | ≈ 2 分钟 | 缓存跳过 |
| AFL 插桩构建 libcurl | `CC=afl-gcc ./configure && make -j2` | **20–40 分钟** | 看到 `libcurl.a` 存在则跳过 |
| Dynamic | `afl-fuzz` 跑 `--fuzz-seconds` | 按设置 | 不缓存 |
| Diagnose + Report | LLM 多次小调用 + 生成 markdown | 1–2 分钟 | 不缓存 |

**首次完整跑大约 1.5 – 3 小时（不含 fuzz 时长本身）**。每个阶段都会在 `work/.<stage>.done` 留下标记，下次重跑可断点续跑。

### 3.3 加速建议

跑通一次后，绝大多数情况只需要重跑 harness / dynamic：

```bash
# 跳过最慢的 scan-build 全量扫描，使用 focused 模式静分（推荐）
AGENT_SKIP_SCAN_BUILD=1 python main.py --target curl --mode all --fuzz-seconds 900

# 只重跑 harness 之后的阶段（保留已有 plan/static 结果）
rm work/.harness.done work/.dynamic.done work/.diagnose.done work/.report.done
AGENT_SKIP_SCAN_BUILD=1 python main.py --target curl --mode all --fuzz-seconds 900
```

### 3.4 复现作业要求的 12 小时 fuzz

```bash
nohup python main.py --target curl --mode all --fuzz-seconds 43200 \
      > work_12h.log 2>&1 &
tail -f work_12h.log

# 期间观察 AFL TUI（另开终端）
watch -n 5 cat work/afl-out/fuzzer_stats
```

跑完后 `afl-plot work/afl-out work/afl-plot/` 可生成覆盖率趋势图供报告截图。

---

## 4. CLI 参数完整列表

```
python main.py [--target TARGET] [--mode MODE] [--api HINT]
               [--fuzz-seconds N] [--workdir DIR]
               [--max-warnings N] [--max-crashes N]
               [--force] [--dry-run] [--asan]
```

| 参数 | 说明 | 默认 |
|------|------|------|
| `--target` | 被测库（当前内置 `curl`，`libpcap` / `libvpx` 占位） | `curl` |
| `--mode` | `all` / `plan` / `static` / `harness` / `dynamic` / `diagnose` / `report` | `all` |
| `--api` | Planner 的提示性 hint，决定 harness 围绕哪类 API（如 `curl_url`） | 由 Planner 自动决定 |
| `--fuzz-seconds` | AFL 运行墙钟时长 | `600` |
| `--workdir` | 产物目录 | `work` |
| `--max-warnings` | 送给 LLM 诊断的静态警告上限 | `20` |
| `--max-crashes` | 送给 LLM 诊断的 crash 上限 | `20` |
| `--force` | 忽略所有 stage 的 `.done` 标记重跑 | `False` |
| `--dry-run` | 只打印将要执行的命令，不真正运行编译 / fuzz | `False` |
| `--asan` | 用 `AFL_USE_ASAN=1` 重新构建 libcurl 与 harness | `False` |

环境变量：

| 名称 | 作用 |
|---|---|
| `OPENAI_API_KEY` | LLM 鉴权（**必须**） |
| `OPENAI_BASE_URL` | OpenAI 兼容代理地址，默认 `https://api.openai.com/v1` |
| `OPENAI_MODEL` | 模型名，默认 `gpt-4.1-mini` |
| `AGENT_SKIP_SCAN_BUILD` | 设为 `1` 跳过最慢的 `scan-build make`，仅保留 focused 模式 |

---

## 5. Agent 工作流设计

```
┌──────────────┐
│  Planner     │  LLM 阅读 README + 头文件，输出
│              │  { target_file, target_api, seed_strategy, static_focus_files }
└──────┬───────┘
       │
   ┌───┴───────────────────────────────────────────┐
   ▼                                               ▼
┌─────────────────┐                          ┌────────────────┐
│ StaticAgent     │                          │ HarnessAgent   │
│ ① clang --analyze (focused)                │ LLM → harness.c│
│ ② scan-build make (optional, slow)         │ afl-gcc 链接   │
│ → HTML reports                             │ → harness_afl  │
└──┬──────────────┘                          └─────┬──────────┘
   │                                               │
   │                                          ┌────▼─────────┐
   │                                          │ DynamicAgent │
   │                                          │ afl-fuzz     │
   │                                          │ → crashes/   │
   │                                          └────┬─────────┘
   │                                               │
   └─────────────────┬─────────────────────────────┘
                     ▼
            ┌──────────────────┐
            │ DiagnosticAgent  │  LLM 对每个 warning / unique crash
            │                  │  打标签（类别、严重性、根因、修复建议）
            └────────┬─────────┘
                     ▼
              ┌─────────────┐
              │  Reporter   │  report.md  +  report.json
              └─────────────┘
```

- 单个 Agent = **单次 LLM 调用 + 工具封装**，不是多 Agent 辩论。
- 每个 stage 写 `work/.<stage>.done` 完成标记，便于分阶段 / 断点续跑（`--force` 忽略）。
- LLM 输入只携带必要片段（头文件、warning 段落、crash hexdump），单次调用平均 ≈ 1 k tokens。
- Diagnostic 与 Planner 使用 `response_format=json_object`，保证产物机器可读。

---

## 6. 产物结构

```
work/
├── plan.json                     # PlannerAgent 输出
├── scan-build-reports/
│   ├── focused/                  # clang --analyze 直接产物（每文件一目录）
│   │   └── lib__urlapi.c/report-*.html
│   └── 2026-05-xx-xx-xx-xx-*/    # scan-build 时间戳目录（如启用）
│       ├── index.html
│       └── report-*.html
├── harness/
│   ├── harness.c                 # LLM 生成的 fuzz driver
│   └── harness_afl               # AFL 插桩可执行
├── seeds/                        # 种子语料
├── afl-out/                      # AFL 输出
│   ├── fuzzer_stats
│   ├── plot_data
│   ├── crashes/                  # 唯一崩溃输入
│   ├── hangs/
│   └── queue/
├── static_findings.json
├── dynamic_findings.json
├── diagnoses.json                # LLM 对每个 finding 的标签
├── report.md                     # 人读
└── report.json                   # 机读
```

---

## 7. 目录结构（代码部分）

```
software_measure/
├── README.md                     # 本文件
├── report/
│   └── curl_report.md            # 已跑出的实验报告样例
├── requirements.txt
├── .env.example
├── .gitignore
├── main.py                       # CLI 入口
└── agent/
    ├── config.py                 # 路径 / 模型 / 环境变量
    ├── llm.py                    # OpenAI 客户端封装（重试 + JSON 模式）
    ├── pipeline.py               # 顺序编排
    ├── agents/
    │   ├── planner.py
    │   ├── static_agent.py       # 同时调度 focused + scan-build
    │   ├── harness_agent.py
    │   ├── dynamic_agent.py
    │   ├── diagnostic_agent.py
    │   └── reporter.py
    ├── tools/
    │   ├── shell.py              # subprocess 封装（含 timeout / dry-run）
    │   ├── clang_sa.py           # 解压 clang+llvm、focused/full 两种调用
    │   ├── afl.py                # afl-gcc / afl-fuzz / afl-cmin 封装
    │   ├── seeds.py
    │   └── parser.py
    └── prompts/                  # 各阶段 system prompt
        ├── planner.md
        ├── harness.md
        ├── static_diagnosis.md
        ├── dynamic_diagnosis.md
        └── report.md
```

---

## 8. 故障排查

| 现象 | 原因 / 处理 |
|---|---|
| `autoreconf: error: required file './ltmain.sh' not found` | `configure.ac` 含 `LT_INIT` 但 `libtoolize` 没跑。代码已自动处理；手动复现时执行 `cd curl && libtoolize --copy --force && autoreconf -fi`。 |
| `make: *** No targets specified and no makefile found` | `./configure` 未生成 `Makefile`。检查 §1.1 是否装好 `autoconf/automake/libtool`，然后 `--force` 重跑。 |
| `afl-fuzz` 报 `core_pattern` 错误 | 见 §1.2，或 `export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1`。 |
| `afl-fuzz` 报 CPU governor 错误 | 见 §1.2，或 `export AFL_SKIP_CPUFREQ=1`（已在 `agent/tools/afl.py` 默认设置）。 |
| `harness_afl: undefined reference to '__AFL_LOOP'` | AFL 2.52b 的 `afl-gcc` **不支持** persistent mode；persistent 需要 `afl-clang-fast` (LLVM mode)。当前 `prompts/harness.md` 已避免使用 `__AFL_LOOP`。 |
| `clang --analyze` 抱怨 `curl_config.h not found` | curl 尚未 configure。先 `python main.py --mode static` 让 Agent 完成 configure；或手动 `cd curl && ./configure --disable-shared --without-ssl ...`。 |
| `scan-build` 不出报告，目录是空 | 老版 scan-build 在 0 警告时会删空目录。`agent/tools/clang_sa.py::run_scan_build` 已默认加 `-keep-empty`；同时建议优先看 focused 模式（`work/scan-build-reports/focused/`）。 |
| LLM 超时 / 配额错误 | `.env` 中 `OPENAI_BASE_URL` 是否可达；Agent 对 5xx 已用 tenacity 指数回退；连续失败请检查代理网络。 |
| `harness_afl` 链接失败：`undefined reference to curl_url_*` | AFL 插桩 libcurl 没编出来。`rm work/.harness.done && python main.py --mode harness --force`。 |
| fuzz execs/sec 个位数 | 多半是 FS 慢（JuiceFS / NFS）；本地 ext4 通常 ≥ 1 k execs/sec。可考虑把 `work/` 软链到 `/tmp/work` 上的本地盘。 |
| 磁盘满 | clang+llvm 解压后 ≈ 7 GB，AFL queue 可在 12h 后达 1 GB，请确保 ≥ 15 GB 可用。 |

---

## 9. 扩展到其他被测库

```python
# 在 agent/config.py 中新增 Target：
def _libpcap_target() -> Target:
    src = REPO_ROOT / "libpcap"
    return Target(
        name="libpcap",
        source_dir=src,
        build_system="autotools",
        headers_dir=src,
        primary_libs=[str(src / "libpcap.a")],
        extra_link_libs=["-lpthread"],
        default_api_hint="pcap_open_offline",
    )

TARGETS["libpcap"] = _libpcap_target()
```

之后即可：

```bash
python main.py --target libpcap --mode all --fuzz-seconds 600
```

PlannerAgent 会自动适配新目标的 README 与头文件，HarnessAgent 会针对该库生成对应 harness。

---

## 10. 不要做的事

- ❌ 不要把 `curl/`、`afl-2.52b/`、`clang+llvm-*.tar.xz`、`venv/`、`work/` 加入版本控制（`.gitignore` 已排除）。
- ❌ 不要在 fuzz 进行中删除 `work/afl-out/`，会导致 `fuzzer_stats` 与 `plot_data` 丢失。
- ❌ 不要把真实 `OPENAI_API_KEY` 提交到 `.env.example`（请提交占位 `sk-replace-me`）。
- ❌ 不要随便升级 AFL 到 AFL++ 而不同步修改 `agent/tools/afl.py`：本框架明确针对 AFL 2.52b 的命令行（无 `-V`、不支持 persistent）做了适配。

---

## 11. 后续改进方向

| 优先级 | 改进 | 预期收益 |
|---|---|---|
| 高 | 编译 `afl-clang-fast` 或迁移到 AFL++，开启 persistent + deferred forkserver | execs/sec 提升 50–100× |
| 高 | 启用 `--asan` 跑长时 fuzz | 捕获 heap-overflow / UAF |
| 中 | 接入 libpcap、libvpx，满足作业 ≥3 项目要求 | — |
| 中 | DiagnosticAgent 后加 CriticAgent 二次审阅 | 减少 LLM 误报 |
| 低 | 自动从 git log 提取近期改动文件，优先 fuzz | 命中 regression |

---

参见 [report/curl_report.md](report/curl_report.md) 获取一次完整跑的样例报告。
