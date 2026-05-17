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

### 3.5 三脚本截图模式（推荐用于交作业）

作业报告需要三类截图：**手写 driver、12 h fuzz、静态分析**。为方便逐项截屏，
仓库另提供三个独立脚本（位于 `scripts/`），分别对应一个阶段。每个脚本在终端
里直接渲染本阶段产物，**结束后停在该窗口不退出**，按 `Ctrl+C` 才返回 shell —
可以从容地按 PrtSc / 截图工具截屏。

| 脚本 | 对应 Python 入口 | 默认 target | 关键参数 | 截屏什么 |
|------|------------------|-------------|----------|---------|
| `scripts/run_static.sh` | `agent/run_static.py` | `curl` | — | clang 版本面板 + 全部 warning 表格 |
| `scripts/run_dynamic.sh` | `agent/run_dynamic.py` | `curl` | `[fuzz_seconds]`，默认 `43200`（12 h） | ① 手写 driver 高亮源码（启动时）<br>② AFL TUI（运行中，自动占据整屏）<br>③ `fuzzer_stats` 表格 + `afl-plot` PNG 路径（结束后） |
| `scripts/run_synthesize.sh` | `agent/run_synthesize.py` | `curl` | — | LLM 诊断 + Markdown / JSON 报告路径 |

> 三个脚本都共享同一个 `work/` 目录；只要某阶段已经跑过，下次再跑会复用其
> 产物（plan / 插桩库 / harness 等）。先 `run_static.sh`、再 `run_dynamic.sh`
> （12 h）、最后 `run_synthesize.sh` 是推荐顺序。

#### 3.5.1 完整三步示例

```bash
cd software_measure
source venv/bin/activate

# ① 静态分析 — 跑完后停在告警表格，截图后 Ctrl+C
bash scripts/run_static.sh curl

# ② 12 h 动态 fuzz — 先按 ENTER 启动 AFL TUI；
#    12 h 到时自动退出 TUI、显示 fuzzer_stats + afl-plot 图片路径，
#    脚本不退出，等你截完图按 Ctrl+C
bash scripts/run_dynamic.sh curl 43200

# ③ 综合（LLM 诊断 + 生成报告）— 不需要截图，但产物用于报告正文
bash scripts/run_synthesize.sh curl
```

每个脚本第一行都会自动 `source venv/bin/activate`，所以无论当前 shell 是不是
已激活 venv 都能直接跑。

#### 3.5.2 怎么"画"手写 driver（截图项 1）

"手写 driver" 在本项目中 = `work/harness/harness.c`（由 HarnessAgent 让 LLM 生
成的 fuzz harness）。`run_dynamic.sh` 在启动 AFL 之前会用 Rich 在终端打印一
个带行号、彩色高亮、Monokai 主题的面板：

```
╭────────────── fuzz driver — work/harness/harness.c ──────────────╮
│  1  #include <stdio.h>                                            │
│  2  #include <stdlib.h>                                           │
│  3  #include <curl/curl.h>                                        │
│  …                                                                │
╰───────────────────────────────────────────────────────────────────╯
```

这一屏出现时就直接截图。如果只想看 driver、不跑 fuzz，可以单独打开它：

```bash
# 终端里彩色高亮预览（同 run_dynamic.sh 用的渲染）
source venv/bin/activate
python -c "
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
p='work/harness/harness.c'
Console().print(Panel(Syntax(open(p).read(),'c',line_numbers=True,theme='monokai'),
                      title=p, border_style='cyan'))
"

# 或直接用 bat（如装了）
bat work/harness/harness.c
```

> 若 `work/harness/harness.c` 还不存在，先跑一次 `python main.py --mode harness
> --target curl` 或 `bash scripts/run_dynamic.sh curl 60`（短 fuzz 即可生成）。

#### 3.5.3 怎么导出 afl-plot 图片（截图项 2）

`run_dynamic.sh` 结束时自动调用 `afl-plot work/afl-out work/afl-plot/`，PNG
落到 `work/afl-plot/`：

- `high_freq.png` — paths_total / pending_total 趋势（1000×300）
- `low_freq.png` — unique_crashes / unique_hangs 趋势（1000×200）
- `exec_speed.png` — execs/sec 趋势（1000×200）
- `index.html` — 把三张图嵌好的汇总页

脚本不会在终端里渲染图片，只打印 PNG 的绝对路径 —— 用 VSCode / 浏览器 /
任何图片查看器打开 PNG 截屏即可。前置依赖只有一个：

```bash
sudo apt install -y gnuplot-nox   # afl-plot 依赖；不装则 _try_afl_plot 静默跳过
```

跨多个项目复用：把 `work/afl-plot/*.png` 拷到 `report/img/<target>/`，再在
`report/<target>_report.md` 里 `![cov](img/<target>/high_freq.png)` 引用。

#### 3.5.4 跑其他被测库

⚠️ 当前 `agent/config.py` 把所有产物写到同一个 `work/`。**切换 target 之前
务必把上一次的 `work/` 备份**，否则 harness / afl-out / 报告会被覆盖：

```bash
# 假设已按 §9 把 libpcap / libvpx 加进 agent/config.py::TARGETS

# 跑 curl，跑完后归档
bash scripts/run_dynamic.sh curl 43200
mv work work-curl

# 跑 libpcap，新建 work/
bash scripts/run_static.sh   libpcap
bash scripts/run_dynamic.sh  libpcap 43200
mv work work-libpcap

# 同理 libvpx
bash scripts/run_dynamic.sh  libvpx 43200
mv work work-libvpx

# 写报告时统一从 work-<target>/ 取 PNG + harness.c + report.md
```

或者每次跑前 `--workdir work-<target>` 也行（同 `main.py` 接受该参数；脚本未
透传，需要直接调 `python -m agent.run_dynamic --target libpcap --workdir
work-libpcap --fuzz-seconds 43200`）。

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

### 5.1 设计思路

本项目的核心论点是：**"挖漏洞"这件事可以被拆成一组"LLM 推理 + 确定性工具"的小步骤**，
而不是让 LLM 端到端"看代码找 bug"。LLM 擅长的是「在大量自然语言 / 代码片段中做归类、
选择和模板填空」，而 AFL / Clang Static Analyzer 等成熟工具擅长的是「机械地、可重复地
执行漏洞挖掘动作」。两者各取所长：

| 职责 | 由谁完成 | 为什么 |
|---|---|---|
| 选 fuzz 入口 API、决定要分析哪个文件 | **LLM**（Planner） | 需要读 README 自然语言、按头文件签名做语义判断 |
| 写出能编译过、能触发解析逻辑的 harness.c | **LLM**（Harness） | 是高度模板化的代码生成任务，但 API 形参组合多 |
| 真正去执行覆盖率引导的输入变异 | **AFL**（工具） | 这是确定性的、需要十亿级 execs 的工程任务，LLM 无法替代 |
| 真正去做路径敏感的污点 / 死代码分析 | **Clang Static Analyzer**（工具） | 同上，需要编译器前端能力 |
| 把上千条工具告警 / crash 归类、判严重性、写人话 | **LLM**（Diagnostic + Reporter） | 工具只输出位置和类别码，缺少业务语义和优先级判断 |

由此得出一条原则：**LLM 不进入热循环**。Agent 在流水线上只出现 4 次（Plan / Harness /
Diagnose / Report），其余时间都是工具在跑。这样 12 h fuzz 的 LLM 成本 < 10 万 tokens。

### 5.2 各 Agent 详解

#### 5.2.1 PlannerAgent — [agent/agents/planner.py](agent/agents/planner.py)

- **输入**：被测库的 `README.md` 头部 + 主要公共头文件（`curl/include/curl/*.h`）的摘录。
- **工具**：`agent/tools/parser.py` 负责截取头文件签名；不调用编译器。
- **LLM**：`gpt-4.1-mini`，`response_format=json_object`，提示词在 [agent/prompts/planner.md](agent/prompts/planner.md)。
- **输出**：`work/plan.json`，结构

  ```json
  {
    "target_file":        "lib/urlapi.c",
    "target_api":         "curl_url_set",
    "seed_strategy":      "url",
    "static_focus_files": ["lib/urlapi.c", "lib/escape.c", "lib/hostip.c"]
  }
  ```
- **作用**：把后续静态 / 动态分析从"对全工程开炮"收敛到"针对最值得攻击的入口"，
  显著缩小搜索空间并让 12 h 预算花在刀刃上。

#### 5.2.2 StaticAgent — [agent/agents/static_agent.py](agent/agents/static_agent.py)

- **输入**：Planner 输出的 `static_focus_files`，被测库源码。
- **工具**：
  - `agent/tools/clang_sa.py::run_focused_clang_analyze()` — 对 3 个 planner
    选中的 `.c` 调 `clang --analyze -Xanalyzer -analyzer-output=html`，30 s 级。
  - `agent/tools/clang_sa.py::run_scan_build()` — 可选的 `scan-build make -j2`
    全工程扫描，30–60 min（受 `AGENT_SKIP_SCAN_BUILD=1` 控制）。
- **LLM**：**不调用**。它是一个纯工具调度 Agent。
- **输出**：`work/static_findings.json` + `work/scan-build-reports/**/*.html`。
- **作用**：在动态测试还没起跑前，就把可被静态规则发现的 NULL deref / 未初始化
  内存 / 死代码先扫一遍，作为 fuzz 的"对照组"。

#### 5.2.3 HarnessAgent — [agent/agents/harness_agent.py](agent/agents/harness_agent.py)

- **输入**：`target_api` 名称 + 对应头文件签名 + Planner 给的 `seed_strategy`。
- **工具**：
  - `agent/tools/shell.py::run()` 调 `afl-gcc` 编译 harness 并链接 `libcurl.a`。
  - 若链接失败（缺 `-lz`、`-lssl` 等），回退到 dry-run 错误信息让 LLM 重试。
- **LLM**：`gpt-4.1-mini`，提示词 [agent/prompts/harness.md](agent/prompts/harness.md)，
  要求生成单文件 C，**避免** `__AFL_LOOP`（AFL 2.52b 的 afl-gcc 不支持 persistent mode）。
- **输出**：`work/harness/harness.c`（"手写 driver"）+ `work/harness/harness_afl`（插桩二进制）。
- **作用**：自动消除"为每个新库人工写一份 harness.c"的体力活；Planner + Harness
  的组合让新增 target 只需要在 `agent/config.py::TARGETS` 加一条目即可。

#### 5.2.4 DynamicAgent — [agent/agents/dynamic_agent.py](agent/agents/dynamic_agent.py)

- **输入**：`harness_afl` + 由 [agent/tools/seeds.py](agent/tools/seeds.py) 按 `seed_strategy` 准备的种子语料。
- **工具**：`agent/tools/afl.py` 封装
  - `afl-fuzz -i seeds -o afl-out -t 5000 -m none -- harness_afl @@`
  - 12 h 墙钟由 `subprocess.run(timeout=...)` 控制。
  - `afl-plot` 在结束后生成 `high_freq.png` / `low_freq.png` / `exec_speed.png`。
- **LLM**：**不调用**。Agent 只做参数装配、超时控制、产物解析。
- **输出**：`work/afl-out/{queue,crashes,hangs,fuzzer_stats,plot_data}` +
  `work/dynamic_findings.json`（已对 unique crash 去重）+ `work/afl-plot/*.png`。
- **作用**：把 AFL 包装成一个"可被流水线调度的步骤"，同时为后续 Diagnostic 提
  供结构化输入（crash 的 hexdump、execs/sec、唯一 crash 数）。

#### 5.2.5 DiagnosticAgent — [agent/agents/diagnostic_agent.py](agent/agents/diagnostic_agent.py)

- **输入**：
  - 静态告警列表（每条带 `file:line + category + 上下文 3 行`）。
  - 动态 crash 列表（每条带 16 字节 hexdump + 触发的 API 调用）。
  - `harness.c` 全文（让 LLM 知道是被怎么调进去的）。
- **工具**：无外部工具调用；纯 LLM 归类。
- **LLM**：对每条 finding **独立**调用一次 `gpt-4.1-mini`，
  `response_format=json_object`，提示词分两份：
  [agent/prompts/static_diagnosis.md](agent/prompts/static_diagnosis.md) /
  [agent/prompts/dynamic_diagnosis.md](agent/prompts/dynamic_diagnosis.md)。
  调用并行度由 `agent/llm.py` 的 `tenacity` 退避控制，5xx 自动重试。
- **输出**：`work/diagnoses.json`，每条形如

  ```json
  {
    "finding_id":   "static#7",
    "category":     "NULL pointer dereference",
    "severity":     "medium",
    "root_cause":   "Hostname 解析失败时 hostp 仍被 strcpy",
    "fix":          "在 Curl_str_until 之后判 NULL 再 memcpy",
    "confidence":   0.78
  }
  ```
- **作用**：把工具的"干警告"翻译成人能直接做优先级排序的"漏洞条目"。
  这一步是整个流水线唯一一处"LLM 在做判断"，其他三处都是"LLM 在做模板填空"。

#### 5.2.6 ReporterAgent — [agent/agents/reporter.py](agent/agents/reporter.py)

- **输入**：Plan + 静态 findings + 动态 findings + 全部 diagnoses。
- **工具**：无；纯 LLM 文本生成。
- **LLM**：`gpt-4.1-mini`，提示词 [agent/prompts/report.md](agent/prompts/report.md)，
  这次**不**用 JSON 模式 —— 输出直接是 Markdown。
- **输出**：`work/report.md`（人读，2–4 KB）+ `work/report.json`（机读，含原始 findings）。
- **作用**：把多源结果合成一份可交作业的报告样例；与 `report/curl_report.md` 风格一致。

### 5.3 LLM 调用约定（全部走 [agent/llm.py](agent/llm.py)）

| 维度 | 设定 | 理由 |
|---|---|---|
| 模型 | `gpt-4.1-mini`（可由 `OPENAI_MODEL` 覆盖） | 价格 / 上下文 / JSON mode 兼容性的平衡点 |
| 温度 | `0`（Planner / Diagnostic）/ `0.3`（Harness / Reporter） | 判断类要稳定；生成类留一点变化 |
| 输出格式 | Planner / Diagnostic → `response_format=json_object`<br>Harness / Reporter → 自由文本（C 源码 / Markdown） | 下游需要解析 vs. 需要可读性 |
| 重试 | `tenacity` 指数回退，最多 5 次，仅对 5xx / 超时 | 容忍代理偶发抖动，不掩盖 4xx 配置错误 |
| 上下文 | 每次调用 ≤ 4 k tokens，平均 ≈ 1 k | LLM 不进入热循环，单次跑全流水线总 token < 10 万 |

### 5.4 与动态 / 静态工具的结合方式

```
                ┌──── plan.json ─────┐
   PlannerAgent ┤                    ├── 选 target_file & static_focus_files
                └────────────────────┘
                          │
        ┌─────────────────┴─────────────────┐
        ▼                                   ▼
 StaticAgent ──► clang --analyze       HarnessAgent ──► afl-gcc harness.c
                scan-build make                          → harness_afl
        │                                   │
        ▼                                   ▼
 static_findings.json               DynamicAgent ──► afl-fuzz 12 h
                                                    afl-plot → PNG
        │                                   │
        └──────────────► DiagnosticAgent ◄──┘   # 同时吃静态 + 动态结果
                          │
                          ▼
                   ReporterAgent ──► report.md / report.json
```

关键耦合点：

1. **Planner → Static**：Planner 给 `static_focus_files`，Static 只跑这几个文件，
   避免 30–60 min 的全工程扫描。可以理解为「让 LLM 给 Clang 圈重点」。
2. **Planner → Harness**：Planner 给 `target_api` 和 `seed_strategy`，Harness 知道
   要 fuzz `curl_url_set`，要喂 URL 字符串。即「让 LLM 给 AFL 选靶子和饵料」。
3. **AFL plot_data → afl-plot → PNG**：Dynamic 跑完后才有 `plot_data` CSV，调
   `afl-plot` 生成 3 张趋势图作为报告截图素材。
4. **Static + Dynamic → Diagnostic**：两路结果合并送进同一个 Diagnostic，让 LLM
   有可能识别出"静态报的 NULL deref 和动态 crash 是同一根因"。
5. **断点续跑**：每个 stage 写 `work/.<stage>.done`，下次重跑会跳过；删掉对应标记即可单独重跑某个 Agent。

### 5.5 任务分解方式（为什么这样切）

- **以"工具输入 / 输出"作为切分边界**：切分点都落在持久化文件上
  （`plan.json` / `harness_afl` / `*.json`），方便单独重跑、单独截图、单独调试。
- **LLM 步骤要么"挑选"要么"归类"，不让 LLM 直接看 12 h 的原始 fuzz 输出**：
  Diagnostic 拿到的是已经被 `agent/tools/afl.py::collect_crashes(limit=20)` 截断、
  去重过的 hexdump，LLM 无须处理 GB 级数据。
- **同一类 finding 调用粒度细到每条**：Diagnostic 对每条 finding 单独问 LLM，
  好处是 prompt 简短、可并行；代价是 N 次小调用，但每次 < 1 k tokens 远比一次
  20 k tokens 的大批量更稳。
- **Reporter 是"汇总"而不是"再分析"**：所有判断在 Diagnostic 阶段就结束；
  Reporter 只是把 JSON 重新组织成 Markdown，避免再次推理引入不一致结论。

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
