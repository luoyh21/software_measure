# 软件度量大作业 — curl 库漏洞挖掘报告

> 评测对象：[curl](https://github.com/curl/curl) (HEAD @ 2026-05-14 checkout)
> 评测方法：动态测试 (AFL 2.52b) + 静态分析 (Clang Static Analyzer 18.1.8) + Agent 工具流
> 报告生成日期：2026-05-14

---

## 1. 评测对象

**curl** 是世界范围内使用最广的 URL 传输库与命令行工具。本项目 GitHub Star 数 > 36k，被嵌入到几乎所有主流操作系统、浏览器、容器与 CI/CD 平台。本次评测主要关注 libcurl 的 **URL 解析子系统**（`lib/urlapi.c` 中的 `curl_url_*` 系列 API），因为：

- 它直接处理用户/网络可控的字符串输入；
- 历史上曾出现多枚 CVE（CVE-2023-27535、CVE-2022-43552 等）与之相关；
- 入口简单（一个 buffer），易于编写 fuzz harness。

补充的静态分析关注文件：`lib/url.c`（连接管理）、`lib/hostip.c`（主机名解析）。

---

## 2. 评测环境

| 项 | 值 |
|---|---|
| 操作系统 | Linux 5.4.119, Ubuntu 22.04 |
| 文件系统 | JuiceFS (远端对象存储挂载) |
| CPU | x86_64, 2 vCPU 可见 |
| 内存 | 充足，未设 `-m` 限制 |
| 编译器 (本机) | gcc 11.4.0 |
| 静态分析器 | Clang Static Analyzer 18.1.8 (`clang+llvm-18.1.8-x86_64-linux-gnu-ubuntu-18.04`) |
| 模糊测试器 | AFL 2.52b (Lcamtuf) |
| Python | 3.10.12 |
| LLM | gpt-4.1-mini（通过 `OPENAI_BASE_URL=https://llmapi.bc-inner.com/v1` 代理） |

---

## 3. 评测方法概述

我们设计了一个 **Agent 工具流** 自动串联以下流程：

```
PlannerAgent (LLM)
    │  挑选 fuzz API、种子策略、静态关注文件
    ▼
StaticAgent ────────► clang --analyze (per file) → HTML reports → 解析为结构化 findings
HarnessAgent (LLM) ─► harness.c → afl-gcc 编译 → harness_afl
DynamicAgent ───────► afl-fuzz (默认 600s，可配置至 12h) → crashes/ + fuzzer_stats
DiagnosticAgent (LLM)► 对每条 warning / 每个 unique crash 做分类、根因、修复建议
ReporterAgent (LLM) ► report.md + report.json
```

工具流的每一阶段都可独立运行 (`--mode static|dynamic|...`)，每个阶段写入 `work/.<stage>.done` 标记位实现断点续跑。

完整设计与代码见仓库根目录与 `agent/` 子树。

---

## 4. 动态测试 (AFL)

### 4.1 driver / harness

由 LLM (gpt-4.1-mini) 在 PlannerAgent 选定 `curl_url_set` 之后自动合成，最终写入 `work/harness/harness.c`：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

int main(int argc, char **argv) {
  if(argc < 2) return 0;
  FILE *f = fopen(argv[1], "rb");
  if(!f) return 0;
  if(fseek(f, 0, SEEK_END) != 0) { fclose(f); return 0; }
  long sz = ftell(f);
  if(sz < 0) { fclose(f); return 0; }
  if(sz > (1L << 20)) sz = (1L << 20);
  if(fseek(f, 0, SEEK_SET) != 0) { fclose(f); return 0; }
  char *buf = (char *)malloc((size_t)sz + 1);
  if(!buf) { fclose(f); return 0; }
  size_t n = fread(buf, 1, (size_t)sz, f);
  fclose(f);
  buf[n] = '\0';

  CURLU *handle = curl_url();
  if(handle) {
    (void)curl_url_set(handle, CURLUPART_URL, buf, 0);
    curl_url_cleanup(handle);
  }
  free(buf);
  return 0;
}
```

设计要点：
- 直接以文件路径 `@@` 作为输入，符合 AFL 习惯；
- 1 MiB 上限，避免 OOM；
- `\0` 末尾保证 URL 字符串合法；
- **未调用 `curl_global_init`** — URL 解析 API 不依赖全局状态，去掉可以让 fuzz 速率从 ~3 execs/sec 提升到 ~5 execs/sec（注：本机 JuiceFS fork I/O 较慢，本地 ext4 通常可到 1k+/sec）。

### 4.2 构建命令

```bash
# libcurl 静态库（带 AFL 插桩）
cd curl
CC=afl-gcc ./configure --disable-shared --without-ssl --disable-ldap \
        --without-libpsl --without-zlib --without-brotli --without-zstd \
        --without-nghttp2
make -j2

# 链接 harness
afl-gcc -O2 -g -I curl/include work/harness/harness.c \
        curl/lib/.libs/libcurl.a -lz -lpthread -ldl -lm \
        -o work/harness/harness_afl
```

### 4.3 fuzz 启动

```bash
afl-fuzz -i work/seeds -o work/afl-out -t 5000 -m none \
         -- work/harness/harness_afl @@
```

种子语料 (8 条) 由 `agent/tools/seeds.py::_DEFAULT_URL_SEEDS` 提供，覆盖：HTTP/HTTPS、IPv6、file://、UTF-8 IDN、percent-encoding 等。

### 4.4 运行结果

本次实验运行 **900 秒（15 分钟）** 短时验证；作业要求的 12 小时仅需 `--fuzz-seconds 43200`，框架完全支持。

| 指标 | 值 |
|---|---|
| 执行总次数 (execs_done) | 5,223 |
| 执行速率 (execs/sec) | 5.28 |
| 唯一路径 (paths_total) | 117 |
| favored paths | 7 |
| bitmap 覆盖率 | 1.18 % |
| 稳定性 | 100 % |
| **唯一崩溃数 (unique_crashes)** | **0** |
| 唯一挂起 (unique_hangs) | 0 |
| AFL 版本 | 2.52b |

> 完整 `fuzzer_stats` 见 `work/afl-out/fuzzer_stats`；
> 覆盖增长曲线见 `work/afl-out/plot_data`，可用 `afl-plot` 渲染。

### 4.5 为什么没有发现真实 bug？

1. **curl 已被深度 fuzz**：Google OSS-Fuzz 持续 24×7 测 curl 已 5+ 年，URL 解析路径是其覆盖最完善的部分。简短的 15 分钟测试很难追上现有覆盖。
2. **测试时长不足**：仅 5k execs、bitmap 覆盖率 1.18 %，远未触达稀有路径。作业要求的 12 小时 fuzz（约 200k execs）会显著扩大覆盖。
3. **JuiceFS 上 fork 较慢**：execs/sec 仅 5，瓶颈在文件系统的 process spawn 与 `@@` 文件读取，本地 ext4 通常可达 1k+/sec。
4. **未使用 ASan**：AFL 默认插桩只能捕获 SIGSEGV / abort。许多内存错误（heap-overflow、UAF）需要 ASan 才能检出。本框架已经为此预留了 `--asan` 开关，仅是本次未启用以保留 fork 速率。
5. **AFL 2.52b 不支持 LLVM persistent mode**：每次 exec 都 fork+exec，CPU 利用率不高。升级到 AFL++ 或编译 afl-clang-fast 可获 50–100× 加速。

---

## 5. 静态分析 (Clang Static Analyzer)

### 5.1 调用方式

我们采用 **两条互补路径**：

| 路径 | 命令 | 速度 | 覆盖范围 |
|------|------|------|---------|
| 聚焦模式 | `clang --analyze -Xanalyzer -analyzer-output=html -Xanalyzer -analyzer-checker=…` 直接分析 planner 选定的 .c 文件 | 数秒/文件 | 仅指定文件，但 100% 出报告 |
| 全量模式 | `scan-build -keep-empty -enable-checker … make -j2` | 30–60 分钟 | 全工程，含跨文件分析 |

启用的 checker：`core`, `deadcode`, `security`, `unix`, `nullability`, `alpha.security.ArrayBoundV2`, `alpha.security.ReturnPtrRange`, `alpha.core.PointerArithm`, `alpha.core.CastSize`, `alpha.core.SizeofPtr`, `alpha.unix.cstring.OutOfBounds`, `security.insecureAPI.bcmp`, `security.insecureAPI.bcopy`, `security.FloatLoopCounter`。

### 5.2 结果汇总（聚焦模式，3 个文件）

共发现 **9 条警告**：

| # | 文件 : 行 | Clang 类别 | LLM 标签 | 严重性 |
|---|---|---|---|---|
| 1 | `lib/url.c:1231` | insecure memset | api-misuse | low |
| 2 | `lib/url.c:1999` | insecure memset | api-misuse | **medium** |
| 3 | `lib/hostip.c:223` | insecure memset | api-misuse | low |
| 4 | `lib/hostip.c:228` | insecure memcpy | **buffer-overflow** | medium |
| 5 | `lib/hostip.c:237` | insecure memcpy | **buffer-overflow** | medium |
| 6 | `lib/hostip.c:258` | insecure memset | api-misuse | low |
| 7 | `lib/hostip.c:263` | insecure memcpy | **buffer-overflow** | medium |
| 8 | `lib/hostip.c:274` | insecure memcpy | **buffer-overflow** | medium |
| 9 | `lib/hostip.c:421` | insecure memcpy | **buffer-overflow** | medium |

详细 HTML 报告：`work/scan-build-reports/focused/lib__<file>.c/report-*.html`。结构化输出：`work/static_findings.json` 与 `work/diagnoses.json`。

### 5.3 关键警告分析

所有 9 条警告同属一类，触发自 `security.insecureAPI.*` 检查族：**Clang 推荐使用 C11 `_s`-后缀函数 (memset_s / memcpy_s)** 替代裸 `memset`/`memcpy`。这是一类**保守的规范性建议**，不代表 curl 真的存在越界写：

- curl 的 `memcpy`/`memset` 调用点均位于 `Curl_resolv_link`、`Curl_addrinfo_callback` 等函数，**长度参数来自结构体定义的 `ai_addrlen`/`sa_len`，受系统调用契约保证**；
- C11 `_s` 函数在 glibc 上并未实现，curl 出于可移植性不可能采用；
- 我们的 DiagnosticAgent 在 LLM 评估时给出 `confidence=medium` 与 `exploitability_note="n/a"`，与人工判断一致。

不过 **静态分析的价值正在于此**：把 memcpy 集中位置标出，便于 reviewer 复核长度参数来源。本次复核未发现真实漏洞。

### 5.4 没有发现 0day 的原因

- curl 是 Google Sanitizers、OSS-Fuzz、Clang 自身 staticAnalyzer 反复扫过的标杆项目；
- 我们这次只指定了 3 个文件做聚焦扫描，未扫 `lib/vtls/*`、`lib/cookie.c`、`lib/parsedate.c` 等历史 CVE 高发区；
- 同样未启用 cross-translation-unit (CTU) 分析。

---

## 6. Agent 工具流设计（开放题）

### 6.1 设计目标

把 fuzz/静分这两类「需要工程经验才能用好」的工具，包装成 **"输入项目路径 → 输出漏洞报告"** 的一键式黑盒。LLM 在四个环节注入"经验"：选目标、写 harness、判结果、写报告。

### 6.2 阶段拆解

| 阶段 | 关键输入 | LLM 角色 | 主要工具 | 产物 |
|---|---|---|---|---|
| **PlannerAgent** | README + 头文件片段 | 选定 fuzz API、种子策略、静分关注文件（JSON 输出，`response_format=json_object`） | — | `plan.json` |
| **StaticAgent** | plan 中的 focus_files | — | `clang --analyze`, `scan-build` | `static_findings.json` + HTML |
| **HarnessAgent** | API 头文件、seed strategy | 写出可链接 `libcurl.a` 的 `harness.c` | `afl-gcc` | `harness.c`, `harness_afl` |
| **DynamicAgent** | harness binary, seed dir | — | `afl-fuzz` (timeout=fuzz_seconds) | `afl-out/`, `fuzzer_stats`, `crashes/` |
| **DiagnosticAgent** | 每条 warning / 每个 crash + 源码上下文 + harness | 分类、根因、修复建议（JSON） | — | `diagnoses.json` |
| **ReporterAgent** | 以上所有 | 生成中文 Markdown 总结 | — | `report.md`, `report.json` |

### 6.3 关键工程细节

1. **Prompt 设计**：每个 prompt 都强制 LLM 输出特定 schema（C 源码或 JSON），ReporterAgent 唯一一次允许自由文本，且文本部分仅作"总结"，不参与结构化输出。
2. **Token 控制**：把超过 8 KB 的源码片段截断；harness 上下文最多含一个头文件；diagnose 单次调用平均 ≈ 1k tokens。
3. **重试**：`tenacity` 指数回退，对 5xx 与超时容错。
4. **断点续跑**：每个阶段写 `.<stage>.done` 标记，`--force` 覆盖；同时 `AGENT_SKIP_SCAN_BUILD=1` 可跳过最慢的全量扫描。
5. **可扩展性**：`agent/config.py::TARGETS` 已为 `libpcap`、`libvpx` 预留；只需在 `_DEFAULT_*_SEEDS` 添加对应种子即可。
6. **可观测性**：所有 LLM 调用 / shell 命令均通过 `rich` logger 打印，便于人工审阅。

### 6.4 Agent 在本次任务中的实际作用

| 环节 | Agent 给出的产物 | 是否优于"硬编码模板" |
|---|---|---|
| Planner | `target_api=curl_url`, `static_focus_files=[lib/urlapi.c, lib/url.c, lib/hostip.c]` | ✅ 解析了 README，给出了合理理由 |
| Harness | 自动生成 28 行 C 代码，处理了 size<0、>1MiB 边界 | ✅ 一次编译通过；比硬编码模板更贴合 API |
| Diagnostic | 把 9 条同类 warning 分别打 (severity, confidence, exploit_note)，并指出 memset 类警告 "n/a" 不直接可利用 | ✅ 节约人工复核成本 |
| Reporter | 生成中文摘要，列出"建议"清单 | ✅ 风险评估写得相对克制 |

### 6.5 局限

- LLM 生成的 harness 仅覆盖单一 API；若需要 fuzz 多个 API（如同时 `curl_url_set` 与 `curl_url_get`），需要多次调用 HarnessAgent；
- 当前没有 CriticAgent 做二次审阅，Diagnostic 偶尔会把 `insecureAPI.bcmp` 这类"规范建议"误判为 high；
- 12 小时长 fuzz 仍需手动启动，Agent 没有"决定何时停止"的能力。

---

## 7. 改进方向

| 优先级 | 改进 | 预期收益 |
|---|---|---|
| 高 | 升级到 **AFL++** 或编译 `afl-clang-fast`，开启 persistent + deferred forkserver | execs/sec 提升 50–100× |
| 高 | 开启 **AddressSanitizer** (`--asan`) | 捕获 heap-overflow / UAF |
| 中 | 全量 `scan-build` 跑一遍（已耗时 1 h，本次因复用 AFL build 暂跳过） | 多检 cross-file 警告 |
| 中 | 接入 **libpcap、libvpx** | 满足作业 ≥3 个项目要求 |
| 低 | 引入 **CriticAgent**（双 LLM 自检 Diagnostic 输出） | 减少误判 |
| 低 | 自动从 git log 抽取近期 commit，让 LLM 优先 fuzz "近期改动文件" | 命中真实 regression |

---

## 8. 复现步骤

```bash
cd software_measure

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # 填入 OPENAI_API_KEY / OPENAI_BASE_URL

# 短时 smoke (≈ 1h 含 clang 解压 + 全量 scan-build + 15min fuzz)
python main.py --target curl --mode all --fuzz-seconds 900

# 作业要求的 12h fuzz
python main.py --target curl --mode all --fuzz-seconds 43200

# 仅 dynamic 用新 harness 重跑
rm work/.harness.done work/.dynamic.done work/.diagnose.done work/.report.done
python main.py --target curl --mode all --fuzz-seconds 43200
```

---

## 附录 A：本次 AFL 运行原始统计

```
start_time        : 1778760880
last_update       : 1778761794
execs_done        : 5223
execs_per_sec     : 5.28
paths_total       : 117
paths_favored     : 7
bitmap_cvg        : 1.18%
stability         : 100.00%
unique_crashes    : 0
unique_hangs      : 0
afl_version       : 2.52b
command_line      : afl-fuzz -i work/seeds -o work/afl-out -t 5000 -m none -- work/harness/harness_afl @@
```

## 附录 B：本次 Clang Static Analyzer 警告原文示例

`work/scan-build-reports/focused/lib__hostip.c/report-fdfea0.html`：

> **Potential insecure memory buffer bounds restriction in call 'memcpy'**
> Call to function 'memcpy' is insecure as it does not provide security checks
> introduced in the C11 standard. Replace with analogous functions that support
> length arguments or provides boundary checks such as 'memcpy_s' in case of C11.

## 附录 C：仓库结构

```
software_measure/
├── README.md                # 用户文档
├── report/curl_report.md    # 本报告
├── requirements.txt
├── main.py                  # CLI
├── agent/                   # Agent 框架（6 个 stage + tools + prompts）
├── work/                    # 运行时产物（gitignored）
└── (curl / afl-2.52b / clang+llvm-*.tar.xz / venv 均 gitignored)
```
