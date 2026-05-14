"""AFL driver: instrumented build of target, harness compile, fuzz run, stat parse."""
from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import Optional

from ..config import Config
from . import shell

log = logging.getLogger("agent.tools.afl")


def build_target_instrumented(cfg: Config) -> Path:
    """Rebuild the target library with afl-gcc instrumentation.

    Returns the path to the (instrumented) static library expected by
    `cfg.target.primary_libs[0]`. On dry-run, returns the same path without
    actually building.
    """
    src = cfg.target.source_dir
    primary_lib = Path(cfg.target.primary_libs[0])

    extra_env: dict[str, str] = {
        "CC": str(cfg.afl_gcc),
        "CXX": str(cfg.afl_dir / "afl-g++"),
        "AFL_HARDEN": "1",
    }
    if cfg.use_asan:
        extra_env["AFL_USE_ASAN"] = "1"

    if cfg.target.build_system == "autotools":
        from . import clang_sa as _csa
        _csa._ensure_configure(src, cfg)
        if (src / "configure").exists():
            shell.run(
                ["./configure", "--disable-shared", "--without-ssl",
                 "--disable-ldap", "--disable-ldaps", "--without-libpsl",
                 "--without-zlib", "--without-brotli", "--without-zstd",
                 "--without-nghttp2"],
                cwd=src, dry_run=cfg.dry_run, extra_env=extra_env,
            )
        shell.run(["make", "clean"], cwd=src, dry_run=cfg.dry_run, check=False)
        shell.run(["make", "-j2"], cwd=src, dry_run=cfg.dry_run, extra_env=extra_env)
    elif cfg.target.build_system == "cmake":
        build_dir = src / "_aflbuild"
        build_dir.mkdir(exist_ok=True)
        shell.run(
            ["cmake", "-DBUILD_SHARED_LIBS=OFF", ".."],
            cwd=build_dir, dry_run=cfg.dry_run, extra_env=extra_env,
        )
        shell.run(
            ["make", "-j2"], cwd=build_dir, dry_run=cfg.dry_run, extra_env=extra_env,
        )
    else:
        raise ValueError(f"unsupported build system: {cfg.target.build_system}")

    if not primary_lib.exists() and not cfg.dry_run:
        log.warning("expected static lib not found: %s", primary_lib)
    return primary_lib


def compile_harness(cfg: Config, harness_c: Path) -> Path:
    """Compile a generated harness C file linked against the instrumented lib."""
    harness_bin = harness_c.with_name("harness_afl")
    target = cfg.target
    include = f"-I{target.headers_dir}"
    cmd = [
        str(cfg.afl_gcc),
        "-O2", "-g", include,
        str(harness_c),
        *target.primary_libs,
        *target.extra_link_libs,
        "-o", str(harness_bin),
    ]
    extra_env = {"AFL_USE_ASAN": "1"} if cfg.use_asan else None
    shell.run(cmd, dry_run=cfg.dry_run, extra_env=extra_env)
    return harness_bin


def run_afl_fuzz(cfg: Config, harness_bin: Path, seeds_dir: Path) -> Path:
    """Run afl-fuzz for `cfg.fuzz_seconds`. Returns the AFL output directory."""
    out_dir = cfg.afl_out_dir
    if out_dir.exists():
        shutil.rmtree(out_dir, ignore_errors=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(cfg.afl_fuzz),
        "-i", str(seeds_dir),
        "-o", str(out_dir),
        "-t", "5000",
        "-m", "none",
        "--", str(harness_bin), "@@",
    ]
    extra_env = {
        "AFL_SKIP_CPUFREQ": "1",
        "AFL_NO_AFFINITY": "1",
        "AFL_EXIT_WHEN_DONE": "0",
    }

    shell.run(
        cmd,
        timeout=cfg.fuzz_seconds + 30,
        check=False,
        dry_run=cfg.dry_run,
        extra_env=extra_env,
        capture=True,
    )
    return out_dir


def parse_fuzzer_stats(out_dir: Path) -> dict:
    stats_path = out_dir / "fuzzer_stats"
    if not stats_path.exists():
        return {}
    stats: dict[str, str] = {}
    for line in stats_path.read_text(errors="replace").splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            stats[k.strip()] = v.strip()
    return stats


def collect_crashes(out_dir: Path, limit: int) -> list[dict]:
    """Return crash inputs with hex preview. README files skipped."""
    crashes_dir = out_dir / "crashes"
    if not crashes_dir.exists():
        return []
    items: list[dict] = []
    for p in sorted(crashes_dir.iterdir()):
        if p.name.startswith(".") or p.name.lower().startswith("readme"):
            continue
        try:
            data = p.read_bytes()
        except OSError:
            continue
        items.append({
            "id": p.name,
            "size": len(data),
            "preview_hex": data[:256].hex(),
            "preview_text": _safe_decode(data[:256]),
            "path": str(p),
        })
        if len(items) >= limit:
            break
    return items


def _safe_decode(b: bytes) -> str:
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return b.decode("latin-1", errors="replace")


def ensure_runtime_prereqs(dry_run: bool = False) -> list[str]:
    """Best-effort sanity checks; returns human-readable warnings."""
    warnings: list[str] = []
    try:
        cp = Path("/proc/sys/kernel/core_pattern").read_text().strip()
        if not cp.startswith("core") and cp != "core":
            warnings.append(
                f"core_pattern={cp!r}; AFL prefers 'core'. "
                "Run: sudo bash -c 'echo core > /proc/sys/kernel/core_pattern'"
            )
    except OSError:
        pass
    return warnings
