"""Global configuration: paths, target definitions, env-driven LLM settings."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv


REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Target:
    name: str
    source_dir: Path
    build_system: str          # "autotools" | "cmake"
    headers_dir: Path
    primary_libs: list[str]    # static lib paths (after build) used to link harness
    extra_link_libs: list[str] = field(default_factory=list)
    default_api_hint: str = ""

    def describe(self) -> str:
        return f"{self.name} @ {self.source_dir} (build={self.build_system})"


def _curl_target() -> Target:
    src = REPO_ROOT / "curl"
    return Target(
        name="curl",
        source_dir=src,
        build_system="autotools",
        headers_dir=src / "include",
        primary_libs=[str(src / "lib" / ".libs" / "libcurl.a")],
        extra_link_libs=["-lz", "-lpthread", "-ldl", "-lm"],
        default_api_hint="curl_url",
    )


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


def _libvpx_target() -> Target:
    src = REPO_ROOT / "libvpx"
    return Target(
        name="libvpx",
        source_dir=src,
        build_system="cmake",
        headers_dir=src,
        primary_libs=[str(src / "libvpx.a")],
        extra_link_libs=["-lpthread", "-lm"],
        default_api_hint="vpx_codec_decode",
    )


TARGETS: dict[str, Target] = {
    "curl": _curl_target(),
    "libpcap": _libpcap_target(),
    "libvpx": _libvpx_target(),
}


@dataclass
class Config:
    target: Target
    workdir: Path
    afl_dir: Path
    clang_tarball: Path
    clang_dir: Path
    fuzz_seconds: int = 600
    max_warnings: int = 20
    max_crashes: int = 20
    api_hint: str = ""
    force: bool = False
    dry_run: bool = False
    use_asan: bool = False
    # LLM
    openai_api_key: str = ""
    openai_base_url: str = ""
    openai_model: str = "gpt-4.1-mini"

    @classmethod
    def from_args(cls, args) -> "Config":
        load_dotenv(REPO_ROOT / ".env")

        if args.target not in TARGETS:
            raise SystemExit(f"unknown target {args.target!r}; known: {list(TARGETS)}")
        target = TARGETS[args.target]

        workdir = (REPO_ROOT / args.workdir).resolve()
        workdir.mkdir(parents=True, exist_ok=True)

        afl_dir = REPO_ROOT / "afl-2.52b"
        clang_tarball = REPO_ROOT / "clang+llvm-18.1.8-x86_64-linux-gnu-ubuntu-18.04.tar.xz"
        clang_dir = REPO_ROOT / "clang+llvm-18.1.8-x86_64-linux-gnu-ubuntu-18.04"

        return cls(
            target=target,
            workdir=workdir,
            afl_dir=afl_dir,
            clang_tarball=clang_tarball,
            clang_dir=clang_dir,
            fuzz_seconds=args.fuzz_seconds,
            max_warnings=args.max_warnings,
            max_crashes=args.max_crashes,
            api_hint=args.api or target.default_api_hint,
            force=args.force,
            dry_run=args.dry_run,
            use_asan=args.asan,
            openai_api_key=os.getenv("OPENAI_API_KEY", ""),
            openai_base_url=os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
            openai_model=os.getenv("OPENAI_MODEL", "gpt-4.1-mini"),
        )

    # ---- derived paths ----
    @property
    def afl_gcc(self) -> Path:
        return self.afl_dir / "afl-gcc"

    @property
    def afl_fuzz(self) -> Path:
        return self.afl_dir / "afl-fuzz"

    @property
    def afl_cmin(self) -> Path:
        return self.afl_dir / "afl-cmin"

    @property
    def scan_build(self) -> Path:
        return self.clang_dir / "bin" / "scan-build"

    @property
    def clang(self) -> Path:
        return self.clang_dir / "bin" / "clang"

    @property
    def plan_path(self) -> Path:
        return self.workdir / "plan.json"

    @property
    def scan_reports_dir(self) -> Path:
        return self.workdir / "scan-build-reports"

    @property
    def harness_dir(self) -> Path:
        return self.workdir / "harness"

    @property
    def afl_out_dir(self) -> Path:
        return self.workdir / "afl-out"

    @property
    def seeds_dir(self) -> Path:
        return self.workdir / "seeds"

    @property
    def diagnoses_path(self) -> Path:
        return self.workdir / "diagnoses.json"

    @property
    def report_md(self) -> Path:
        return self.workdir / "report.md"

    @property
    def report_json(self) -> Path:
        return self.workdir / "report.json"

    def done_marker(self, stage: str) -> Path:
        return self.workdir / f".{stage}.done"
