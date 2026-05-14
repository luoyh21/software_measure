"""Clang Static Analyzer driver.

- Lazily extracts the bundled clang+llvm tarball.
- Runs `scan-build` over the target's autotools build.
- Parses HTML reports into structured findings.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Optional

from bs4 import BeautifulSoup

from ..config import Config
from . import shell

log = logging.getLogger("agent.tools.clang_sa")


def ensure_clang(cfg: Config) -> Path:
    """Extract clang+llvm tarball if `bin/scan-build` is not present."""
    if cfg.scan_build.exists() and cfg.clang.exists():
        return cfg.scan_build
    if not cfg.clang_tarball.exists():
        raise FileNotFoundError(
            f"clang tarball missing at {cfg.clang_tarball}; "
            "please download from https://releases.llvm.org/."
        )
    log.info("extracting %s → %s", cfg.clang_tarball.name, cfg.clang_dir.parent)
    shell.run(
        ["tar", "xf", str(cfg.clang_tarball)],
        cwd=cfg.clang_tarball.parent,
        dry_run=cfg.dry_run,
    )
    if not cfg.scan_build.exists() and not cfg.dry_run:
        raise RuntimeError(
            f"scan-build still missing at {cfg.scan_build} after extraction"
        )
    return cfg.scan_build


def run_scan_build(cfg: Config) -> Path:
    """Run scan-build over the configured target. Returns the report directory."""
    scan_build = ensure_clang(cfg)
    src = cfg.target.source_dir
    out_dir = cfg.scan_reports_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    extra_checkers = [
        "-enable-checker", "alpha.security.ArrayBoundV2",
        "-enable-checker", "alpha.security.ReturnPtrRange",
        "-enable-checker", "alpha.core.PointerArithm",
        "-enable-checker", "alpha.core.CastSize",
        "-enable-checker", "alpha.unix.cstring.OutOfBounds",
        "-enable-checker", "security.insecureAPI.bcmp",
        "-enable-checker", "security.insecureAPI.bcopy",
        "-enable-checker", "security.insecureAPI.bzero",
        "-enable-checker", "security.FloatLoopCounter",
    ]
    keep_empty = ["-keep-empty"]

    if cfg.target.build_system == "autotools":
        _ensure_configure(src, cfg)
        # Only re-configure if Makefile is missing — `./configure` through
        # scan-build can take ~20 min on this tree.
        if (src / "configure").exists() and not (src / "Makefile").exists():
            shell.run(
                [
                    str(scan_build), *keep_empty, *extra_checkers,
                    "-o", str(out_dir),
                    "./configure", "--disable-shared", "--without-ssl",
                    "--disable-ldap", "--disable-ldaps", "--without-libpsl",
                    "--without-zlib", "--without-brotli", "--without-zstd",
                    "--without-nghttp2",
                ],
                cwd=src,
                dry_run=cfg.dry_run,
            )
        shell.run(["make", "clean"], cwd=src, dry_run=cfg.dry_run, check=False)
        shell.run(
            [str(scan_build), *keep_empty, *extra_checkers,
             "-o", str(out_dir), "make", "-j2"],
            cwd=src,
            dry_run=cfg.dry_run,
        )
    elif cfg.target.build_system == "cmake":
        build_dir = src / "_scanbuild"
        build_dir.mkdir(exist_ok=True)
        shell.run(
            [
                str(scan_build),
                "-o", str(out_dir),
                "cmake", "-DBUILD_SHARED_LIBS=OFF", "..",
            ],
            cwd=build_dir,
            dry_run=cfg.dry_run,
        )
        shell.run(
            [str(scan_build), "-o", str(out_dir), "make", "-j2"],
            cwd=build_dir,
            dry_run=cfg.dry_run,
        )
    else:
        raise ValueError(f"unsupported build system: {cfg.target.build_system}")

    return out_dir


def run_clang_analyze_focused(cfg: Config, focus_files: list[str]) -> Path:
    """Direct `clang --analyze` on a hand-picked list of source files.

    This is fast (seconds per file) and produces HTML reports regardless of
    whether scan-build's libtool integration captured the build. Reports go
    into `work/scan-build-reports/focused/<file>/`.
    """
    ensure_clang(cfg)
    src = cfg.target.source_dir
    out_root = cfg.scan_reports_dir / "focused"
    out_root.mkdir(parents=True, exist_ok=True)

    # Curl-specific include paths; harmless for other targets that share the
    # autotools layout.
    include_flags: list[str] = [
        f"-I{cfg.target.headers_dir}",
        f"-I{src}",
        f"-I{src / 'lib'}",
        f"-I{src / 'lib' / 'curlx'}",
        f"-I{src / 'lib' / 'vauth'}",
        f"-I{src / 'lib' / 'vtls'}",
        f"-I{src / 'lib' / 'vquic'}",
        f"-I{src / 'lib' / 'vssh'}",
        "-DHAVE_CONFIG_H",
    ]
    checker_flags: list[str] = []
    for c in [
        "core", "deadcode", "security", "unix", "nullability",
        "alpha.security.ArrayBoundV2",
        "alpha.security.ReturnPtrRange",
        "alpha.core.PointerArithm",
        "alpha.core.CastSize",
        "alpha.core.SizeofPtr",
        "alpha.unix.cstring.OutOfBounds",
        "security.insecureAPI.bcmp",
        "security.insecureAPI.bcopy",
        "security.FloatLoopCounter",
    ]:
        checker_flags += ["-Xanalyzer", f"-analyzer-checker={c}"]

    for rel in focus_files:
        f = (src / rel).resolve()
        if not f.exists():
            log.warning("focused analyze: missing %s", f)
            continue
        out_sub = out_root / rel.replace("/", "__")
        out_sub.mkdir(parents=True, exist_ok=True)
        cmd = [
            str(cfg.clang),
            "--analyze",
            "-Xanalyzer", "-analyzer-output=html",
            *checker_flags,
            *include_flags,
            "-o", str(out_sub),
            str(f),
        ]
        # check=False — analyzer can return non-zero on warnings.
        shell.run(cmd, cwd=src, check=False, dry_run=cfg.dry_run)
    return out_root


def parse_focused_reports(focused_root: Path) -> list[dict]:
    """Each `clang --analyze` HTML file is one warning. Parse the header
    comments to extract bug type / file / line."""
    findings: list[dict] = []
    if not focused_root.exists():
        return findings
    for html in focused_root.rglob("*.html"):
        try:
            text = html.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        meta = {
            "BUGTYPE": "",
            "BUGCATEGORY": "",
            "BUGFILE": "",
            "BUGLINE": "0",
            "BUGDESC": "",
        }
        for key in meta:
            m = re.search(rf"<!--\s*{key}\s+(.+?)\s*-->", text)
            if m:
                meta[key] = m.group(1)
        if not meta["BUGTYPE"] and not meta["BUGDESC"]:
            continue
        findings.append({
            "category": meta["BUGTYPE"] or meta["BUGCATEGORY"] or "Unknown",
            "file": meta["BUGFILE"],
            "line": _safe_int(meta["BUGLINE"]),
            "description": meta["BUGDESC"] or meta["BUGTYPE"],
            "report_path": str(html),
        })
    return findings


def latest_report_dir(scan_reports_root: Path) -> Optional[Path]:
    """scan-build creates a timestamped subdir per run; return the newest."""
    if not scan_reports_root.exists():
        return None
    candidates = [p for p in scan_reports_root.iterdir() if p.is_dir()]
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


def _ensure_configure(src: Path, cfg: Config) -> None:
    """Generate ./configure from configure.ac if it doesn't exist yet."""
    if (src / "configure").exists():
        return
    if (src / "buildconf").exists():
        shell.run(["./buildconf"], cwd=src, dry_run=cfg.dry_run)
    elif (src / "autogen.sh").exists():
        shell.run(["./autogen.sh"], cwd=src, dry_run=cfg.dry_run)
    elif (src / "configure.ac").exists():
        # libtoolize must run before autoreconf when configure.ac uses LT_INIT;
        # on some distros autoreconf -fi alone does not pull in ltmain.sh.
        if (src / "configure.ac").read_text(errors="replace").find("LT_INIT") >= 0 \
                or "AC_PROG_LIBTOOL" in (src / "configure.ac").read_text(errors="replace"):
            shell.run(["libtoolize", "--copy", "--force"], cwd=src,
                      dry_run=cfg.dry_run, check=False)
        shell.run(["autoreconf", "-fi"], cwd=src, dry_run=cfg.dry_run)
    else:
        raise RuntimeError(
            f"cannot bootstrap autotools build in {src}: "
            "no configure, buildconf, autogen.sh, or configure.ac"
        )


def parse_reports(scan_reports_root: Path) -> list[dict]:
    """Return a list of {file, line, category, description, report_path} dicts."""
    latest = latest_report_dir(scan_reports_root)
    if latest is None:
        return []
    index = latest / "index.html"
    if not index.exists():
        return []
    soup = BeautifulSoup(index.read_text(encoding="utf-8", errors="replace"),
                        "lxml")
    findings: list[dict] = []
    for table in soup.select("table.sortable, table"):
        rows = table.find_all("tr")
        if len(rows) < 2:
            continue
        headers = [th.get_text(strip=True).lower() for th in rows[0].find_all(["th", "td"])]

        def col(name_candidates):
            for nc in name_candidates:
                for i, h in enumerate(headers):
                    if nc in h:
                        return i
            return None

        idx_bug = col(["bug type", "issue"])
        idx_file = col(["file"])
        idx_line = col(["line"])
        idx_desc = col(["description", "bug"])
        if idx_file is None:
            continue
        for tr in rows[1:]:
            tds = tr.find_all(["td"])
            if not tds:
                continue
            def cell(i):
                if i is None or i >= len(tds):
                    return ""
                return tds[i].get_text(" ", strip=True)
            report_link = ""
            for a in tr.find_all("a"):
                href = a.get("href", "")
                if href.endswith(".html"):
                    report_link = href
                    break
            findings.append({
                "category": cell(idx_bug) or "Unknown",
                "file": cell(idx_file),
                "line": _safe_int(cell(idx_line)),
                "description": cell(idx_desc),
                "report_path": str(latest / report_link) if report_link else "",
            })
    return findings


def _safe_int(s: str) -> int:
    m = re.search(r"\d+", s or "")
    return int(m.group()) if m else 0
