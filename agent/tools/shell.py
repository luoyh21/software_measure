"""Subprocess wrapper with logging, optional dry-run and timeout."""
from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path
from typing import Mapping, Sequence

log = logging.getLogger("agent.shell")


class ShellError(RuntimeError):
    def __init__(self, cmd: Sequence[str], returncode: int, stdout: str, stderr: str):
        self.cmd = list(cmd)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        super().__init__(
            f"command failed (rc={returncode}): {' '.join(self.cmd)}\n"
            f"--- stderr ---\n{stderr[-2000:]}\n"
        )


def run(
    cmd: Sequence[str],
    *,
    cwd: Path | str | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float | None = None,
    check: bool = True,
    dry_run: bool = False,
    capture: bool = True,
    extra_env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess:
    """Run a command. Returns CompletedProcess. Raises ShellError on failure.

    When `dry_run` is True, prints the command and returns a dummy result.
    """
    cmd_list = [str(c) for c in cmd]
    log.info("$ %s%s", "(dry-run) " if dry_run else "",
             " ".join(cmd_list) + (f"  # cwd={cwd}" if cwd else ""))
    if dry_run:
        return subprocess.CompletedProcess(cmd_list, 0, "", "")

    final_env = None
    if env is not None or extra_env is not None:
        final_env = dict(os.environ)
        if env is not None:
            final_env.update({k: str(v) for k, v in env.items()})
        if extra_env is not None:
            final_env.update({k: str(v) for k, v in extra_env.items()})

    try:
        proc = subprocess.run(
            cmd_list,
            cwd=str(cwd) if cwd else None,
            env=final_env,
            timeout=timeout,
            capture_output=capture,
            text=True,
        )
    except subprocess.TimeoutExpired as exc:
        log.warning("command timed out after %ss: %s", timeout, " ".join(cmd_list))
        return subprocess.CompletedProcess(
            cmd_list,
            124,
            exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
            exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or ""),
        )

    if check and proc.returncode != 0:
        raise ShellError(cmd_list, proc.returncode, proc.stdout or "", proc.stderr or "")
    return proc
