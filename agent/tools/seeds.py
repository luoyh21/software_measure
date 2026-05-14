"""Seed corpus discovery / generation for AFL."""
from __future__ import annotations

import logging
from pathlib import Path

log = logging.getLogger("agent.tools.seeds")


_DEFAULT_URL_SEEDS = [
    b"http://example.com/",
    b"https://user:pass@example.com:8080/path?query=1#frag",
    b"ftp://ftp.example.com/file.txt",
    b"file:///etc/hostname",
    b"http://[::1]:80/",
    b"http://[2001:db8::1]/",
    b"http://example.com/%2e%2e/etc/passwd",
    b"http://xn--bcher-kva.example/",
]

_DEFAULT_HEADER_SEEDS = [
    b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    b"Set-Cookie: a=1; Path=/; Secure\r\n",
]


def provision_seeds(seeds_dir: Path, api_hint: str) -> Path:
    """Populate `seeds_dir` with a small corpus chosen by `api_hint`."""
    seeds_dir.mkdir(parents=True, exist_ok=True)
    if any(seeds_dir.iterdir()):
        return seeds_dir
    hint = (api_hint or "").lower()
    if "url" in hint or hint == "":
        bank = _DEFAULT_URL_SEEDS
    elif "header" in hint or "http" in hint or "cookie" in hint:
        bank = _DEFAULT_HEADER_SEEDS
    else:
        bank = _DEFAULT_URL_SEEDS
    for i, payload in enumerate(bank):
        (seeds_dir / f"seed_{i:03d}").write_bytes(payload)
    log.info("seeded %d inputs into %s", len(bank), seeds_dir)
    return seeds_dir
