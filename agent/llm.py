"""OpenAI client wrapper with retry, JSON-mode helper, and prompt loader."""
from __future__ import annotations

import json
import logging
from pathlib import Path

from openai import OpenAI
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from .config import Config

log = logging.getLogger("agent.llm")

PROMPT_DIR = Path(__file__).resolve().parent / "prompts"


def load_prompt(name: str) -> str:
    path = PROMPT_DIR / name
    return path.read_text(encoding="utf-8")


class LLM:
    """Thin OpenAI wrapper exposing chat() and chat_json()."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        if not cfg.openai_api_key:
            raise RuntimeError("OPENAI_API_KEY not set; copy .env.example to .env first.")
        self.client = OpenAI(api_key=cfg.openai_api_key, base_url=cfg.openai_base_url)
        self.model = cfg.openai_model

    @retry(
        reraise=True,
        stop=stop_after_attempt(4),
        wait=wait_exponential(multiplier=2, min=2, max=30),
        retry=retry_if_exception_type(Exception),
    )
    def _create(self, **kwargs):
        return self.client.chat.completions.create(**kwargs)

    def chat(self, *, system: str, user: str, temperature: float = 0.2,
             max_tokens: int = 2048) -> str:
        log.info("LLM chat → model=%s, user_chars=%d", self.model, len(user))
        resp = self._create(
            model=self.model,
            temperature=temperature,
            max_tokens=max_tokens,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return resp.choices[0].message.content or ""

    def chat_json(self, *, system: str, user: str, temperature: float = 0.0,
                  max_tokens: int = 2048) -> dict:
        log.info("LLM chat_json → model=%s, user_chars=%d", self.model, len(user))
        resp = self._create(
            model=self.model,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        text = resp.choices[0].message.content or "{}"
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            log.warning("LLM returned non-JSON; attempting salvage")
            start = text.find("{")
            end = text.rfind("}")
            if start >= 0 and end > start:
                return json.loads(text[start : end + 1])
            raise
