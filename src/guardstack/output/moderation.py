"""Content moderation before the user sees an answer.

Built-in rules are deliberately narrow and high-precision (actionable instructions for weapons or
self-harm, dehumanising language). For broad coverage, plug in a safety classifier served behind
an OpenAI-compatible endpoint (e.g. a Llama Guard model on vLLM) via `ModelJudge`.
"""

from __future__ import annotations

import re

import httpx

from ..types import Action, Finding, Verdict

RULES: tuple[tuple[str, re.Pattern], ...] = (
    ("weapons_instructions", re.compile(
        r"\b(step\s*\d|first,?|then,?|mix|combine|assemble)\b.{0,80}\b(explosive|detonator|pipe bomb|nerve agent|"
        r"thermite|napalm|untraceable (gun|firearm))\b", re.I | re.S)),
    ("self_harm_encouragement", re.compile(
        r"\b(you should|go ahead and|just)\s+(kill|hurt|harm|cut)\s+yourself\b|\bbest way to (kill|harm) yourself\b", re.I)),
    ("dehumanising", re.compile(r"\b(are|is)\s+(vermin|subhuman|parasites|cockroaches|animals that should)\b", re.I)),
)


class ModelJudge:
    """Asks a safety classifier model; expects 'safe' or 'unsafe' followed by category codes."""

    def __init__(self, url: str, model: str, api_key: str = "", transport: httpx.BaseTransport | None = None) -> None:
        self.url, self.model = url.rstrip("/"), model
        self.client = httpx.Client(timeout=30, transport=transport,
                                   headers={"Authorization": f"Bearer {api_key}"} if api_key else {})

    def classify(self, user: str, answer: str) -> tuple[bool, list[str]]:
        r = self.client.post(f"{self.url}/v1/chat/completions", json={
            "model": self.model, "temperature": 0, "max_tokens": 20,
            "messages": [{"role": "user", "content": user}, {"role": "assistant", "content": answer}]})
        r.raise_for_status()
        lines = r.json()["choices"][0]["message"]["content"].strip().splitlines()
        unsafe = bool(lines) and lines[0].strip().lower() == "unsafe"
        cats = [c.strip() for c in lines[1].split(",")] if unsafe and len(lines) > 1 else []
        return unsafe, cats


def check(answer: str, user: str = "", judge: ModelJudge | None = None) -> Verdict:
    v = Verdict("output", text=answer)
    for category, pattern in RULES:
        m = pattern.search(answer)
        if m:
            v.add(Finding("output.moderation", category, 1.0, m.group(0)[:60], Action.BLOCK))
    if judge is not None and not v.blocked:
        unsafe, cats = judge.classify(user, answer)
        if unsafe:
            v.add(Finding("output.moderation", "judge:" + ",".join(cats or ["unsafe"]), 1.0, "", Action.BLOCK))
    return v
