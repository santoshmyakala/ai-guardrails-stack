"""Topic and scope filter: keep an agent on the job it was built for.

Denied topics are blocked outright (e.g. a support bot giving medical or legal advice). With an
allowlist, requests that match none of the allowed topics are refused as out of scope; short
greetings and thanks are always allowed, so the conversation stays natural.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..text import normalise
from ..types import Action, Finding, Verdict

SMALLTALK = re.compile(r"^\W*(hi|hello|hey|thanks|thank you|good (morning|afternoon|evening)|bye)\b", re.I)


@dataclass(frozen=True)
class Topic:
    name: str
    patterns: tuple[re.Pattern, ...]

    @classmethod
    def build(cls, name: str, keywords: list[str]) -> Topic:
        return cls(name, tuple(re.compile(rf"\b{k}\b", re.I) for k in keywords))

    def matches(self, text: str) -> str | None:
        for p in self.patterns:
            m = p.search(text)
            if m:
                return m.group(0)
        return None


@dataclass
class TopicFilter:
    denied: list[Topic] = field(default_factory=list)
    allowed: list[Topic] = field(default_factory=list)  # empty = any topic not denied

    @classmethod
    def from_config(cls, cfg: dict) -> TopicFilter:
        return cls(denied=[Topic.build(n, kw) for n, kw in (cfg.get("denied") or {}).items()],
                   allowed=[Topic.build(n, kw) for n, kw in (cfg.get("allowed") or {}).items()])

    def check(self, text: str) -> Verdict:
        norm = normalise(text)
        v = Verdict("input", text=text)
        for topic in self.denied:
            hit = topic.matches(norm)
            if hit:
                v.add(Finding("input.topic", f"denied:{topic.name}", 1.0, hit, Action.BLOCK))
        if self.allowed and not v.blocked and not SMALLTALK.match(norm):
            if not any(t.matches(norm) for t in self.allowed):
                v.add(Finding("input.topic", "out_of_scope", 1.0, norm[:60], Action.BLOCK))
        return v
