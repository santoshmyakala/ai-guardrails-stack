"""Shared result types. Every check returns Findings; layers turn them into a Verdict."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Action(StrEnum):
    ALLOW = "allow"
    FLAG = "flag"          # allowed, recorded for review
    REDACT = "redact"      # allowed after the content was changed
    APPROVAL = "approval"  # paused until a human decides
    BLOCK = "block"


SEVERITY = {Action.ALLOW: 0, Action.FLAG: 1, Action.REDACT: 2, Action.APPROVAL: 3, Action.BLOCK: 4}


@dataclass(frozen=True)
class Finding:
    check: str            # e.g. "input.prompt_injection"
    category: str         # e.g. "instruction_override"
    score: float          # 0..1 confidence of the rule that fired
    evidence: str = ""    # short, safe excerpt (never a full prompt)
    action: Action = Action.FLAG


@dataclass
class Verdict:
    layer: str
    action: Action = Action.ALLOW
    findings: list[Finding] = field(default_factory=list)
    text: str | None = None  # the (possibly redacted) text to continue with

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)
        if SEVERITY[finding.action] > SEVERITY[self.action]:
            self.action = finding.action

    @property
    def blocked(self) -> bool:
        return self.action == Action.BLOCK

    def reasons(self) -> list[str]:
        return sorted({f"{f.check}:{f.category}" for f in self.findings})
