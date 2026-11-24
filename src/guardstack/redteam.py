"""Red-team harness: run attack and benign corpora through the real layers and report.

Detection rate per category, false-positive rate on legitimate traffic, and every miss by id. The
corpora are written by the same author as the rules, so treat the numbers as a regression gate,
not as independent assurance; complement them with external tools and human red-teamers.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .config import Config
from .input import pii
from .input.injection import InjectionDetector
from .output import grounding, leakage, moderation
from .policy.opa import OPAClient
from .tools.catalog import Ledger, build_catalog
from .tools.guard import ToolGuard
from .types import Action


@dataclass
class Report:
    by_category: dict[str, list[int]] = field(default_factory=lambda: defaultdict(lambda: [0, 0]))  # [hit, total]
    misses: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    benign_total: int = 0

    @property
    def detection_rate(self) -> float:
        hit = sum(h for h, _ in self.by_category.values())
        total = sum(t for _, t in self.by_category.values())
        return hit / total if total else 1.0

    @property
    def false_positive_rate(self) -> float:
        return len(self.false_positives) / self.benign_total if self.benign_total else 0.0

    def markdown(self) -> str:
        hit = sum(h for h, _ in self.by_category.values())
        total = sum(t for _, t in self.by_category.values())
        lines = ["| Attack category | Caught | Rate |", "|---|---:|---:|"]
        for cat in sorted(self.by_category):
            h, t = self.by_category[cat]
            lines.append(f"| {cat} | {h}/{t} | {h / t:.0%} |")
        lines.append(f"| **All attacks** | **{hit}/{total}** | **{self.detection_rate:.1%}** |")
        lines.append(f"| **Legitimate requests wrongly stopped** | **{len(self.false_positives)}/{self.benign_total}** "
                     f"| **{self.false_positive_rate:.1%}** |")
        if self.misses:
            lines += ["", "Missed attacks (known gaps): " + ", ".join(f"`{m}`" for m in self.misses)]
        if self.false_positives:
            lines += ["", "False positives: " + ", ".join(f"`{m}`" for m in self.false_positives)]
        return "\n".join(lines) + "\n"


def run(corpus: Path, config_path: str, opa_url: str) -> Report:
    cfg = Config.load(config_path)
    agent = cfg.agents["support-bot"]
    detector = InjectionDetector(cfg.prompt_threshold, cfg.document_threshold)
    guard = ToolGuard(build_catalog(Ledger()), OPAClient(opa_url))
    attacks = yaml.safe_load((corpus / "attacks.yaml").read_text())
    benign = yaml.safe_load((corpus / "benign.yaml").read_text())
    rep = Report()

    def caught(case: dict) -> bool:
        kind = case["kind"]
        if kind == "prompt":
            return detector.check_prompt(case["text"]).action == Action.BLOCK
        if kind == "document":
            kept, _ = detector.check_documents([{"id": case["id"], "text": case["text"]}])
            return not kept
        if kind == "pii":
            red = pii.redact(case["text"])
            return all(v not in red.text for v in case["values"])
        if kind == "tool":
            d = guard.decide(agent, case["tool"], case["args"])
            return d.action in (Action.BLOCK, Action.APPROVAL) if case.get("expect", "contained") == "contained" \
                else d.action == Action(case["expect"])
        if kind == "output":
            v = leakage.check(case["text"], system_prompt=case.get("system", ""))
            return v.action in (Action.BLOCK, Action.REDACT) or moderation.check(case["text"]).blocked
        if kind == "answer":
            return bool(grounding.check(case["text"], case["sources"]).verdict.findings)
        raise ValueError(f"unknown kind {kind}")

    for case in attacks:
        ok = caught(case)
        rep.by_category[case["category"]][0] += ok
        rep.by_category[case["category"]][1] += 1
        if not ok:
            rep.misses.append(case["id"])

    for case in benign:
        rep.benign_total += 1
        kind = case["kind"]
        if kind == "prompt":
            bad = detector.check_prompt(case["text"]).action != Action.ALLOW
        elif kind == "document":
            bad = not detector.check_documents([{"id": case["id"], "text": case["text"]}])[0]
        elif kind == "tool":
            bad = guard.decide(agent, case["tool"], case["args"]).action == Action.BLOCK
        elif kind == "output":
            v = leakage.check(case["text"])
            bad = v.action != Action.ALLOW or moderation.check(case["text"]).blocked
        elif kind == "answer":
            bad = bool(grounding.check(case["text"], case["sources"]).verdict.findings)
        else:
            raise ValueError(kind)
        if bad:
            rep.false_positives.append(case["id"])
    return rep
