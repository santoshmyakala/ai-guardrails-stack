"""Grounding check: is every claim in the answer supported by the retrieved sources?

Per sentence: the share of its content words found in the best-matching source (support), every
number in it must appear in that source (an invented figure is the most damaging kind of
hallucination), and citations like [S2] must point at a source that actually supports it.
Deterministic and explainable; a model-based judge can be layered on top for paraphrases.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..types import Action, Finding, Verdict

STOP = set("""a an the and or but if then than that this these those is are was were be been being am do does did
of in on at to for from by with as into about over after before under between per via it its it's they them their
there here we you your our i me my he she his her not no yes can could should would will may might must so such
also very more most less least other some any each all both which who whom whose what when where why how""".split())
HEDGES = re.compile(r"^(i (don't|do not) know|i('m| am) not sure|the sources? (don't|do not) say)", re.I)
NUMBER = re.compile(r"\d[\d,]*(?:\.\d+)?%?")
CITE = re.compile(r"\[([A-Za-z0-9_.-]+)\]")


def _stem(w: str) -> str:
    for suf in ("ing", "edly", "ed", "es", "s", "ly"):
        if len(w) > len(suf) + 3 and w.endswith(suf):
            return w[: -len(suf)]
    return w


def content(text: str) -> set[str]:
    return {_stem(w) for w in re.findall(r"[a-z0-9]+", text.lower()) if w not in STOP and len(w) > 1}


def numbers(text: str) -> set[str]:
    return {n.replace(",", "").rstrip(".") for n in NUMBER.findall(text)}


def sentences(text: str) -> list[str]:
    return [s.strip() for s in re.split(r"(?<=[.!?])\s+|\n+", text) if s.strip()]


@dataclass
class GroundingResult:
    verdict: Verdict
    score: float  # share of checked sentences that are supported


def check(answer: str, sources: list[dict], min_support: float = 0.5, block_below: float = 0.5) -> GroundingResult:
    v = Verdict("output")
    by_id = {s["id"]: s["text"] for s in sources}
    checked = supported = 0
    for sent in sentences(answer):
        bare = CITE.sub("", sent)
        words = content(bare)
        if len(words) < 3 or HEDGES.match(bare):
            continue
        checked += 1
        cited = CITE.findall(sent)
        for c in cited:
            if c not in by_id:
                v.add(Finding("output.grounding", "invalid_citation", 1.0, f"[{c}]", Action.FLAG))
        pool = {c: by_id[c] for c in cited if c in by_id} or by_id
        best_id, best = max(((sid, len(words & content(t)) / len(words)) for sid, t in pool.items()),
                            key=lambda x: x[1], default=(None, 0.0))
        missing_numbers = numbers(bare) - (numbers(pool[best_id]) if best_id else set())
        ok = best >= min_support and not missing_numbers
        if missing_numbers:
            v.add(Finding("output.grounding", "unsupported_number", 1.0,
                          f"{sorted(missing_numbers)} not in {best_id}", Action.FLAG))
        if best < min_support:
            category = "citation_mismatch" if cited else "unsupported_claim"
            v.add(Finding("output.grounding", category, round(1 - best, 2), sent[:80], Action.FLAG))
        supported += ok
    score = supported / checked if checked else 1.0
    if checked and score < block_below:
        v.add(Finding("output.grounding", "mostly_ungrounded", round(1 - score, 2),
                      f"{supported}/{checked} sentences supported", Action.BLOCK))
    v.text = answer
    return GroundingResult(v, score)
