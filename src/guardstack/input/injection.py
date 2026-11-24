"""Prompt-injection and jailbreak detection.

Rules are explicit and explainable: every block names the rule that fired. They run on every
variant from `text.variants()`, so encoded or obfuscated payloads are caught; a match that only
appears after decoding is itself suspicious and adds weight. Retrieved documents (indirect
injection) are judged more strictly than the user's own prompt, because a document has no
business giving the model instructions at all.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..text import variants
from ..types import Action, Finding, Verdict

_W = r"(?:\W+\w+){0,6}?\W+"  # up to six words in between


@dataclass(frozen=True)
class Rule:
    check: str
    category: str
    weight: float
    pattern: re.Pattern


def _r(check: str, category: str, weight: float, pattern: str) -> Rule:
    return Rule(check, category, weight, re.compile(pattern, re.I))


RULES: tuple[Rule, ...] = (
    # --- prompt injection: attempts to replace or read the instructions
    _r("prompt_injection", "instruction_override", 1.0,
       rf"\b(ignore|disregard|forget|override|bypass|skip)\b{_W}(previous|prior|above|earlier|preceding|all|any|your|the|these|system)\b{_W}?(instructions?|rules|guidelines|directions|prompts?|constraints|guardrails)\b"),
    _r("prompt_injection", "instruction_override", 1.0,
       rf"\b(pay no attention to|stop following|no longer follow|do not follow|don'?t follow)\b{_W}?(what you were (told|given)|your (previous|prior|original|earlier|initial) (instructions|rules|orders|guidelines))"),
    _r("prompt_injection", "instruction_override", 1.0,
       r"\b(previous|prior|earlier|above|original|system|initial)\s+(instructions|rules|guidelines|directives)\s+(no longer apply|(are|were|have been)\s+(cancelled|canceled|void|revoked|obsolete|suspended|lifted))"),
    _r("prompt_injection", "new_instructions", 0.8,
       r"\b(new|updated|real|actual|revised)\s+(system\s+)?(instructions?|rules|directives?)\s*(:|are|follow)|\bfrom now on,?\s+(you|always|only|never)\b"),
    _r("prompt_injection", "system_prompt_extraction", 0.9,
       rf"\b(reveal|show|print|repeat|output|display|tell me|give me|leak|dump|what (is|are|was))\b{_W}?(your|the)\s+(?:(?:system|initial|original|hidden|secret|developer)\s+){{1,2}}(prompt|instructions?|message|rules)"),
    _r("prompt_injection", "system_prompt_extraction", 0.9,
       r"\b(everything|the text|the words)\s+(above|before)\s+(this|my)\s+(line|message|point)\b.{0,40}\b(repeat|print|output|show|tell|copy)"
       r"|\b(repeat|print|output|show|copy)\b.{0,30}\b(everything|the text|the words)\s+(above|before)\s+(this|my)\s+(line|message|point)\b"),
    _r("prompt_injection", "fake_role_marker", 0.9,
       r"(<\|im_start\|>|<\|system\|>|\[/?INST\]|<<SYS>>|^\s*#{1,3}\s*(system|assistant)\s*:|^\s*(system|developer)\s*:)"),
    _r("prompt_injection", "exfiltration_link", 0.9,
       r"!\[[^\]]*\]\(https?://[^)]*(\?|&)[^)]*=\s*(\{|\$|%7B|<)"),
    _r("prompt_injection", "tool_hijack", 0.7,
       rf"(?:^|[.!?:;,]\s*|\b(?:assistant|ai|you|agents? reading this)\b[^.]{{0,40}}?)\b(call|use|invoke|run|execute|trigger)\b{_W}?(the\s+)?\w+[_\s]?(tool|function|api)\b{_W}(send|email|post|upload|forward|transfer|delete)\b"),
    # --- jailbreak: attempts to remove the safety behaviour itself
    _r("jailbreak", "persona_override", 0.9,
       rf"\b(you are now|act as|pretend (to be|you are|that you are)|role-?play as|from now on you are)\b{_W}?(dan\b|an? (unrestricted|unfiltered|uncensored|jailbroken|evil|amoral)|no (rules|restrictions|limits|filters))"),
    _r("jailbreak", "persona_override", 0.9,
       r"\b(play a game|let'?s pretend|imagine|in this game)\b.{0,60}\byou (have|had) no (rules|guidelines|restrictions|limits|filters)\b"),
    _r("jailbreak", "do_anything_now", 1.0, r"\bdo anything now\b|\bDAN mode\b|\bjailbreak(ed)? mode\b|\bdeveloper mode (enabled|on|activated)\b"),
    _r("jailbreak", "remove_safety", 0.9,
       rf"\b(without|ignore|disable|turn off|remove|bypass|lift)\b{_W}?(?:(your|its)\s+(\w+\s+)?(filters?|restrictions|limitations|guidelines|policies|safeguards|censorship)|(any|all|the)?\s*(safety|ethical|moral)\s+(filters?|restrictions|limitations|guidelines|policies|safeguards)|any\s+(content\s+)?(filters|restrictions|limitations|censorship))\b"),
    _r("jailbreak", "hypothetical_wrapper", 0.5,
       r"\b(hypothetically|in a fictional (world|story)|for a (novel|movie|story)|purely (fictional|academic))\b.{0,80}\b(how to|step[- ]by[- ]step|instructions for)\b"),
)

ENCODED_BONUS = 0.3  # a rule that only fires after decoding is a deliberate evasion


class InjectionDetector:
    def __init__(self, prompt_threshold: float = 0.8, document_threshold: float = 0.5) -> None:
        self.prompt_threshold = prompt_threshold
        self.document_threshold = document_threshold

    def findings(self, text: str) -> list[Finding]:
        best: dict[tuple[str, str], Finding] = {}
        for name, variant in variants(text):
            for rule in RULES:
                m = rule.pattern.search(variant)
                if not m:
                    continue
                score = min(1.0, rule.weight + (ENCODED_BONUS if name != "plain" else 0.0))
                category = rule.category if name == "plain" else f"{rule.category}+{name}"
                key = (rule.check, rule.category)
                if key not in best or score > best[key].score:
                    best[key] = Finding(f"input.{rule.check}", category, score, m.group(0)[:80])
        return sorted(best.values(), key=lambda f: -f.score)

    def check_prompt(self, text: str) -> Verdict:
        v = Verdict("input", text=text)
        for f in self.findings(text):
            action = Action.BLOCK if f.score >= self.prompt_threshold else Action.FLAG
            v.add(Finding(f.check, f.category, f.score, f.evidence, action))
        return v

    def check_documents(self, docs: list[dict]) -> tuple[list[dict], Verdict]:
        """Drop documents that try to instruct the model (indirect injection); keep the rest."""
        v = Verdict("input")
        kept = []
        for doc in docs:
            hits = [f for f in self.findings(doc.get("text", "")) if f.score >= self.document_threshold]
            if hits:
                for f in hits:
                    v.add(Finding("input.indirect_injection", f.category, f.score,
                                  f"doc {doc.get('id', '?')}: {f.evidence}", Action.REDACT))
            else:
                kept.append(doc)
        return kept, v
