"""PII detection and reversible redaction.

Each detector is a pattern plus a validator (Luhn, IBAN mod-97, date and checksum for Swedish
personal identity numbers, octet ranges), so "looks like a number" is not enough to redact.
Redaction replaces values with typed placeholders (<EMAIL_1>); the mapping stays server-side in
the request context, so the model never sees the values and they can be restored for the same
user if policy allows.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date

from ..types import Action, Finding, Verdict


def luhn(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
        alt = not alt
    return total % 10 == 0


def _card(s: str) -> bool:
    d = re.sub(r"\D", "", s)
    return 13 <= len(d) <= 19 and luhn(d) and len(set(d)) > 1


def _iban(s: str) -> bool:
    s = s.replace(" ", "").upper()
    if not 15 <= len(s) <= 34:
        return False
    rearranged = s[4:] + s[:4]
    return int("".join(str(int(c, 36)) for c in rearranged)) % 97 == 1


def _personnummer(s: str) -> bool:
    d = re.sub(r"\D", "", s)[-10:]
    month, day = int(d[2:4]), int(d[4:6]) % 60  # +60 marks a coordination number
    try:
        date(2000, month, day)
    except ValueError:
        return False
    return luhn(d)


def _ipv4(s: str) -> bool:
    parts = s.split(".")
    return all(p.isdigit() and int(p) <= 255 and (p == "0" or not p.startswith("0")) for p in parts) and s not in ("0.0.0.0",)


def _ssn(s: str) -> bool:
    a, g, n = s.split("-")
    return a not in ("000", "666") and not a.startswith("9") and g != "00" and n != "0000"


def _phone(s: str) -> bool:
    return 9 <= len(re.sub(r"\D", "", s)) <= 15


@dataclass(frozen=True)
class Detector:
    kind: str
    pattern: re.Pattern
    valid: Callable[[str], bool] = lambda s: True


DETECTORS: tuple[Detector, ...] = (
    Detector("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    Detector("IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b"), _iban),
    Detector("CARD", re.compile(r"\b(?:\d[ -]?){12,18}\d\b"), _card),
    Detector("PERSONNUMMER", re.compile(r"\b(?:19|20)?\d{6}[-+]?\d{4}\b"), _personnummer),
    Detector("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), _ssn),
    Detector("PHONE", re.compile(r"(?<![\w-])\+\d{1,3}[ -]?(?:\(?\d{1,4}\)?[ -]?){2,5}\d{2,4}\b|\b0\d{1,3}[- ]\d{2,4}(?:[ -]\d{2,4}){1,3}\b"), _phone),
    Detector("IPV4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), _ipv4),
)


@dataclass
class Vault:
    """Placeholder <-> value mapping for one request. Never logged."""
    values: dict[str, str] = field(default_factory=dict)
    counters: dict[str, int] = field(default_factory=dict)

    def token(self, kind: str, value: str) -> str:
        for tok, val in self.values.items():
            if val == value and tok.startswith(f"<{kind}_"):
                return tok
        self.counters[kind] = self.counters.get(kind, 0) + 1
        tok = f"<{kind}_{self.counters[kind]}>"
        self.values[tok] = value
        return tok

    def restore(self, text: str) -> str:
        for tok, val in self.values.items():
            text = text.replace(tok, val)
        return text


def find(text: str) -> list[tuple[int, int, str]]:
    """Non-overlapping (start, end, kind), earlier detectors winning ties."""
    spans: list[tuple[int, int, str]] = []
    for det in DETECTORS:
        for m in det.pattern.finditer(text):
            if not det.valid(m.group(0)):
                continue
            if any(m.start() < e and s < m.end() for s, e, _ in spans):
                continue
            spans.append((m.start(), m.end(), det.kind))
    return sorted(spans)


def redact(text: str, vault: Vault | None = None, check: str = "input.pii") -> Verdict:
    vault = vault if vault is not None else Vault()
    v = Verdict(check.split(".")[0])
    out, last = [], 0
    for start, end, kind in find(text):
        out.append(text[last:start])
        out.append(vault.token(kind, text[start:end]))
        last = end
        v.add(Finding(check, kind.lower(), 1.0, f"<{kind}>", Action.REDACT))
    out.append(text[last:])
    v.text = "".join(out)
    return v
