"""Leak prevention: secrets, personal data and the system prompt must not reach the user.

Secrets are redacted in place. The system prompt is protected twice: a random canary token is
embedded in it (seeing the token in an answer proves a leak), and any run of eight or more
consecutive words copied from it is treated as a leak too (OWASP LLM07).
"""

from __future__ import annotations

import re
import secrets as _secrets

from ..input.pii import Vault
from ..input.pii import find as find_pii
from ..types import Action, Finding, Verdict

SECRET_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("aws_secret_key", re.compile(r"(?i)aws.{0,20}(?:secret|key).{0,5}[:=]\s*['\"]?[A-Za-z0-9/+]{40}\b")),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?(?:-----END[^-]*-----|$)")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("generic_secret", re.compile(r"(?i)\b(?:api[_-]?key|secret|password|passwd|token)\b\s*[:=]\s*['\"]?[A-Za-z0-9/+_\-.]{16,}")),
)


def new_canary() -> str:
    return f"gs-canary-{_secrets.token_hex(8)}"


def _words(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.lower())


def copied_run(system_prompt: str, output: str, n: int = 8) -> str | None:
    sw, ow = _words(system_prompt), _words(output)
    grams = {tuple(sw[i:i + n]) for i in range(len(sw) - n + 1)}
    for i in range(len(ow) - n + 1):
        if tuple(ow[i:i + n]) in grams:
            return " ".join(ow[i:i + n])
    return None


def check(output: str, system_prompt: str = "", canary: str | None = None, vault: Vault | None = None) -> Verdict:
    v = Verdict("output")
    text = output
    if canary and canary in text:
        v.add(Finding("output.leak", "system_prompt_canary", 1.0, canary, Action.BLOCK))
    if system_prompt:
        run = copied_run(system_prompt, text)
        if run:
            v.add(Finding("output.leak", "system_prompt_copy", 1.0, run[:80], Action.BLOCK))
    for kind, pattern in SECRET_PATTERNS:
        for _ in pattern.finditer(text):
            v.add(Finding("output.leak", kind, 1.0, f"<{kind}>", Action.REDACT))
        text = pattern.sub(f"[REDACTED:{kind}]", text)
    vault = vault if vault is not None else Vault()
    pieces, last = [], 0
    for start, end, kind in find_pii(text):
        pieces += [text[last:start], vault.token(kind, text[start:end])]
        last = end
        v.add(Finding("output.pii", kind.lower(), 1.0, f"<{kind}>", Action.REDACT))
    pieces.append(text[last:])
    v.text = "".join(pieces)
    return v
