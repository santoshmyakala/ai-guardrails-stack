"""Normalisation and decoding, so detectors see what the model would understand.

Attackers hide instructions with zero-width characters, look-alike letters, s p a c e d letters,
leetspeak, Base64, hex, ROT13 or URL encoding. `variants()` returns the plain text plus every
decoding that produced readable text; detectors scan all of them.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
from urllib.parse import unquote

ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍‎‏⁠⁡⁢⁣⁤﻿­"))
# Cyrillic/Greek letters that render like Latin ones (the ones commonly used to dodge filters).
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "һ": "h", "ӏ": "l", "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X", "ο": "o", "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v",
    "ρ": "p", "τ": "t", "υ": "u", "Ο": "O", "Α": "A", "Ε": "E", "Ι": "I",
})
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})
_SPACED = re.compile(r"\b(?:[A-Za-z][ ._\-*]){4,}[A-Za-z]\b")
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX = re.compile(r"\b(?:[0-9a-fA-F]{2}){8,}\b")
_URLENC = re.compile(r"(?:%[0-9a-fA-F]{2}){4,}")


def normalise(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).translate(ZERO_WIDTH).translate(CONFUSABLES)
    text = _SPACED.sub(lambda m: re.sub(r"[ ._\-*]", "", m.group(0)), text)
    return re.sub(r"\s+", " ", text).strip()


def _readable(raw: bytes) -> str | None:
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(ch.isprintable() or ch.isspace() for ch in s)
    letters = sum(ch.isalpha() for ch in s)
    return s if s and printable / len(s) > 0.95 and letters / len(s) > 0.5 else None


def variants(text: str) -> list[tuple[str, str]]:
    """[(name, text)] – the normalised text first, then each readable decoding."""
    base = normalise(text)
    out = [("plain", base)]
    leet = base.translate(LEET)
    if leet != base:
        out.append(("leetspeak", leet))
    for token in _B64.findall(text):
        try:
            decoded = _readable(base64.b64decode(token + "=" * (-len(token) % 4), validate=True))
        except (binascii.Error, ValueError):
            decoded = None
        if decoded:
            out.append(("base64", normalise(decoded)))
    for token in _HEX.findall(text):
        decoded = _readable(bytes.fromhex(token))
        if decoded:
            out.append(("hex", normalise(decoded)))
    if _URLENC.search(text):
        out.append(("url", normalise(unquote(text))))
    out.append(("rot13", codecs.decode(base, "rot13")))
    return out
