"""Format validation: structured answers must match their JSON Schema before anything downstream
parses them. Returns the parsed value or the exact errors (used for one repair attempt)."""

from __future__ import annotations

import json
import re

from jsonschema import Draft202012Validator

FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.S)


def extract_json(text: str):
    m = FENCE.search(text)
    candidate = (m.group(1) if m else text).strip()
    try:
        return json.loads(candidate)
    except ValueError:
        pass
    for open_, close in (("{", "}"), ("[", "]")):
        start, end = candidate.find(open_), candidate.rfind(close)
        if 0 <= start < end:
            try:
                return json.loads(candidate[start:end + 1])
            except ValueError:
                continue
    raise ValueError("no JSON value found")


def validate(text: str, schema: dict) -> tuple[object | None, list[str]]:
    try:
        value = extract_json(text)
    except ValueError as e:
        return None, [str(e)]
    errors = [f"{'/'.join(map(str, err.absolute_path)) or '(root)'}: {err.message}"
              for err in sorted(Draft202012Validator(schema).iter_errors(value), key=lambda e: list(e.path))]
    return (value if not errors else None), errors
