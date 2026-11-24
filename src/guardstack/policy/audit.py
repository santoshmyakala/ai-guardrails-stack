"""Tamper-evident audit log: append-only JSON lines, each record chained to the previous one by an
HMAC. Editing, deleting, inserting or reordering any record breaks the chain at that point, and
without the key an attacker cannot recompute it. Prompts are recorded as SHA-256 digests only.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
from pathlib import Path

GENESIS = "0" * 64


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _mac(key: bytes, record: dict) -> str:
    body = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hmac.new(key, body, hashlib.sha256).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path, key: bytes, clock=time.time) -> None:
        if len(key) < 16:
            raise ValueError("audit key must be at least 16 bytes")
        self.path, self.key, self.clock = Path(path), key, clock
        self._lock = threading.Lock()
        self.seq, self.prev = 0, GENESIS
        if self.path.exists():
            last = None
            for line in self.path.read_text().splitlines():
                if line.strip():
                    last = json.loads(line)
            if last:
                self.seq, self.prev = last["seq"], last["mac"]

    def append(self, event: dict) -> dict:
        with self._lock:
            record = {"seq": self.seq + 1, "ts": round(self.clock(), 3), "prev": self.prev, **event}
            record["mac"] = _mac(self.key, record)
            with self.path.open("a") as fh:
                fh.write(json.dumps(record, sort_keys=True, default=str) + "\n")
            self.seq, self.prev = record["seq"], record["mac"]
            return record


def verify(path: str | Path, key: bytes) -> tuple[int, list[str]]:
    """(records checked, problems). An empty problem list means the chain is intact."""
    problems, prev, count = [], GENESIS, 0
    for n, line in enumerate(Path(path).read_text().splitlines(), 1):
        if not line.strip():
            continue
        count += 1
        try:
            rec = json.loads(line)
        except ValueError:
            problems.append(f"line {n}: not JSON")
            break
        mac = rec.pop("mac", None)
        if rec.get("seq") != count:
            problems.append(f"line {n}: sequence {rec.get('seq')} where {count} was expected (record removed or inserted)")
        if rec.get("prev") != prev:
            problems.append(f"line {n}: chain broken (previous record changed, removed or reordered)")
        if mac is None or not hmac.compare_digest(mac, _mac(key, rec)):
            problems.append(f"line {n}: MAC mismatch (record altered)")
        if problems:
            break
        prev = mac
    return count, problems
