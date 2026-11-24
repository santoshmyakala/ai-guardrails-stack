"""Human approval for high-risk actions.

An approval is bound to the exact arguments (by digest), can be decided only by a configured
approver who is not the requester, expires, and is consumed by a single execution: approving
"refund 50 EUR" cannot be replayed, or turned into "refund 5000 EUR".
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field


class ApprovalError(Exception):
    pass


def digest(tool: str, args: dict) -> str:
    return hashlib.sha256(json.dumps({"tool": tool, "args": args}, sort_keys=True, default=str).encode()).hexdigest()


@dataclass
class Approval:
    id: str
    run_id: str
    agent: str
    requested_by: str
    tool: str
    args: dict
    args_digest: str
    reasons: list[str]
    created: float
    expires: float
    status: str = "pending"  # pending | approved | denied | used | expired
    decided_by: str | None = None

    def public(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


@dataclass
class ApprovalStore:
    approvers: set[str]
    ttl_seconds: int = 900
    clock: callable = time.time
    items: dict[str, Approval] = field(default_factory=dict)

    def request(self, run_id: str, agent: str, requested_by: str, tool: str, args: dict, reasons: list[str]) -> Approval:
        now = self.clock()
        a = Approval(secrets.token_urlsafe(12), run_id, agent, requested_by, tool, args, digest(tool, args),
                     reasons, now, now + self.ttl_seconds)
        self.items[a.id] = a
        return a

    def _get(self, approval_id: str) -> Approval:
        a = self.items.get(approval_id)
        if a is None:
            raise ApprovalError("unknown approval")
        if a.status == "pending" and self.clock() > a.expires:
            a.status = "expired"
        return a

    def decide(self, approval_id: str, approver: str, approve: bool) -> Approval:
        a = self._get(approval_id)
        if a.status != "pending":
            raise ApprovalError(f"approval is {a.status}")
        if approver not in self.approvers:
            raise ApprovalError("not an approver")
        if approver == a.requested_by:
            raise ApprovalError("requester cannot approve their own action")
        a.status, a.decided_by = ("approved" if approve else "denied"), approver
        return a

    def consume(self, approval_id: str, tool: str, args: dict) -> Approval:
        a = self._get(approval_id)
        if a.status != "approved":
            raise ApprovalError(f"approval is {a.status}")
        if a.tool != tool or a.args_digest != digest(tool, args):
            raise ApprovalError("arguments differ from what was approved")
        a.status = "used"
        return a

    def pending(self) -> list[Approval]:
        return [a for a in self.items.values() if self._get(a.id).status == "pending"]
