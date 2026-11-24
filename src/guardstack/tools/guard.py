"""The tool layer: decides whether a model-proposed tool call may run, in this order:

1. the tool exists and is on this agent's allowlist (least privilege)
2. the agent holds every scope the tool needs
3. the arguments validate against the tool's strict schema
4. the policy (OPA, Rego) allows it, possibly only with human approval

Any failure blocks the call; the model gets the reason back so it can recover.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from decimal import Decimal

from pydantic import ValidationError

from ..policy.opa import OPAClient, PolicyError
from ..types import Action
from .catalog import ToolSpec


@dataclass(frozen=True)
class AgentProfile:
    id: str
    tools: frozenset[str]
    scopes: frozenset[str]
    allowed_domains: tuple[str, ...] = ()
    internal_domains: tuple[str, ...] = ()
    max_refund: float = 0
    refund_approval_over: float = 0

    @classmethod
    def from_config(cls, agent_id: str, cfg: dict) -> AgentProfile:
        return cls(agent_id, frozenset(cfg.get("tools", [])), frozenset(cfg.get("scopes", [])),
                   tuple(cfg.get("allowed_domains", [])), tuple(cfg.get("internal_domains", [])),
                   float(cfg.get("max_refund", 0)), float(cfg.get("refund_approval_over", 0)))


@dataclass
class ToolDecision:
    action: Action
    tool: str
    reasons: list[str] = field(default_factory=list)
    args: dict | None = None  # validated, JSON-safe arguments


def _jsonable(model) -> dict:
    return json.loads(model.model_dump_json())


class ToolGuard:
    def __init__(self, catalog: dict[str, ToolSpec], policy: OPAClient) -> None:
        self.catalog = catalog
        self.policy = policy

    def decide(self, agent: AgentProfile, name: str, raw_args: dict | str, context: dict | None = None) -> ToolDecision:
        spec = self.catalog.get(name)
        if spec is None:
            return ToolDecision(Action.BLOCK, name, ["unknown_tool"])
        if name not in agent.tools:
            return ToolDecision(Action.BLOCK, name, [f"not_allowed_for_agent:{agent.id}"])
        missing = sorted(spec.scopes - agent.scopes)
        if missing:
            return ToolDecision(Action.BLOCK, name, [f"missing_scope:{s}" for s in missing])
        try:
            text = raw_args if isinstance(raw_args, str) else json.dumps(raw_args, default=str)
            args = spec.args.model_validate_json(text)
        except ValidationError as e:
            problems = [f"{'.'.join(map(str, err['loc'])) or 'arguments'}: {err['msg']}" for err in e.errors()]
            return ToolDecision(Action.BLOCK, name, [f"invalid_arguments: {p}" for p in problems])
        safe = _jsonable(args)
        payload = {
            "agent": {"id": agent.id, "scopes": sorted(agent.scopes), "allowed_domains": list(agent.allowed_domains),
                      "internal_domains": list(agent.internal_domains), "max_refund": agent.max_refund,
                      "refund_approval_over": agent.refund_approval_over},
            "tool": {"name": name, "side_effect": spec.side_effect, "external": spec.external,
                     "sandboxed": spec.sandboxed},
            "args": {k: (str(v) if isinstance(v, Decimal) else v) for k, v in safe.items()},
            "context": context or {},
        }
        try:
            d = self.policy.decide(payload)
        except PolicyError as e:
            return ToolDecision(Action.BLOCK, name, [f"policy_error: {e}"])
        if not d["allow"]:
            return ToolDecision(Action.BLOCK, name, list(d.get("reasons", [])), safe)
        if d.get("approval"):
            return ToolDecision(Action.APPROVAL, name, list(d.get("reasons", [])), safe)
        return ToolDecision(Action.ALLOW, name, [], safe)

    def execute(self, name: str, args: dict):
        spec = self.catalog[name]
        return spec.handler(spec.args.model_validate_json(json.dumps(args)))
