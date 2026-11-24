"""Configuration: one YAML file describes agents, approvers and each layer's thresholds."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .tools.guard import AgentProfile


@dataclass
class Config:
    agents: dict[str, AgentProfile]
    approvers: set[str]
    prompt_threshold: float = 0.8
    document_threshold: float = 0.5
    topics: dict = field(default_factory=dict)
    grounding_min_support: float = 0.5
    grounding_block_below: float = 0.5
    restore_pii: bool = False
    opa_url: str = "http://127.0.0.1:8181"
    max_steps: int = 6
    format_repairs: int = 1

    @classmethod
    def parse(cls, raw: dict) -> Config:
        inp, out, pol = raw.get("input", {}), raw.get("output", {}), raw.get("policy", {})
        return cls(
            agents={k: AgentProfile.from_config(k, v) for k, v in (raw.get("agents") or {}).items()},
            approvers=set(raw.get("approvers") or []),
            prompt_threshold=float(inp.get("prompt_threshold", 0.8)),
            document_threshold=float(inp.get("document_threshold", 0.5)),
            topics=inp.get("topics") or {},
            grounding_min_support=float(out.get("grounding_min_support", 0.5)),
            grounding_block_below=float(out.get("grounding_block_below", 0.5)),
            restore_pii=bool(out.get("restore_pii", False)),
            opa_url=pol.get("opa_url", "http://127.0.0.1:8181"),
            max_steps=int(raw.get("max_steps", 6)),
            format_repairs=int(out.get("format_repairs", 1)),
        )

    @classmethod
    def load(cls, path: str | Path) -> Config:
        return cls.parse(yaml.safe_load(Path(path).read_text()))
