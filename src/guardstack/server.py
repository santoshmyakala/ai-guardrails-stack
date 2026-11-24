"""HTTP API around the guarded agent.

Callers authenticate with a bearer key (configured as SHA-256 digests) that maps to an identity
and a role: `client` may start and resume runs and use the check endpoints; `approver` may list
and decide pending approvals. The identity, not anything in the request body, is who the audit
log records.
"""

import hashlib
import hmac
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException
from prometheus_client import make_asgi_app
from pydantic import BaseModel, Field

from .input import pii
from .output import grounding, leakage, moderation
from .pipeline import GuardedAgent
from .tools.approvals import ApprovalError


class RunRequest(BaseModel):
    agent: str
    prompt: str = Field(min_length=1, max_length=20_000)
    documents: list[dict] = Field(default_factory=list, max_length=50)
    response_schema: dict | None = None


class ResumeRequest(BaseModel):
    approval_id: str


class Decision(BaseModel):
    approve: bool


class CheckRequest(BaseModel):
    text: str = Field(max_length=50_000)
    sources: list[dict] = Field(default_factory=list)


def _findings(v) -> list[dict]:
    return [{"check": f.check, "category": f.category, "score": f.score, "action": f.action.value} for f in v.findings]


def create_app(agent: GuardedAgent, callers: list[dict]) -> FastAPI:
    keys = {c["key_sha256"].lower(): c for c in callers}

    def caller(authorization: Annotated[str | None, Header()] = None) -> dict:
        token = (authorization or "").removeprefix("Bearer ").strip()
        digest = hashlib.sha256(token.encode()).hexdigest()
        match = next((c for d, c in keys.items() if hmac.compare_digest(d, digest)), None)
        if not token or match is None:
            raise HTTPException(401, "missing or invalid API key", headers={"WWW-Authenticate": "Bearer"})
        return match

    def role(required: str):
        def check(c: Annotated[dict, Depends(caller)]) -> dict:
            if c["role"] != required:
                raise HTTPException(403, f"needs the {required} role")
            return c
        return check

    Client = Annotated[dict, Depends(role("client"))]
    Approver = Annotated[dict, Depends(role("approver"))]

    app = FastAPI(title="guardstack", docs_url=None, redoc_url=None)
    app.mount("/metrics", make_asgi_app(registry=agent.metrics.registry))

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok"}

    @app.post("/v1/runs")
    def start(req: RunRequest, c: Client) -> dict:
        if req.agent not in agent.cfg.agents:
            raise HTTPException(404, "unknown agent")
        return agent.run(req.agent, c["name"], req.prompt, req.documents, req.response_schema).public()

    @app.post("/v1/runs/{run_id}/resume")
    def resume(run_id: str, req: ResumeRequest, c: Client) -> dict:
        state = agent.paused.get(run_id)
        if state is None or state.user != c["name"]:
            raise HTTPException(404, "no paused run with this id for you")
        return agent.resume(run_id, req.approval_id).public()

    @app.get("/v1/approvals")
    def pending(c: Approver) -> list[dict]:
        return [a.public() for a in agent.approvals.pending()]

    @app.post("/v1/approvals/{approval_id}")
    def decide(approval_id: str, d: Decision, c: Approver) -> dict:
        try:
            a = agent.approvals.decide(approval_id, c["name"], d.approve)
        except ApprovalError as e:
            raise HTTPException(409, str(e)) from e
        agent.audit.append({"run_id": a.run_id, "agent": a.agent, "user": c["name"], "layer": "tool",
                            "check": "approval_decision", "action": a.status, "reasons": [a.tool]})
        return a.public()

    @app.post("/v1/check/input")
    def check_input(req: CheckRequest, c: Client) -> dict:
        inj = agent.injection.check_prompt(req.text)
        red = pii.redact(req.text)
        return {"action": max(inj.action, red.action, key=lambda a: ["allow", "flag", "redact", "approval", "block"].index(a.value)).value,
                "findings": _findings(inj) + _findings(red), "redacted": red.text}

    @app.post("/v1/check/output")
    def check_output(req: CheckRequest, c: Client) -> dict:
        leak = leakage.check(req.text)
        mod = moderation.check(leak.text)
        out = {"findings": _findings(leak) + _findings(mod), "text": leak.text}
        if req.sources:
            g = grounding.check(req.text, req.sources)
            out["findings"] += _findings(g.verdict)
            out["grounding_score"] = round(g.score, 3)
        actions = [f["action"] for f in out["findings"]]
        out["action"] = "block" if "block" in actions else "redact" if "redact" in actions else "flag" if actions else "allow"
        return out

    return app
