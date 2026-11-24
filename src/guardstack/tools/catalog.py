"""The tools an agent may call: arguments as strict Pydantic models, plus the scopes each needs.

The demo handlers have no real side effects: they record what would have happened in an
in-memory ledger, so the whole stack can be tested end to end without a mail server or a
payment provider.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Args(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class SearchDocs(Args):
    query: str = Field(min_length=2, max_length=300)
    top_k: int = Field(default=3, ge=1, le=10)


class HttpFetch(Args):
    url: str = Field(max_length=2048, pattern=r"^[a-zA-Z][a-zA-Z0-9+.-]*://[^\s]+$")


class SendEmail(Args):
    to: list[str] = Field(min_length=1, max_length=10)
    subject: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=10_000)


class RefundPayment(Args):
    order_id: str = Field(pattern=r"^ORD-\d{4,10}$")
    amount: Decimal = Field(gt=0, le=Decimal("100000"), decimal_places=2)
    currency: Literal["EUR", "SEK", "USD"]


class DeleteRecord(Args):
    table: Literal["customers", "orders", "tickets", "audit_log"]
    record_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")


class RunPython(Args):
    code: str = Field(min_length=1, max_length=4000)


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    args: type[Args]
    scopes: frozenset[str]
    side_effect: bool = False
    external: bool = False   # sends data outside the organisation
    sandboxed: bool = False
    handler: Callable[..., Any] | None = None

    def schema(self) -> dict:
        """OpenAI function-calling schema for this tool."""
        return {"type": "function", "function": {"name": self.name, "description": self.description,
                                                 "parameters": self.args.model_json_schema()}}


@dataclass
class Ledger:
    """What the demo tools 'did' (stands in for real side effects in tests and demos)."""
    effects: list[dict] = field(default_factory=list)

    def record(self, kind: str, **details: Any) -> dict:
        entry = {"effect": kind, **{k: str(v) for k, v in details.items()}}
        self.effects.append(entry)
        return {"status": "done", **entry}


def build_catalog(ledger: Ledger, documents: list[dict] | None = None,
                  fetch: Callable[[str], str] | None = None, sandbox: Any = None) -> dict[str, ToolSpec]:
    docs = documents or []

    def search_docs(a: SearchDocs) -> list[dict]:
        words = {w for w in a.query.lower().split() if len(w) > 2}
        scored = sorted(docs, key=lambda d: -len(words & set(d["text"].lower().split())))
        return [{"id": d["id"], "text": d["text"]} for d in scored[: a.top_k]]

    specs = [
        ToolSpec("search_docs", "Search the knowledge base.", SearchDocs, frozenset({"docs:read"}),
                 handler=search_docs),
        ToolSpec("http_fetch", "Fetch a public web page over HTTPS.", HttpFetch, frozenset({"web:read"}),
                 external=True, handler=lambda a: (fetch or (lambda u: f"[fetched {u}]"))(a.url)),
        ToolSpec("send_email", "Send an email.", SendEmail, frozenset({"email:send"}), side_effect=True,
                 external=True, handler=lambda a: ledger.record("email", to=",".join(a.to), subject=a.subject)),
        ToolSpec("refund_payment", "Refund (part of) an order.", RefundPayment, frozenset({"payments:refund"}),
                 side_effect=True, handler=lambda a: ledger.record("refund", order=a.order_id, amount=a.amount,
                                                                   currency=a.currency)),
        ToolSpec("delete_record", "Delete a record.", DeleteRecord, frozenset({"records:delete"}),
                 side_effect=True, handler=lambda a: ledger.record("delete", table=a.table, id=a.record_id)),
        ToolSpec("run_python", "Run a short Python snippet in an isolated sandbox (no network).", RunPython,
                 frozenset({"code:execute"}), sandboxed=True,
                 handler=lambda a: sandbox.run_python(a.code).as_dict() if sandbox else {"error": "no sandbox"}),
    ]
    return {s.name: s for s in specs}
