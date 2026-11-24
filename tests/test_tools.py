import pytest

from guardstack.tools.approvals import ApprovalError, ApprovalStore
from guardstack.types import Action

from .conftest import needs_docker


def agent(config, name="support-bot"):
    return config.agents[name]


@needs_docker
def test_unknown_and_unlisted_tools_are_blocked(guard, config):
    assert guard.decide(agent(config), "format_disk", {}).reasons == ["unknown_tool"]
    d = guard.decide(agent(config), "run_python", {"code": "print(1)"})
    assert d.action == Action.BLOCK and d.reasons == ["not_allowed_for_agent:support-bot"]


@needs_docker
def test_missing_scope_is_blocked(guard, config):
    from dataclasses import replace
    weak = replace(agent(config), scopes=frozenset({"docs:read"}))
    d = guard.decide(weak, "send_email", {"to": ["a@acme.example"], "subject": "s", "body": "b"})
    assert d.reasons == ["missing_scope:email:send"]


@needs_docker
@pytest.mark.parametrize("args, problem", [
    ({"order_id": "1234", "amount": "10.00", "currency": "EUR"}, "order_id"),
    ({"order_id": "ORD-1234", "amount": "-5", "currency": "EUR"}, "amount"),
    ({"order_id": "ORD-1234", "amount": "10.001", "currency": "EUR"}, "amount"),
    ({"order_id": "ORD-1234", "amount": "10", "currency": "BTC"}, "currency"),
    ({"order_id": "ORD-1234", "amount": "10", "currency": "EUR", "note": "x"}, "note"),
])
def test_arguments_are_validated_strictly(guard, config, args, problem):
    d = guard.decide(agent(config), "refund_payment", args)
    assert d.action == Action.BLOCK and any(problem in r for r in d.reasons), d.reasons


@needs_docker
def test_policy_decides_after_validation(guard, config):
    a = agent(config)
    assert guard.decide(a, "refund_payment", {"order_id": "ORD-1234", "amount": "40", "currency": "EUR"}).action == Action.ALLOW
    assert guard.decide(a, "refund_payment", {"order_id": "ORD-1234", "amount": "250", "currency": "EUR"}).action == Action.APPROVAL
    assert guard.decide(a, "refund_payment", {"order_id": "ORD-1234", "amount": "900", "currency": "EUR"}).action == Action.BLOCK
    ssrf = guard.decide(a, "http_fetch", {"url": "https://169.254.169.254/latest/meta-data/"})
    assert ssrf.action == Action.BLOCK and "internal address" in ssrf.reasons[0]


def test_unreachable_policy_fails_closed(config, ledger):
    from guardstack.policy.opa import OPAClient
    from guardstack.tools.catalog import build_catalog
    from guardstack.tools.guard import ToolGuard
    g = ToolGuard(build_catalog(ledger), OPAClient("http://127.0.0.1:9", timeout=0.5))
    d = g.decide(agent(config), "search_docs", {"query": "refunds"})
    assert d.action == Action.BLOCK and d.reasons[0].startswith("policy_error")


class Clock:
    t = 1000.0

    def __call__(self):
        return self.t


def test_approvals_are_bound_single_use_and_need_a_second_person():
    clock = Clock()
    store = ApprovalStore({"alice@acme.example", "bob@acme.example"}, ttl_seconds=60, clock=clock)
    args = {"order_id": "ORD-1", "amount": "250.00", "currency": "EUR"}
    a = store.request("run1", "support-bot", "alice@acme.example", "refund_payment", args, ["big"])
    with pytest.raises(ApprovalError, match="own action"):
        store.decide(a.id, "alice@acme.example", True)
    with pytest.raises(ApprovalError, match="not an approver"):
        store.decide(a.id, "mallory@evil.example", True)
    store.decide(a.id, "bob@acme.example", True)
    with pytest.raises(ApprovalError, match="differ"):
        store.consume(a.id, "refund_payment", {**args, "amount": "2500.00"})
    store.consume(a.id, "refund_payment", args)
    with pytest.raises(ApprovalError, match="used"):
        store.consume(a.id, "refund_payment", args)


def test_approvals_expire():
    clock = Clock()
    store = ApprovalStore({"bob@acme.example"}, ttl_seconds=60, clock=clock)
    a = store.request("run1", "support-bot", "alice", "delete_record", {"table": "tickets", "record_id": "1"}, [])
    clock.t += 61
    with pytest.raises(ApprovalError, match="expired"):
        store.decide(a.id, "bob@acme.example", True)
