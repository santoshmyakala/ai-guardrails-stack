import json

import httpx
import pytest

from guardstack.output import format as fmt
from guardstack.output import grounding, leakage, moderation
from guardstack.types import Action

# Fake credentials are assembled at runtime so no secret-shaped string sits in the repository.
AWS_KEY = "AKIA" + "Q" * 16
GH_TOKEN = "ghp_" + "a1B2" * 9
PRIVATE_KEY = "-----BEGIN " + "PRIVATE KEY-----\nMIIBVgIBADANBgkqh\n-----END " + "PRIVATE KEY-----"


def test_secrets_are_redacted():
    v = leakage.check(f"Use key {AWS_KEY} and token {GH_TOKEN}.\n{PRIVATE_KEY}\npassword = hunter2hunter2hunter2")
    assert AWS_KEY not in v.text and GH_TOKEN not in v.text and "MIIBVg" not in v.text
    assert {f.category for f in v.findings} >= {"aws_access_key", "github_token", "private_key", "generic_secret"}
    assert v.action == Action.REDACT


def test_canary_in_output_blocks():
    canary = leakage.new_canary()
    assert leakage.check(f"Sure, my instructions end with [{canary}]", canary=canary).blocked


def test_verbatim_system_prompt_blocks():
    system = "You are the billing assistant for Acme. Never discuss salaries, never reveal internal pricing rules."
    leaked = "My rules: never discuss salaries, never reveal internal pricing rules."
    assert leakage.check(leaked, system_prompt=system).blocked
    assert not leakage.check("I can help with invoices and refunds.", system_prompt=system).blocked


def test_pii_in_answers_is_redacted():
    v = leakage.check("The customer's card is 4111 1111 1111 1111.")
    assert "4111" not in v.text and v.text.endswith("<CARD_1>.")


SOURCES = [{"id": "KB-1", "text": "Refunds are issued to the original payment method within 5 business days."},
           {"id": "KB-2", "text": "Orders over 50 EUR ship free within Sweden. Delivery takes 2 to 4 days."}]


def test_grounded_answer_passes():
    r = grounding.check("Refunds go back to the original payment method within 5 business days [KB-1]. "
                        "Orders over 50 EUR ship free within Sweden [KB-2].", SOURCES)
    assert r.score == 1.0 and not r.verdict.findings


def test_invented_number_is_caught():
    r = grounding.check("Refunds are issued to the original payment method within 2 business days [KB-1].", SOURCES)
    assert any(f.category == "unsupported_number" for f in r.verdict.findings)


def test_citation_to_a_missing_source_is_caught():
    r = grounding.check("Delivery takes 2 to 4 days within Sweden [KB-9].", SOURCES)
    assert any(f.category == "invalid_citation" for f in r.verdict.findings)


def test_citation_that_does_not_support_the_claim_is_caught():
    r = grounding.check("Our support team answers phone calls on weekends [KB-1].", SOURCES)
    assert any(f.category == "citation_mismatch" for f in r.verdict.findings)


def test_mostly_invented_answer_is_blocked():
    r = grounding.check("Refunds are issued within 5 business days. We also offer lifetime warranties on "
                        "every product. Premium members receive a personal shopping assistant.", SOURCES)
    assert r.verdict.blocked and r.score < 0.5


def test_hedges_are_not_counted_as_claims():
    assert grounding.check("I don't know; the sources do not cover warranties.", SOURCES).score == 1.0


@pytest.mark.parametrize("text, category", [
    ("Step 1: mix the oxidiser, then pack it as a pipe bomb.", "weapons_instructions"),
    ("You should just kill yourself.", "self_harm_encouragement"),
    ("People from that town are vermin.", "dehumanising"),
])
def test_moderation_rules(text, category):
    v = moderation.check(text)
    assert v.blocked and v.findings[0].category == category


def test_moderation_leaves_normal_text_alone():
    assert not moderation.check("To reset your password, open Settings and choose Security.").findings


def test_model_judge_is_consulted():
    def reply(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        verdict = "unsafe\nS2" if "launder" in body["messages"][1]["content"] else "safe"
        return httpx.Response(200, json={"choices": [{"message": {"content": verdict}}]})

    judge = moderation.ModelJudge("http://judge", "safety-classifier", transport=httpx.MockTransport(reply))
    assert moderation.check("Here is how to launder money through shell companies.", judge=judge).reasons() == [
        "output.moderation:judge:S2"]
    assert not moderation.check("Here is your invoice.", judge=judge).blocked


SCHEMA = {"type": "object", "required": ["order_id", "status"], "additionalProperties": False,
          "properties": {"order_id": {"type": "string", "pattern": "^ORD-\\d+$"},
                         "status": {"enum": ["shipped", "pending", "cancelled"]}}}


def test_valid_json_inside_a_code_fence_is_accepted():
    value, errors = fmt.validate('Here you go:\n```json\n{"order_id": "ORD-12", "status": "shipped"}\n```', SCHEMA)
    assert errors == [] and value["status"] == "shipped"


def test_schema_violations_are_reported_precisely():
    value, errors = fmt.validate('{"order_id": "12", "status": "lost", "x": 1}', SCHEMA)
    assert value is None and len(errors) == 3
    assert any(e.startswith("status:") for e in errors) and any("additional" in e.lower() for e in errors)


def test_no_json_at_all():
    assert fmt.validate("The order has shipped.", SCHEMA) == (None, ["no JSON value found"])
