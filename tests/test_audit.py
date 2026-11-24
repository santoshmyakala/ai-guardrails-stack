import json

import pytest

from guardstack.policy.audit import AuditLog, verify

KEY = b"test-audit-key-0123456789abcdef"


@pytest.fixture
def log(tmp_path):
    a = AuditLog(tmp_path / "audit.jsonl", KEY)
    for i in range(5):
        a.append({"layer": "input", "check": "prompt_injection", "action": "allow", "n": i})
    return a


def lines(log):
    return log.path.read_text().splitlines()


def test_intact_chain_verifies(log):
    assert verify(log.path, KEY) == (5, [])


def test_reopening_continues_the_chain(log):
    AuditLog(log.path, KEY).append({"layer": "run", "action": "start"})
    assert verify(log.path, KEY) == (6, [])


def test_edited_record_is_detected(log):
    ls = lines(log)
    rec = json.loads(ls[2])
    rec["action"] = "block"
    ls[2] = json.dumps(rec, sort_keys=True)
    log.path.write_text("\n".join(ls) + "\n")
    count, problems = verify(log.path, KEY)
    assert problems and "line 3: MAC mismatch" in problems[0]


def test_deleted_record_is_detected(log):
    ls = lines(log)
    del ls[1]
    log.path.write_text("\n".join(ls) + "\n")
    _, problems = verify(log.path, KEY)
    assert problems and problems[0].startswith("line 2")


def test_reordered_records_are_detected(log):
    ls = lines(log)
    ls[1], ls[2] = ls[2], ls[1]
    log.path.write_text("\n".join(ls) + "\n")
    assert verify(log.path, KEY)[1]


def test_a_forger_without_the_key_cannot_rebuild_the_chain(log, tmp_path):
    forged = AuditLog(tmp_path / "forged.jsonl", b"attacker-key-0123456789abcdef")
    for i in range(5):
        forged.append({"layer": "input", "check": "prompt_injection", "action": "allow", "n": i})
    assert verify(forged.path, KEY)[1]


def test_short_keys_are_refused(tmp_path):
    with pytest.raises(ValueError):
        AuditLog(tmp_path / "a.jsonl", b"short")
