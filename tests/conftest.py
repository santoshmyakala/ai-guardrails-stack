"""Fixtures. OPA runs for real (in Docker) with the repository's policies; tests that need Docker
are skipped when it is unavailable, and CI always has it."""

from __future__ import annotations

import shutil
import socket
import subprocess
import time
from pathlib import Path

import httpx
import pytest

from guardstack.config import Config
from guardstack.metrics import Metrics
from guardstack.pipeline import GuardedAgent
from guardstack.policy.audit import AuditLog
from guardstack.policy.opa import OPAClient
from guardstack.tools.approvals import ApprovalStore
from guardstack.tools.catalog import Ledger, build_catalog
from guardstack.tools.guard import ToolGuard

ROOT = Path(__file__).resolve().parents[1]
OPA_IMAGE = "openpolicyagent/opa:1.22.4"
AUDIT_KEY = b"test-audit-key-0123456789abcdef"
DOCS = [
    {"id": "KB-1", "text": "Refunds are issued to the original payment method within 5 business days."},
    {"id": "KB-2", "text": "Orders over 50 EUR ship free within Sweden. Delivery takes 2 to 4 days."},
    {"id": "KB-3", "text": "Support is open Monday to Friday, 08:00 to 17:00 CET."},
]


def docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


needs_docker = pytest.mark.skipif(not docker_available(), reason="Docker engine not available")


@pytest.fixture(scope="session")
def opa_url():
    if not docker_available():
        pytest.skip("Docker engine not available")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    name = f"guardstack-test-opa-{port}"
    subprocess.run(["docker", "run", "-d", "--rm", "--name", name, "-p", f"127.0.0.1:{port}:8181",
                    "-v", f"{ROOT / 'policies'}:/policies:ro", OPA_IMAGE, "run", "--server",
                    "--addr", "0.0.0.0:8181", "--ignore=*_test.rego", "/policies"], check=True, capture_output=True)
    url = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            if httpx.get(f"{url}/health?bundles", timeout=1).status_code == 200:
                break
        except httpx.HTTPError:
            pass
        time.sleep(0.1)
    yield url
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)


@pytest.fixture
def config() -> Config:
    return Config.load(ROOT / "guardstack.example.yml")


@pytest.fixture
def ledger() -> Ledger:
    return Ledger()


@pytest.fixture
def guard(opa_url, ledger) -> ToolGuard:
    return ToolGuard(build_catalog(ledger, DOCS), OPAClient(opa_url))


@pytest.fixture
def audit(tmp_path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl", AUDIT_KEY)


@pytest.fixture
def make_agent(config, guard, audit):
    def make(model, **cfg_overrides):
        for k, v in cfg_overrides.items():
            setattr(config, k, v)
        return GuardedAgent(config, model, guard, ApprovalStore(config.approvers), audit, Metrics())
    return make
