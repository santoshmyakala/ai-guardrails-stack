"""The sandbox for model-written code, tested against a real container engine."""

import pytest

from guardstack.tools.sandbox import DockerSandbox

from .conftest import needs_docker

pytestmark = needs_docker


@pytest.fixture(scope="module")
def sandbox():
    return DockerSandbox(timeout=20)


def test_runs_code_and_returns_output(sandbox):
    r = sandbox.run_python("print(sum(range(10)))")
    assert r.exit_code == 0 and r.stdout.strip() == "45"


def test_has_no_network(sandbox):
    r = sandbox.run_python("import socket\ns=socket.socket(); s.settimeout(3)\ns.connect(('1.1.1.1', 443))")
    assert r.exit_code != 0 and ("unreachable" in r.stderr.lower() or "error" in r.stderr.lower())


def test_root_filesystem_is_read_only(sandbox):
    r = sandbox.run_python("open('/etc/evil', 'w').write('x')")
    assert r.exit_code != 0 and "Read-only file system" in r.stderr


def test_runs_as_an_unprivileged_user(sandbox):
    r = sandbox.run_python("import os; print(os.getuid(), os.getgid())")
    assert r.stdout.strip() == "65534 65534"


def test_tmp_is_writable_but_not_executable(sandbox):
    r = sandbox.run_python(
        "import os, stat\nopen('/tmp/x.sh','w').write('#!/bin/sh\\necho hi')\n"
        "os.chmod('/tmp/x.sh', 0o755)\nimport subprocess\n"
        "try:\n    subprocess.run(['/tmp/x.sh'], check=True)\nexcept PermissionError as e:\n    print('denied')")
    assert r.stdout.strip() == "denied"


def test_memory_is_capped(sandbox):
    r = sandbox.run_python("x = bytearray(1024 * 1024 * 1024)\nprint('allocated')")
    assert "allocated" not in r.stdout and r.exit_code != 0


def test_process_count_is_capped(sandbox):
    r = sandbox.run_python(
        "import subprocess\nps=[]\ntry:\n    for i in range(200):\n        ps.append(subprocess.Popen(['sleep','5']))\n"
        "except (OSError, BlockingIOError):\n    print('limit', len(ps))\nfor p in ps: p.kill()")
    assert r.stdout.startswith("limit"), r.stdout + r.stderr


def test_runaway_code_is_killed():
    r = DockerSandbox(timeout=4).run_python("while True: pass")
    assert r.timed_out and r.exit_code == -1


def test_missing_runtime_fails_closed():
    r = DockerSandbox(docker="/nonexistent/docker").run_python("print('should never run')")
    assert r.exit_code == -1 and r.stdout == "" and "sandbox unavailable" in r.stderr
