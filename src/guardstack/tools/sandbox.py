"""Sandboxed execution of model-written code in a throw-away container.

No network, read-only root filesystem, every capability dropped, no privilege escalation, an
unprivileged user, and limits on memory, CPU, processes, output size and wall time. Set
`runtime="runsc"` to run under gVisor where it is installed, for a second, user-space kernel.
"""

from __future__ import annotations

import secrets
import subprocess
from dataclasses import asdict, dataclass

MAX_OUTPUT = 64 * 1024


@dataclass
class Result:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class DockerSandbox:
    image: str = "python:3.13-slim"
    timeout: float = 10.0
    memory: str = "256m"
    cpus: str = "0.5"
    pids: int = 64
    runtime: str | None = None  # e.g. "runsc" (gVisor)
    docker: str = "docker"

    def command(self, name: str) -> list[str]:
        cmd = [self.docker, "run", "--rm", "-i", "--name", name,
               "--network", "none", "--read-only", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges", "--pids-limit", str(self.pids),
               "--memory", self.memory, "--memory-swap", self.memory, "--cpus", self.cpus,
               "--user", "65534:65534", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
               "--env", "PYTHONDONTWRITEBYTECODE=1"]
        if self.runtime:
            cmd += ["--runtime", self.runtime]
        return cmd + [self.image, "python", "-I", "-"]

    def run_python(self, code: str) -> Result:
        name = f"guardstack-sbx-{secrets.token_hex(6)}"
        try:
            p = subprocess.run(self.command(name), input=code.encode(), capture_output=True, timeout=self.timeout)
            return Result(p.returncode, p.stdout[:MAX_OUTPUT].decode(errors="replace"),
                          p.stderr[-MAX_OUTPUT:].decode(errors="replace"), False)
        except subprocess.TimeoutExpired:
            subprocess.run([self.docker, "kill", name], capture_output=True)
            return Result(-1, "", f"killed after {self.timeout}s", True)
        except FileNotFoundError:  # no container runtime on this host: fail closed, never run code locally
            return Result(-1, "", "sandbox unavailable: no container runtime", False)
