"""Client for Open Policy Agent's data API. The policy lives in policies/*.rego, not in Python."""

from __future__ import annotations

import httpx


class PolicyError(RuntimeError):
    pass


class OPAClient:
    def __init__(self, url: str = "http://127.0.0.1:8181", path: str = "guardstack/tools/decision",
                 timeout: float = 2.0, transport: httpx.BaseTransport | None = None) -> None:
        self.endpoint = f"{url.rstrip('/')}/v1/data/{path}"
        self.client = httpx.Client(timeout=timeout, transport=transport)

    def decide(self, payload: dict) -> dict:
        """The policy decision. Fails closed: an unreachable or undefined policy is an error."""
        try:
            r = self.client.post(self.endpoint, json={"input": payload})
            r.raise_for_status()
        except httpx.HTTPError as e:
            raise PolicyError(f"policy engine unavailable: {e}") from e
        result = r.json().get("result")
        if not isinstance(result, dict) or "allow" not in result:
            raise PolicyError("policy returned no decision (is the policy loaded?)")
        return result
