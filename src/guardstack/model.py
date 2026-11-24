"""Model clients. The pipeline needs one method: complete(messages, tools) -> reply.

A reply is {"content": str | None, "tool_calls": [{"id", "name", "arguments"}]}. Use
OpenAICompatible for any OpenAI-style endpoint (vLLM, llama.cpp, a gateway, a hosted API);
ScriptedModel replays fixed replies for tests, demos and red-team scenarios.
"""

from __future__ import annotations

import json
from collections.abc import Callable

import httpx


class OpenAICompatible:
    def __init__(self, url: str, model: str, api_key: str = "", timeout: float = 120,
                 transport: httpx.BaseTransport | None = None) -> None:
        self.url, self.model = url.rstrip("/"), model
        self.client = httpx.Client(timeout=timeout, transport=transport,
                                   headers={"Authorization": f"Bearer {api_key}"} if api_key else {})

    def complete(self, messages: list[dict], tools: list[dict]) -> dict:
        body = {"model": self.model, "messages": messages, "temperature": 0}
        if tools:
            body["tools"] = tools
        r = self.client.post(f"{self.url}/v1/chat/completions", json=body)
        r.raise_for_status()
        msg = r.json()["choices"][0]["message"]
        calls = [{"id": c["id"], "name": c["function"]["name"], "arguments": c["function"]["arguments"]}
                 for c in msg.get("tool_calls") or []]
        return {"content": msg.get("content"), "tool_calls": calls}


class ScriptedModel:
    """Returns the scripted replies in order (or computes them from the conversation)."""

    def __init__(self, replies: list[dict] | Callable[[list[dict]], dict]) -> None:
        self.replies = replies
        self.seen: list[list[dict]] = []

    def complete(self, messages: list[dict], tools: list[dict]) -> dict:
        self.seen.append(json.loads(json.dumps(messages)))
        if callable(self.replies):
            return self.replies(messages)
        reply = self.replies[min(len(self.seen) - 1, len(self.replies) - 1)]
        return {"content": reply.get("content"), "tool_calls": reply.get("tool_calls", [])}


def tool_call(name: str, call_id: str = "call_1", **arguments) -> dict:
    return {"content": None, "tool_calls": [{"id": call_id, "name": name, "arguments": json.dumps(arguments)}]}


def answer(text: str) -> dict:
    return {"content": text, "tool_calls": []}
