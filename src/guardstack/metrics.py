"""Prometheus metrics for guardrail decisions."""

from prometheus_client import CollectorRegistry, Counter, Histogram


class Metrics:
    def __init__(self) -> None:
        r = self.registry = CollectorRegistry()
        self.decisions = Counter("guardstack_decisions", "Guardrail decisions by layer, check and action.",
                                 ["layer", "check", "action"], registry=r)
        self.runs = Counter("guardstack_runs", "Agent runs by final status.", ["status"], registry=r)
        self.latency = Histogram("guardstack_layer_seconds", "Time spent in each guardrail layer.", ["layer"],
                                 buckets=(0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 1), registry=r)
