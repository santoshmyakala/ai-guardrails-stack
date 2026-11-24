#!/usr/bin/env python3
"""Render compliance/controls.yaml to docs/compliance.md, and check that every cited test exists.

    python scripts/compliance.py           # write docs/compliance.md
    python scripts/compliance.py --check   # fail on missing evidence or a stale document
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
OWASP = {"LLM01": "Prompt Injection", "LLM02": "Sensitive Information Disclosure", "LLM05": "Improper Output Handling",
         "LLM06": "Excessive Agency", "LLM07": "System Prompt Leakage", "LLM09": "Misinformation"}
EU = {"Art. 9": "risk management", "Art. 10": "data governance", "Art. 11": "technical documentation",
      "Art. 12": "record-keeping", "Art. 14": "human oversight", "Art. 15": "accuracy, robustness, cybersecurity"}


def missing_evidence(controls: list[dict]) -> list[str]:
    problems = []
    for c in controls:
        for ev in c["evidence"]:
            path, _, name = ev.partition("::")
            f = ROOT / path
            if not f.exists():
                problems.append(f"{c['id']}: {path} does not exist")
                continue
            pattern = rf"^def {re.escape(name)}\(" if path.endswith(".py") else rf"^{re.escape(name)} if"
            if not re.search(pattern, f.read_text(), re.M):
                problems.append(f"{c['id']}: {name} not found in {path}")
    return problems


def render(controls: list[dict]) -> str:
    out = ["# Compliance mapping", "",
           "Generated from [`compliance/controls.yaml`](../compliance/controls.yaml) by `scripts/compliance.py`; CI fails if a",
           "cited test disappears or this file is stale. The mapping shows which control supports which requirement;",
           "it is evidence for an assessment, not a certification.", "",
           "| Control | Layer | OWASP LLM Top 10 (2025) | EU AI Act | NIST AI RMF | Proven by |",
           "|---|---|---|---|---|---|"]
    for c in controls:
        owasp = ", ".join(f"{x} {OWASP[x]}" for x in c["owasp_llm"]) or "–"
        eu = ", ".join(f"{x} ({EU[x]})" for x in c["eu_ai_act"]) or "–"
        tests = "<br>".join(f"`{e.split('::')[1]}`" for e in c["evidence"])
        note = f"<br><sub>{c['notes']}</sub>" if c.get("notes") else ""
        out.append(f"| **{c['id']}** {c['control']}{note} | {c['layer']} | {owasp} | {eu} | {', '.join(c['nist_ai_rmf'])} | {tests} |")
    out += ["", "Not mapped to an OWASP item: the topic filter, moderation, audit logging and the mapping itself support",
            "risk management and accountability rather than a specific LLM vulnerability class."]
    return "\n".join(out) + "\n"


def main() -> None:
    controls = yaml.safe_load((ROOT / "compliance/controls.yaml").read_text())
    problems = missing_evidence(controls)
    doc = ROOT / "docs/compliance.md"
    if "--check" in sys.argv:
        if not doc.exists() or doc.read_text() != render(controls):
            problems.append("docs/compliance.md is stale: run scripts/compliance.py")
        for p in problems:
            print(p)
        print(f"{len(controls)} controls, {sum(len(c['evidence']) for c in controls)} evidence links: "
              f"{'OK' if not problems else 'FAILED'}")
        sys.exit(1 if problems else 0)
    doc.write_text(render(controls))
    print(f"wrote {doc.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
