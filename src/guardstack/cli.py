"""guardstack command line: check text, verify an audit log, run the red-team suite, serve the API."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def _key() -> bytes:
    key = os.environ.get("GUARDSTACK_AUDIT_KEY", "")
    if len(key) < 16:
        sys.exit("set GUARDSTACK_AUDIT_KEY (at least 16 characters)")
    return key.encode()


def main() -> None:
    ap = argparse.ArgumentParser(prog="guardstack")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="run the input layer on a piece of text")
    c.add_argument("text")
    a = sub.add_parser("audit-verify", help="verify an audit log's HMAC chain")
    a.add_argument("path")
    r = sub.add_parser("redteam", help="run the attack and benign corpora and report detection rates")
    r.add_argument("--corpus", default="redteam")
    r.add_argument("--opa", default=os.environ.get("GUARDSTACK_OPA_URL", "http://127.0.0.1:8181"))
    r.add_argument("--config", default="guardstack.example.yml")
    r.add_argument("--markdown", help="also write the report as Markdown here")
    r.add_argument("--min-detection", type=float, default=0.0)
    r.add_argument("--max-false-positive", type=float, default=1.0)
    s = sub.add_parser("serve", help="run the HTTP API")
    s.add_argument("--config", default=os.environ.get("GUARDSTACK_CONFIG", "guardstack.yml"))
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()

    if args.cmd == "check":
        from .input.injection import InjectionDetector
        from .input.pii import redact
        v, red = InjectionDetector().check_prompt(args.text), redact(args.text)
        print(json.dumps({"action": v.action.value, "reasons": v.reasons(), "redacted": red.text}, indent=2))
        sys.exit(2 if v.blocked else 0)

    if args.cmd == "audit-verify":
        from .policy.audit import verify
        count, problems = verify(args.path, _key())
        print(f"{count} records, chain {'INTACT' if not problems else 'BROKEN'}")
        for p in problems:
            print("  " + p)
        sys.exit(1 if problems else 0)

    if args.cmd == "redteam":
        from .redteam import run
        report = run(Path(args.corpus), args.config, args.opa)
        print(report.markdown())
        if args.markdown:
            Path(args.markdown).write_text(report.markdown())
        ok = report.detection_rate >= args.min_detection and report.false_positive_rate <= args.max_false_positive
        sys.exit(0 if ok else 1)

    if args.cmd == "serve":
        import uvicorn
        import yaml

        from .config import Config
        from .metrics import Metrics
        from .model import OpenAICompatible
        from .pipeline import GuardedAgent
        from .policy.audit import AuditLog
        from .policy.opa import OPAClient
        from .server import create_app
        from .tools.approvals import ApprovalStore
        from .tools.catalog import Ledger, build_catalog
        from .tools.guard import ToolGuard
        from .tools.sandbox import DockerSandbox

        raw = yaml.safe_load(Path(args.config).read_text())
        cfg = Config.parse(raw)
        model = OpenAICompatible(os.environ["GUARDSTACK_MODEL_URL"], os.environ.get("GUARDSTACK_MODEL", "default"),
                                 os.environ.get("GUARDSTACK_MODEL_KEY", ""))
        guard = ToolGuard(build_catalog(Ledger(), raw.get("documents", []), sandbox=DockerSandbox()),
                          OPAClient(os.environ.get("GUARDSTACK_OPA_URL", cfg.opa_url)))
        agent = GuardedAgent(cfg, model, guard, ApprovalStore(cfg.approvers),
                             AuditLog(os.environ.get("GUARDSTACK_AUDIT_LOG", "audit.jsonl"), _key()), Metrics())
        uvicorn.run(create_app(agent, raw.get("callers", [])), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
