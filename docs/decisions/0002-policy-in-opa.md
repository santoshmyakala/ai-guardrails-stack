# ADR 0002: Tool-call policy in OPA, failing closed

## Status
Accepted

## Context
Which tool an agent may call, with which arguments and when a human must approve, is business and
security policy. Risk and security teams need to read, review and test it without reading the
agent's Python. It must change without a redeploy of the agent.

## Decision
- The Python guard does the structural checks first: allowlist, scopes and a strict argument schema.
  Only well-formed calls reach the policy.
- The policy itself is Rego (`policies/tools.rego`), evaluated by an OPA server over its REST API.
  It returns `allow`, `approval` and the reasons. Any deny wins.
- If OPA is unreachable, times out or returns no decision, the call is **blocked**
  (`tool.policy_error`).
- Rego has its own unit tests (`opa test`), and CI checks formatting.

## Consequences
- Policy is reviewed like code, with 16 Rego tests, and versioned with the agent.
- OPA is one more service to run. It is small, stateless and can run as a sidecar.
- Failing closed means an OPA outage stops tool use. Answers that need no tools still work.
