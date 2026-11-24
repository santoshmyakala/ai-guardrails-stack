# ADR 0004: A tamper-evident audit log without prompt content

## Status
Accepted

## Context
Every guardrail decision should be traceable for incident review and for record-keeping duties
(EU AI Act Art. 12). Logs are also a privacy risk if they store prompts, and they are only evidence
if an edit can be detected.

## Decision
- Each record is a JSON line with a sequence number and the previous record's MAC.
- It is authenticated with HMAC-SHA256 under a key kept outside the log.
- Prompts are stored only as SHA-256 digests; findings carry rule names, not matched text.
- `guardstack audit-verify` checks the whole chain.

## Consequences
- An edited, deleted, reordered or inserted record is detected. Without the key, a forger cannot
  rebuild the chain.
- Truncating the newest records is only detectable against an external copy of the last MAC. For
  that, ship the log to append-only storage such as object lock or a SIEM.
- Investigations see *what was decided and why*, not what the user wrote. That is deliberate.
