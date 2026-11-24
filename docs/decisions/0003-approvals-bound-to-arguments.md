# ADR 0003: Approvals are bound to the exact arguments

## Status
Accepted

## Context
"A human approved it" is only worth something if the human approved *this* action. Common gaps:
- the model changes the amount after approval;
- an approval is replayed;
- the requester approves their own action;
- an approval sits unused for days.

## Decision
An approval records a SHA-256 digest of the canonical JSON of the tool name and arguments. Consuming it:
- re-computes the digest and refuses on any difference;
- works once only;
- expires after a TTL (15 minutes by default);
- needs a decision from a configured approver who is not the requester.

Approvers use a separate API role. The run pauses (`awaiting_approval`) and is resumed by the client
with the approval id.

## Consequences
- An approved refund of 250.00 cannot become 2500.00, and a denied action cannot be retried with the
  same id.
- Pending approvals live in process memory. Several replicas would need a shared store, such as
  Redis or a database, behind the same `ApprovalStore` interface.
