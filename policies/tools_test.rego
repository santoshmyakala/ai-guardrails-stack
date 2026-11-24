package guardstack.tools_test

import rego.v1

import data.guardstack.tools

agent := {
	"id": "support-bot",
	"scopes": ["docs:read", "web:read", "email:send", "payments:refund", "records:delete"],
	"allowed_domains": ["example.com", "python.org"],
	"internal_domains": ["acme.example"],
	"max_refund": 500,
	"refund_approval_over": 100,
}

fetch_allowed(url) if {
	d := tools.decision with input as call("http_fetch", {"url": url})
	d.allow
}

call(name, args) := {"agent": agent, "tool": {"name": name, "external": name in {"http_fetch", "send_email"}}, "args": args, "context": {}}

test_https_to_allowed_domain_is_allowed if {
	d := tools.decision with input as call("http_fetch", {"url": "https://docs.python.org/3/library/re.html"})
	d.allow
	not d.approval
}

test_plain_http_is_denied if {
	d := tools.decision with input as call("http_fetch", {"url": "http://example.com/"})
	not d.allow
	"http_fetch: only https URLs" in d.reasons
}

test_cloud_metadata_ip_is_denied if {
	d := tools.decision with input as call("http_fetch", {"url": "https://169.254.169.254/latest/meta-data/"})
	not d.allow
	"http_fetch: 169.254.169.254 is an internal address" in d.reasons
}

test_private_and_loopback_ips_are_denied if {
	every u in ["https://10.0.0.5/admin", "https://127.0.0.1:8080/", "https://192.168.1.1/", "https://[::1]/", "https://[fd00::1]/"] {
		not fetch_allowed(u)
	}
}

test_internal_names_are_denied if {
	every u in ["https://localhost/", "https://metadata.google.internal/computeMetadata/v1/", "https://printer.local/"] {
		not fetch_allowed(u)
	}
}

test_userinfo_trick_is_denied if {
	d := tools.decision with input as call("http_fetch", {"url": "https://example.com@169.254.169.254/"})
	not d.allow
}

test_unlisted_domain_is_denied if {
	d := tools.decision with input as call("http_fetch", {"url": "https://evil.example.net/x"})
	"http_fetch: evil.example.net is not an allowed domain" in d.reasons
}

test_lookalike_domain_is_denied if {
	not fetch_allowed("https://notexample.com/")
}

test_small_refund_runs_without_approval if {
	d := tools.decision with input as call("refund_payment", {"order_id": "ORD-1234", "amount": "40.00", "currency": "EUR"})
	d.allow
	not d.approval
}

test_large_refund_needs_approval if {
	d := tools.decision with input as call("refund_payment", {"order_id": "ORD-1234", "amount": "250.00", "currency": "EUR"})
	d.allow
	d.approval
}

test_refund_over_agent_limit_is_denied if {
	d := tools.decision with input as call("refund_payment", {"order_id": "ORD-1234", "amount": "5000.00", "currency": "EUR"})
	not d.allow
}

test_every_delete_needs_approval if {
	d := tools.decision with input as call("delete_record", {"table": "tickets", "record_id": "T-1"})
	d.approval
}

test_audit_log_cannot_be_deleted if {
	d := tools.decision with input as call("delete_record", {"table": "audit_log", "record_id": "1"})
	not d.allow
}

test_internal_email_needs_no_approval if {
	d := tools.decision with input as call("send_email", {"to": ["ops@acme.example"], "subject": "s", "body": "b"})
	d.allow
	not d.approval
}

test_external_email_needs_approval if {
	d := tools.decision with input as call("send_email", {"to": ["ops@acme.example", "x@gmail.com"], "subject": "s", "body": "b"})
	d.approval
	"send_email: external recipients [\"x@gmail.com\"]" in d.reasons
}

test_redacted_pii_never_leaves if {
	d := tools.decision with input as call("send_email", {"to": ["x@gmail.com"], "subject": "s", "body": "card <CARD_1>"})
	not d.allow
}
