# Tool-call policy. Input (built by guardstack.tools.guard):
#   agent:   {id, scopes[], allowed_domains[], internal_domains[], max_refund, refund_approval_over}
#   tool:    {name, side_effect, external, sandboxed}
#   args:    the validated arguments
#   context: {user, redacted_pii[]}
# Decision: {allow, approval, reasons[]}. Any deny wins; otherwise approval if any rule asks for it.
package guardstack.tools

import rego.v1

default decision := {"allow": false, "approval": false, "reasons": ["no decision"]}

decision := {"allow": false, "approval": false, "reasons": sort(deny)} if count(deny) > 0

decision := {"allow": true, "approval": true, "reasons": sort(needs_approval)} if {
	count(deny) == 0
	count(needs_approval) > 0
}

decision := {"allow": true, "approval": false, "reasons": []} if {
	count(deny) == 0
	count(needs_approval) == 0
}

# ------------------------------------------------------------------ http_fetch: no SSRF
private_ranges := ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10", "0.0.0.0/8"]

url_parts := parts if {
	input.tool.name == "http_fetch"
	parts := regex.find_all_string_submatch_n(`^([a-zA-Z][a-zA-Z0-9+.-]*)://(?:[^@/]*@)?(\[[^\]]+\]|[^:/?#]+)`, input.args.url, 1)[0]
}

host := lower(trim(url_parts[2], "[]"))

deny contains "http_fetch: only https URLs" if {
	input.tool.name == "http_fetch"
	lower(url_parts[1]) != "https"
}

deny contains "http_fetch: URL has no host" if {
	input.tool.name == "http_fetch"
	not url_parts
}

deny contains "http_fetch: credentials in URL" if {
	input.tool.name == "http_fetch"
	regex.match(`^[a-zA-Z][a-zA-Z0-9+.-]*://[^/]*@`, input.args.url)
}

deny contains sprintf("http_fetch: %s is an internal address", [host]) if {
	input.tool.name == "http_fetch"
	regex.match(`^[0-9.]+$`, host)
	some cidr in private_ranges
	net.cidr_contains(cidr, host)
}

deny contains sprintf("http_fetch: %s is an internal address", [host]) if {
	input.tool.name == "http_fetch"
	contains(host, ":") # IPv6 literal: loopback, link-local, unique-local
	regex.match(`^(::1|::|fe[89ab][0-9a-f]:.*|f[cd][0-9a-f]{2}:.*|::ffff:.*)$`, host)
}

deny contains sprintf("http_fetch: %s is an internal name", [host]) if {
	input.tool.name == "http_fetch"
	internal_name(host)
}

internal_name(h) if h == "localhost"

internal_name(h) if endswith(h, ".localhost")

internal_name(h) if endswith(h, ".internal")

internal_name(h) if endswith(h, ".local")

internal_name(h) if h == "metadata.google.internal"

deny contains sprintf("http_fetch: %s is not an allowed domain", [host]) if {
	input.tool.name == "http_fetch"
	url_parts
	count(input.agent.allowed_domains) > 0
	not domain_allowed(host)
}

domain_allowed(h) if {
	some d in input.agent.allowed_domains
	h == d
}

domain_allowed(h) if {
	some d in input.agent.allowed_domains
	endswith(h, concat("", [".", d]))
}

# ------------------------------------------------------------------ refunds
deny contains sprintf("refund_payment: %v exceeds this agent's limit of %v", [input.args.amount, input.agent.max_refund]) if {
	input.tool.name == "refund_payment"
	to_number(input.args.amount) > input.agent.max_refund
}

needs_approval contains sprintf("refund_payment: amounts over %v need a human", [input.agent.refund_approval_over]) if {
	input.tool.name == "refund_payment"
	to_number(input.args.amount) > input.agent.refund_approval_over
}

# ------------------------------------------------------------------ deletes
deny contains "delete_record: the audit log is append-only" if {
	input.tool.name == "delete_record"
	input.args.table == "audit_log"
}

needs_approval contains "delete_record: deletions need a human" if {
	input.tool.name == "delete_record"
}

# ------------------------------------------------------------------ email
external_recipients contains r if {
	input.tool.name == "send_email"
	some r in input.args.to
	domain := lower(split(r, "@")[1])
	not domain in {d | some d in input.agent.internal_domains}
}

needs_approval contains sprintf("send_email: external recipients %v", [sort(external_recipients)]) if {
	count(external_recipients) > 0
}

# ------------------------------------------------------------------ data protection
# Never let redacted personal data (placeholders such as <CARD_1>) leave the organisation.
deny contains sprintf("%s: would send redacted personal data outside", [input.tool.name]) if {
	input.tool.external
	some field in object.keys(input.args)
	value := sprintf("%v", [input.args[field]])
	regex.match(`<(EMAIL|CARD|IBAN|PERSONNUMMER|SSN|PHONE|IPV4)_[0-9]+>`, value)
}
