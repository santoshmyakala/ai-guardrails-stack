# Compliance mapping

Generated from [`compliance/controls.yaml`](../compliance/controls.yaml) by `scripts/compliance.py`; CI fails if a
cited test disappears or this file is stale. The mapping shows which control supports which requirement;
it is evidence for an assessment, not a certification.

| Control | Layer | OWASP LLM Top 10 (2025) | EU AI Act | NIST AI RMF | Proven by |
|---|---|---|---|---|---|
| **IN-1** Prompt injection detection | Input | LLM01 Prompt Injection | Art. 15 (accuracy, robustness, cybersecurity) | MANAGE | `test_direct_attacks_are_blocked`<br>`test_obfuscated_attacks_are_blocked`<br>`test_poisoned_documents_are_dropped_and_clean_ones_kept`<br>`test_injection_is_blocked_before_the_model_is_called` |
| **IN-2** Jailbreak detection | Input | LLM01 Prompt Injection | Art. 15 (accuracy, robustness, cybersecurity) | MANAGE | `test_direct_attacks_are_blocked`<br>`test_benign_lookalikes_are_allowed` |
| **IN-3** PII redaction<br><sub>Supports GDPR data minimisation (Art. 5(1)(c)).</sub> | Input | LLM02 Sensitive Information Disclosure | Art. 10 (data governance) | MANAGE | `test_pii_is_redacted_with_validators_and_reversible`<br>`test_lookalike_numbers_are_not_redacted`<br>`test_pii_never_reaches_the_model` |
| **IN-4** Topic and scope filter | Input | – | Art. 9 (risk management) | MAP, MANAGE | `test_topic_filter_denies_and_scopes`<br>`test_denied_topic_is_blocked` |
| **TL-1** Least-privilege access | Tool | LLM06 Excessive Agency | Art. 15 (accuracy, robustness, cybersecurity) | MANAGE | `test_unknown_and_unlisted_tools_are_blocked`<br>`test_missing_scope_is_blocked` |
| **TL-2** Argument validation | Tool | LLM05 Improper Output Handling, LLM06 Excessive Agency | Art. 15 (accuracy, robustness, cybersecurity) | MANAGE | `test_arguments_are_validated_strictly`<br>`test_cloud_metadata_ip_is_denied`<br>`test_ssrf_attempt_is_blocked_and_the_model_is_told_why` |
| **TL-3** Sandboxed execution | Tool | LLM05 Improper Output Handling, LLM06 Excessive Agency | Art. 15 (accuracy, robustness, cybersecurity) | MANAGE | `test_has_no_network`<br>`test_root_filesystem_is_read_only`<br>`test_memory_is_capped`<br>`test_runaway_code_is_killed` |
| **TL-4** Human approval | Tool | LLM06 Excessive Agency | Art. 14 (human oversight) | GOVERN, MANAGE | `test_approvals_are_bound_single_use_and_need_a_second_person`<br>`test_small_refund_runs_large_refund_waits_for_a_human`<br>`test_every_delete_needs_approval` |
| **OUT-1** Content moderation | Output | – | Art. 15 (accuracy, robustness, cybersecurity) | MEASURE, MANAGE | `test_moderation_rules`<br>`test_model_judge_is_consulted` |
| **OUT-2** Grounding check | Output | LLM09 Misinformation | Art. 15 (accuracy, robustness, cybersecurity) | MEASURE | `test_invented_number_is_caught`<br>`test_citation_that_does_not_support_the_claim_is_caught`<br>`test_hallucinated_figure_is_flagged` |
| **OUT-3** Leak prevention | Output | LLM02 Sensitive Information Disclosure, LLM07 System Prompt Leakage | Art. 15 (accuracy, robustness, cybersecurity) | MANAGE | `test_secrets_are_redacted`<br>`test_canary_in_output_blocks`<br>`test_system_prompt_leak_is_blocked` |
| **OUT-4** Format validation | Output | LLM05 Improper Output Handling | Art. 15 (accuracy, robustness, cybersecurity) | MANAGE | `test_schema_violations_are_reported_precisely`<br>`test_structured_answer_is_repaired_once` |
| **POL-1** Policy as code | Policy | LLM06 Excessive Agency | Art. 9 (risk management) | GOVERN | `test_refund_over_agent_limit_is_denied`<br>`test_unreachable_policy_fails_closed` |
| **POL-2** Audit logging | Policy | – | Art. 12 (record-keeping) | GOVERN, MEASURE | `test_edited_record_is_detected`<br>`test_a_forger_without_the_key_cannot_rebuild_the_chain`<br>`test_every_decision_is_in_a_verifiable_audit_log` |
| **POL-3** Red teaming | Policy | LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM07 System Prompt Leakage, LLM09 Misinformation | Art. 15 (accuracy, robustness, cybersecurity) | MEASURE | `test_red_team_gate` |
| **POL-4** Compliance mapping | Policy | – | Art. 11 (technical documentation) | GOVERN | `test_every_control_has_existing_evidence` |

Not mapped to an OWASP item: the topic filter, moderation, audit logging and the mapping itself support
risk management and accountability rather than a specific LLM vulnerability class.
