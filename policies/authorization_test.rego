package agentgate.authz

import rego.v1

valid_grant := {
	"request_id": "req-policy-001",
	"repo": "github.com/agentgate-sandbox/terraform-demo",
	"commit_sha": "0123456789abcdef0123456789abcdef01234567",
	"operation": "terraform-plan",
	"environment": "dev",
	"vault_role": "terraform-sandbox",
	"ttl": 600,
	"nonce": "nonce-policy-001",
	"issued_at": "2026-07-17T09:55:00Z",
	"on_behalf_of": "student@example.test",
	"ticket_id": "SANDBOX-101",
}

valid_input := {
	"request_id": "req-policy-001",
	"spiffe_id": "spiffe://sandbox.agentgate.test/ns/agentgate-sandbox/sa/terraform-runner",
	"task_grant": valid_grant,
	"requested_vault_role": "terraform-sandbox",
	"current_time": "2026-07-17T10:00:00Z",
}

evaluate(candidate) := result if {
	result := decision with input as candidate
}

with_grant(overrides) := candidate if {
	candidate := object.union(valid_input, {
		"task_grant": object.union(valid_grant, overrides),
	})
}

test_bundle_configuration_is_complete_for_startup if {
	bundle_ready
}

test_valid_plan_is_allowed_at_requested_ttl if {
	result := evaluate(valid_input)
	result == {
		"decision": "allow",
		"reason": "allow.scope_valid: workload identity and signed task scope are allowed",
		"granted_ttl_seconds": 600,
	}
}

test_positive_one_second_ttl_is_allowed_without_defaulting if {
	result := evaluate(with_grant({
		"ttl": 1,
		"issued_at": "2026-07-17T09:59:59.500Z",
	}))
	result.decision == "allow"
	result.granted_ttl_seconds == 1
}

test_fifteen_minute_boundary_is_allowed_without_clamping if {
	result := evaluate(with_grant({"ttl": 900}))
	result.decision == "allow"
	result.granted_ttl_seconds == 900
}

test_ttl_above_fifteen_minutes_is_clamped_to_fifteen_minutes if {
	result := evaluate(with_grant({"ttl": 901}))
	result.decision == "allow"
	result.granted_ttl_seconds == 900
}

test_sixty_minute_boundary_is_clamped_to_fifteen_minutes if {
	result := evaluate(with_grant({"ttl": 3600}))
	result.decision == "allow"
	result.granted_ttl_seconds == 900
}

test_ttl_above_sixty_minutes_is_denied if {
	result := evaluate(with_grant({"ttl": 3601}))
	result.decision == "deny"
	result.reason == "deny.ttl_exceeds_maximum: signed task grant ttl must not exceed 3600 seconds"
	result.granted_ttl_seconds == 0
}

test_zero_ttl_is_denied_instead_of_defaulting if {
	result := evaluate(with_grant({"ttl": 0}))
	result.decision == "deny"
	result.reason == "deny.non_positive_ttl: signed task grant ttl must be positive"
}

test_negative_ttl_is_denied if {
	result := evaluate(with_grant({"ttl": -1}))
	result.decision == "deny"
	result.reason == "deny.non_positive_ttl: signed task grant ttl must be positive"
}

test_fractional_ttl_is_denied_as_malformed_task_scope if {
	result := evaluate(with_grant({"ttl": 1.5}))
	result.decision == "deny"
	result.reason == "deny.invalid_ttl: signed task grant ttl must be a whole number of seconds"
}

test_prod_apply_requires_human_approval_after_scope_checks if {
	candidate := with_grant({
		"operation": "terraform-apply",
		"environment": "prod",
		"ttl": 1200,
	})
	result := evaluate(candidate)
	result == {
		"decision": "pending_approval",
		"reason": "pending.prod_apply: production terraform apply requires human approval",
		"granted_ttl_seconds": 900,
	}
}

test_prod_plan_does_not_require_apply_approval if {
	result := evaluate(with_grant({"environment": "prod"}))
	result.decision == "allow"
	result.granted_ttl_seconds == 600
}

test_non_prod_apply_is_allowed_after_scope_checks if {
	result := evaluate(with_grant({"operation": "terraform-apply"}))
	result.decision == "allow"
}

test_prod_apply_with_invalid_repository_is_denied_before_approval if {
	candidate := with_grant({
		"repo": "github.com/attacker/production",
		"operation": "terraform-apply",
		"environment": "prod",
	})
	result := evaluate(candidate)
	result.decision == "deny"
	result.reason == "deny.repository_not_allowed: signed task grant repository is not allowed"
}

test_prod_apply_with_role_mismatch_is_denied_before_approval if {
	candidate := with_grant({
		"operation": "terraform-apply",
		"environment": "prod",
	})
	result := evaluate(object.union(candidate, {
		"requested_vault_role": "terraform-readonly-sandbox",
	}))
	result.decision == "deny"
	result.reason == "deny.vault_role_mismatch: requested Vault role must equal the signed task grant vault_role"
}

test_same_workload_with_unallowed_signed_role_cannot_pass if {
	candidate := with_grant({"vault_role": "terraform-readonly-sandbox"})
	result := evaluate(object.union(candidate, {
		"requested_vault_role": "terraform-readonly-sandbox",
	}))
	result.decision == "deny"
	result.reason == "deny.vault_role_not_allowed_for_workload: Vault role is not allowed for the authenticated workload path"
}

test_valid_grant_used_by_wrong_workload_cannot_pass if {
	candidate := object.union(valid_input, {
		"spiffe_id": "spiffe://sandbox.agentgate.test/ns/agentgate-sandbox/sa/plan-runner",
	})
	result := evaluate(candidate)
	result.decision == "deny"
	result.reason == "deny.vault_role_not_allowed_for_workload: Vault role is not allowed for the authenticated workload path"
}

test_workload_operation_map_blocks_apply_for_plan_only_runner if {
	grant_candidate := with_grant({
		"operation": "terraform-apply",
		"vault_role": "terraform-readonly-sandbox",
	})
	candidate := object.union(grant_candidate, {
		"spiffe_id": "spiffe://sandbox.agentgate.test/ns/agentgate-sandbox/sa/plan-runner",
		"requested_vault_role": "terraform-readonly-sandbox",
	})
	result := evaluate(candidate)
	result.decision == "deny"
	result.reason == "deny.operation_not_allowed_for_workload: operation is not allowed for the authenticated workload path"
}

test_plan_only_runner_can_use_its_exact_role_for_plan if {
	grant_candidate := with_grant({"vault_role": "terraform-readonly-sandbox"})
	candidate := object.union(grant_candidate, {
		"spiffe_id": "spiffe://sandbox.agentgate.test/ns/agentgate-sandbox/sa/plan-runner",
		"requested_vault_role": "terraform-readonly-sandbox",
	})
	result := evaluate(candidate)
	result.decision == "allow"
}

test_trust_domain_alone_never_authorizes_unknown_workload_path if {
	candidate := object.union(valid_input, {
		"spiffe_id": "spiffe://sandbox.agentgate.test/ns/agentgate-sandbox/sa/unregistered-runner",
	})
	result := evaluate(candidate)
	result.decision == "deny"
	result.reason == "deny.workload_path_not_allowed: SPIFFE workload path is not configured"
}

test_allowed_workload_path_in_wrong_trust_domain_is_denied if {
	candidate := object.union(valid_input, {
		"spiffe_id": "spiffe://evil.example/ns/agentgate-sandbox/sa/terraform-runner",
	})
	result := evaluate(candidate)
	result.decision == "deny"
	result.reason == "deny.untrusted_spiffe_domain: SPIFFE trust domain is not allowed"
}

test_malformed_spiffe_uri_is_denied_before_scope_checks if {
	candidate := object.union(valid_input, {
		"spiffe_id": "sandbox.agentgate.test/ns/agentgate-sandbox/sa/terraform-runner",
	})
	result := evaluate(candidate)
	result.decision == "deny"
	result.reason == "deny.malformed_spiffe_id: authenticated spiffe_id must contain a trust domain and workload path"
}

test_missing_authenticated_spiffe_identity_is_denied if {
	result := evaluate(object.union(valid_input, {"spiffe_id": ""}))
	result.decision == "deny"
	result.reason == "deny.missing_spiffe_id: authenticated spiffe_id is required"
}

test_access_request_id_must_match_signed_request_id if {
	result := evaluate(object.union(valid_input, {"request_id": "req-tampered"}))
	result.decision == "deny"
	result.reason == "deny.request_id_mismatch: access request_id must equal the signed task grant request_id"
}

test_missing_access_request_id_is_denied if {
	result := evaluate(object.union(valid_input, {"request_id": " "}))
	result.decision == "deny"
	result.reason == "deny.missing_request_id: access request_id is required"
}

test_missing_signed_request_id_is_denied if {
	result := evaluate(with_grant({"request_id": ""}))
	result.decision == "deny"
	result.reason == "deny.missing_grant_request_id: signed task grant request_id is required"
}

test_missing_verified_task_grant_is_denied if {
	result := evaluate(object.union(valid_input, {"task_grant": null}))
	result.decision == "deny"
	result.reason == "deny.missing_task_grant: verified task_grant is required"
}

test_repository_outside_allowlist_is_denied if {
	result := evaluate(with_grant({"repo": "github.com/example/not-the-sandbox"}))
	result.decision == "deny"
	result.reason == "deny.repository_not_allowed: signed task grant repository is not allowed"
}

test_missing_repository_is_denied if {
	result := evaluate(with_grant({"repo": ""}))
	result.decision == "deny"
	result.reason == "deny.missing_repository: signed task grant repo is required"
}

test_uppercase_hexadecimal_commit_sha_is_valid if {
	result := evaluate(with_grant({
		"commit_sha": "0123456789ABCDEF0123456789ABCDEF01234567",
	}))
	result.decision == "allow"
}

test_commit_sha_with_non_hexadecimal_character_is_denied if {
	result := evaluate(with_grant({
		"commit_sha": "g123456789abcdef0123456789abcdef01234567",
	}))
	result.decision == "deny"
	result.reason == "deny.invalid_commit_sha: signed task grant commit_sha must be exactly 40 hexadecimal characters"
}

test_commit_sha_shorter_than_forty_characters_is_denied if {
	result := evaluate(with_grant({
		"commit_sha": "0123456789abcdef0123456789abcdef0123456",
	}))
	result.decision == "deny"
	result.reason == "deny.invalid_commit_sha: signed task grant commit_sha must be exactly 40 hexadecimal characters"
}

test_commit_sha_longer_than_forty_characters_is_denied if {
	result := evaluate(with_grant({
		"commit_sha": "0123456789abcdef0123456789abcdef012345678",
	}))
	result.decision == "deny"
	result.reason == "deny.invalid_commit_sha: signed task grant commit_sha must be exactly 40 hexadecimal characters"
}

test_missing_commit_sha_is_denied if {
	result := evaluate(with_grant({"commit_sha": ""}))
	result.decision == "deny"
	result.reason == "deny.missing_commit_sha: signed task grant commit_sha is required"
}

test_unsupported_operation_has_specific_denial if {
	result := evaluate(with_grant({"operation": "kubectl-apply"}))
	result.decision == "deny"
	result.reason == "deny.unsupported_operation: signed task grant operation is not supported"
}

test_missing_operation_is_denied if {
	result := evaluate(with_grant({"operation": ""}))
	result.decision == "deny"
	result.reason == "deny.missing_operation: signed task grant operation is required"
}

test_unsupported_environment_has_specific_denial if {
	result := evaluate(with_grant({"environment": "production"}))
	result.decision == "deny"
	result.reason == "deny.unsupported_environment: signed task grant environment is not supported"
}

test_missing_environment_is_denied if {
	result := evaluate(with_grant({"environment": ""}))
	result.decision == "deny"
	result.reason == "deny.missing_environment: signed task grant environment is required"
}

test_requested_vault_role_must_equal_signed_role if {
	result := evaluate(object.union(valid_input, {
		"requested_vault_role": "terraform-readonly-sandbox",
	}))
	result.decision == "deny"
	result.reason == "deny.vault_role_mismatch: requested Vault role must equal the signed task grant vault_role"
}

test_missing_signed_vault_role_is_denied if {
	result := evaluate(with_grant({"vault_role": ""}))
	result.decision == "deny"
	result.reason == "deny.missing_grant_vault_role: signed task grant vault_role is required"
}

test_missing_requested_vault_role_is_denied if {
	result := evaluate(object.union(valid_input, {"requested_vault_role": ""}))
	result.decision == "deny"
	result.reason == "deny.missing_requested_vault_role: requested_vault_role is required"
}

test_missing_nonce_is_denied_even_after_upstream_verification if {
	result := evaluate(with_grant({"nonce": ""}))
	result.decision == "deny"
	result.reason == "deny.missing_nonce: signed task grant nonce is required"
}

test_missing_issued_at_is_denied_even_after_upstream_verification if {
	result := evaluate(with_grant({"issued_at": ""}))
	result.decision == "deny"
	result.reason == "deny.missing_issued_at: signed task grant issued_at is required"
}

test_malformed_issued_at_is_denied if {
	result := evaluate(with_grant({"issued_at": "yesterday"}))
	result.decision == "deny"
	result.reason == "deny.invalid_issued_at: signed task grant issued_at must be an RFC3339 timestamp"
}

test_missing_signed_human_attribution_is_denied if {
	result := evaluate(with_grant({"on_behalf_of": " "}))
	result.decision == "deny"
	result.reason == "deny.missing_on_behalf_of: signed human attribution on_behalf_of is required"
}

test_missing_ticket_id_is_denied_even_after_upstream_verification if {
	result := evaluate(with_grant({"ticket_id": ""}))
	result.decision == "deny"
	result.reason == "deny.missing_ticket_id: signed task grant ticket_id is required"
}

test_grant_beyond_clock_skew_is_denied_as_future_issued if {
	result := evaluate(with_grant({"issued_at": "2026-07-17T10:00:31Z"}))
	result.decision == "deny"
	result.reason == "deny.grant_issued_in_future: signed task grant issued_at exceeds the allowed clock skew"
}

test_grant_at_clock_skew_boundary_is_not_denied if {
	result := evaluate(with_grant({"issued_at": "2026-07-17T10:00:30Z"}))
	result.decision == "allow"
}

test_grant_at_expiry_boundary_is_denied if {
	result := evaluate(with_grant({"issued_at": "2026-07-17T09:50:00Z"}))
	result.decision == "deny"
	result.reason == "deny.grant_expired: signed task grant has expired"
}

test_grant_just_before_expiry_remains_eligible if {
	candidate := object.union(valid_input, {
		"current_time": "2026-07-17T10:04:59Z",
	})
	result := evaluate(candidate)
	result.decision == "allow"
}

test_malformed_trusted_current_time_hits_distinct_default_deny if {
	result := evaluate(object.union(valid_input, {"current_time": "not-a-time"}))
	result.decision == "deny"
	result.reason == "deny.default: no authorization rule matched the request"
	result.granted_ttl_seconds == 0
}

test_non_object_input_fails_closed_with_specific_reason if {
	result := evaluate("not-an-object")
	result.decision == "deny"
	result.reason == "deny.invalid_input: policy input must be an object"
}
