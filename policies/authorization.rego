package agentgate.authz

import rego.v1

# These values are intentionally limited to a teaching sandbox. A deployment
# changes this policy data, formats the module, and receives a new policy hash.
config := {
	"trust_domains": ["sandbox.agentgate.test"],
	"repositories": ["github.com/agentgate-sandbox/terraform-demo"],
	"environments": ["dev", "staging", "prod"],
	"operations": ["terraform-plan", "terraform-apply"],
	"max_clock_skew_seconds": 30,
	"workloads": {
		"/ns/agentgate-sandbox/sa/terraform-runner": {
			"operations": ["terraform-plan", "terraform-apply"],
			"vault_roles": ["terraform-sandbox"],
		},
		"/ns/agentgate-sandbox/sa/plan-runner": {
			"operations": ["terraform-plan"],
			"vault_roles": ["terraform-readonly-sandbox"],
		},
	},
}

default decision := {
	"decision": "deny",
	"reason": "deny.default: no authorization rule matched the request",
	"granted_ttl_seconds": 0,
}

# The ordered chain gives one deterministic reason when an input violates more
# than one rule. Identity checks precede signed task-scope checks.
decision := deny_decision("deny.invalid_input: policy input must be an object") if {
	not is_object(input)
} else := deny_decision("deny.missing_request_id: access request_id is required") if {
	not nonempty_string(input.request_id)
} else := deny_decision("deny.missing_spiffe_id: authenticated spiffe_id is required") if {
	not nonempty_string(input.spiffe_id)
} else := deny_decision("deny.malformed_spiffe_id: authenticated spiffe_id must contain a trust domain and workload path") if {
	not valid_spiffe_id(input.spiffe_id)
} else := deny_decision("deny.untrusted_spiffe_domain: SPIFFE trust domain is not allowed") if {
	not trust_domain_allowed(spiffe_trust_domain(input.spiffe_id))
} else := deny_decision("deny.workload_path_not_allowed: SPIFFE workload path is not configured") if {
	not workload_configured(spiffe_workload_path(input.spiffe_id))
} else := deny_decision("deny.missing_task_grant: verified task_grant is required") if {
	not is_object(input.task_grant)
} else := deny_decision("deny.missing_grant_request_id: signed task grant request_id is required") if {
	not nonempty_string(input.task_grant.request_id)
} else := deny_decision("deny.request_id_mismatch: access request_id must equal the signed task grant request_id") if {
	input.request_id != input.task_grant.request_id
} else := deny_decision("deny.missing_repository: signed task grant repo is required") if {
	not nonempty_string(input.task_grant.repo)
} else := deny_decision("deny.repository_not_allowed: signed task grant repository is not allowed") if {
	not repository_allowed(input.task_grant.repo)
} else := deny_decision("deny.missing_commit_sha: signed task grant commit_sha is required") if {
	not nonempty_string(input.task_grant.commit_sha)
} else := deny_decision("deny.invalid_commit_sha: signed task grant commit_sha must be exactly 40 hexadecimal characters") if {
	not valid_commit_sha(input.task_grant.commit_sha)
} else := deny_decision("deny.missing_operation: signed task grant operation is required") if {
	not nonempty_string(input.task_grant.operation)
} else := deny_decision("deny.unsupported_operation: signed task grant operation is not supported") if {
	not operation_supported(input.task_grant.operation)
} else := deny_decision("deny.operation_not_allowed_for_workload: operation is not allowed for the authenticated workload path") if {
	not operation_allowed_for_workload(
		spiffe_workload_path(input.spiffe_id),
		input.task_grant.operation,
	)
} else := deny_decision("deny.missing_environment: signed task grant environment is required") if {
	not nonempty_string(input.task_grant.environment)
} else := deny_decision("deny.unsupported_environment: signed task grant environment is not supported") if {
	not environment_supported(input.task_grant.environment)
} else := deny_decision("deny.missing_grant_vault_role: signed task grant vault_role is required") if {
	not nonempty_string(input.task_grant.vault_role)
} else := deny_decision("deny.missing_requested_vault_role: requested_vault_role is required") if {
	not nonempty_string(input.requested_vault_role)
} else := deny_decision("deny.vault_role_mismatch: requested Vault role must equal the signed task grant vault_role") if {
	input.requested_vault_role != input.task_grant.vault_role
} else := deny_decision("deny.vault_role_not_allowed_for_workload: Vault role is not allowed for the authenticated workload path") if {
	not vault_role_allowed_for_workload(
		spiffe_workload_path(input.spiffe_id),
		input.requested_vault_role,
	)
} else := deny_decision("deny.invalid_ttl: signed task grant ttl must be a whole number of seconds") if {
	not whole_number(input.task_grant.ttl)
} else := deny_decision("deny.non_positive_ttl: signed task grant ttl must be positive") if {
	input.task_grant.ttl <= 0
} else := deny_decision("deny.ttl_exceeds_maximum: signed task grant ttl must not exceed 3600 seconds") if {
	input.task_grant.ttl > 3600
} else := deny_decision("deny.missing_nonce: signed task grant nonce is required") if {
	not nonempty_string(input.task_grant.nonce)
} else := deny_decision("deny.missing_issued_at: signed task grant issued_at is required") if {
	not nonempty_string(input.task_grant.issued_at)
} else := deny_decision("deny.invalid_issued_at: signed task grant issued_at must be an RFC3339 timestamp") if {
	not valid_timestamp(input.task_grant.issued_at)
} else := deny_decision("deny.missing_on_behalf_of: signed human attribution on_behalf_of is required") if {
	not nonempty_string(input.task_grant.on_behalf_of)
} else := deny_decision("deny.missing_ticket_id: signed task grant ticket_id is required") if {
	not nonempty_string(input.task_grant.ticket_id)
} else := deny_decision("deny.grant_issued_in_future: signed task grant issued_at exceeds the allowed clock skew") if {
	valid_timestamp(input.current_time)
	grant_issued_too_far_in_future
} else := deny_decision("deny.grant_expired: signed task grant has expired") if {
	valid_timestamp(input.current_time)
	grant_expired
} else := pending_decision(
	"pending.prod_apply: production terraform apply requires human approval",
	granted_ttl_seconds,
) if {
	valid_timestamp(input.current_time)
	input.task_grant.operation == "terraform-apply"
	input.task_grant.environment == "prod"
} else := allow_decision(
	"allow.scope_valid: workload identity and signed task scope are allowed",
	granted_ttl_seconds,
) if {
	valid_timestamp(input.current_time)
}

# bundle_ready is queried during engine construction. Missing or structurally
# incomplete configuration prevents the prepared policy from being installed.
bundle_ready if {
	is_array(config.trust_domains)
	count(config.trust_domains) > 0
	every trust_domain in config.trust_domains {
		nonempty_string(trust_domain)
	}

	is_array(config.repositories)
	count(config.repositories) > 0
	every repository in config.repositories {
		nonempty_string(repository)
	}

	is_array(config.environments)
	count(config.environments) > 0
	every environment in config.environments {
		nonempty_string(environment)
	}

	is_array(config.operations)
	count(config.operations) > 0
	every operation in config.operations {
		nonempty_string(operation)
	}

	is_number(config.max_clock_skew_seconds)
	config.max_clock_skew_seconds >= 0

	is_object(config.workloads)
	count(config.workloads) > 0
	every path, workload in config.workloads {
		startswith(path, "/")
		is_object(workload)
		is_array(workload.operations)
		count(workload.operations) > 0
		every operation in workload.operations {
			operation in config.operations
		}
		is_array(workload.vault_roles)
		count(workload.vault_roles) > 0
		every vault_role in workload.vault_roles {
			nonempty_string(vault_role)
		}
	}
}

granted_ttl_seconds := input.task_grant.ttl if {
	input.task_grant.ttl <= 900
} else := 900

grant_issued_too_far_in_future if {
	issued_at := time.parse_rfc3339_ns(input.task_grant.issued_at)
	current_time := time.parse_rfc3339_ns(input.current_time)
	allowed_skew := config.max_clock_skew_seconds * 1000000000
	issued_at > current_time + allowed_skew
}

grant_expired if {
	issued_at := time.parse_rfc3339_ns(input.task_grant.issued_at)
	current_time := time.parse_rfc3339_ns(input.current_time)
	expires_at := issued_at + (input.task_grant.ttl * 1000000000)
	current_time >= expires_at
}

valid_spiffe_id(spiffe_id) if {
	is_string(spiffe_id)
	regex.match(`^spiffe://[^/?#]+/[^?#]+$`, spiffe_id)
	parts := split(spiffe_id, "/")
	count(parts) >= 4
	every path_segment in array.slice(parts, 3, count(parts)) {
		path_segment != ""
	}
}

spiffe_trust_domain(spiffe_id) := trust_domain if {
	valid_spiffe_id(spiffe_id)
	trust_domain := split(spiffe_id, "/")[2]
}

spiffe_workload_path(spiffe_id) := path if {
	valid_spiffe_id(spiffe_id)
	prefix := sprintf("spiffe://%s", [spiffe_trust_domain(spiffe_id)])
	path := trim_prefix(spiffe_id, prefix)
}

trust_domain_allowed(trust_domain) if {
	trust_domain in config.trust_domains
}

workload_configured(path) if {
	is_object(config.workloads[path])
}

repository_allowed(repository) if {
	repository in config.repositories
}

operation_supported(operation) if {
	operation in config.operations
}

operation_allowed_for_workload(path, operation) if {
	operation in config.workloads[path].operations
}

environment_supported(environment) if {
	environment in config.environments
}

vault_role_allowed_for_workload(path, vault_role) if {
	vault_role in config.workloads[path].vault_roles
}

valid_commit_sha(commit_sha) if {
	is_string(commit_sha)
	regex.match(`^[0-9a-fA-F]{40}$`, commit_sha)
}

valid_timestamp(timestamp) if {
	is_string(timestamp)
	_ := time.parse_rfc3339_ns(timestamp)
}

whole_number(value) if {
	is_number(value)
	floor(value) == value
}

nonempty_string(value) if {
	is_string(value)
	trim_space(value) != ""
}

deny_decision(reason) := {
	"decision": "deny",
	"reason": reason,
	"granted_ttl_seconds": 0,
}

allow_decision(reason, ttl) := {
	"decision": "allow",
	"reason": reason,
	"granted_ttl_seconds": ttl,
}

pending_decision(reason, ttl) := {
	"decision": "pending_approval",
	"reason": reason,
	"granted_ttl_seconds": ttl,
}
