// Package policies exposes the exact formatted Rego bytes embedded by AgentGate.
package policies

import _ "embed"

//go:embed authorization.rego
var authorizationBundle string

// AuthorizationBundle returns the immutable runtime policy module.
func AuthorizationBundle() string {
	return authorizationBundle
}
