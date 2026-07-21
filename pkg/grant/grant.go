// Package grant is the public dispatcher SDK for AgentGate task grants.
//
// A trusted dispatcher is external infrastructure: it authenticates a human
// or CI context, constructs credential-free task claims, and signs them with
// its Ed25519 key. This package re-exports the canonical grant contract so an
// external dispatcher produces bytes that AgentGate's embedded verifier
// accepts, without duplicating the canonical signing implementation.
//
// Everything here is an alias for the internal implementation; there is one
// canonical payload definition and one signature algorithm.
package grant

import (
	"github.com/jaezeu/agentgate/internal/grant"
)

// Operation is an autonomous action authorized by a dispatcher.
type Operation = grant.Operation

// Canonical operations understood by AgentGate policy.
const (
	OperationTerraformPlan     = grant.OperationTerraformPlan
	OperationTerraformApply    = grant.OperationTerraformApply
	OperationKubernetesInspect = grant.OperationKubernetesInspect
)

// TaskGrant is dispatcher-signed task context. TTL is encoded in seconds.
type TaskGrant = grant.TaskGrant

// Signer signs canonical task-grant claims with the dispatcher's Ed25519 key.
type Signer = grant.Signer

// Ed25519Verifier verifies signatures, time bounds, required claims, and replay.
type Ed25519Verifier = grant.Ed25519Verifier

// NonceStore atomically consumes a nonce until its grant expires.
type NonceStore = grant.NonceStore

// MemoryNonceStore is a single-process NonceStore for tests and simulations.
type MemoryNonceStore = grant.MemoryNonceStore

// Verification errors surfaced to dispatcher integrations.
var (
	ErrExpired          = grant.ErrExpired
	ErrFutureIssued     = grant.ErrFutureIssued
	ErrInvalidSignature = grant.ErrInvalidSignature
	ErrMissingClaim     = grant.ErrMissingClaim
	ErrReplay           = grant.ErrReplay
)

// NewMemoryNonceStore builds an empty in-memory nonce store.
func NewMemoryNonceStore() *MemoryNonceStore { return grant.NewMemoryNonceStore() }

// GenerateKeyPair creates a dispatcher Ed25519 key pair.
var GenerateKeyPair = grant.GenerateKeyPair

// MarshalPublicKeyPEM encodes a dispatcher public key as PEM.
var MarshalPublicKeyPEM = grant.MarshalPublicKeyPEM

// MarshalPrivateKeyPEM encodes a dispatcher private key as PEM.
var MarshalPrivateKeyPEM = grant.MarshalPrivateKeyPEM

// ParsePublicKeyPEM decodes a dispatcher public key from PEM.
var ParsePublicKeyPEM = grant.ParsePublicKeyPEM

// ParsePrivateKeyPEM decodes a dispatcher private key from PEM.
var ParsePrivateKeyPEM = grant.ParsePrivateKeyPEM
