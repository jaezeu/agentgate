package grant

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

var (
	ErrExpired           = errors.New("task grant expired")
	ErrFutureIssued      = errors.New("task grant issued too far in the future")
	ErrInvalidSignature  = errors.New("task grant signature is invalid")
	ErrMissingClaim      = errors.New("task grant is missing a required claim")
	ErrMissingOnBehalfOf = errors.New("task grant is missing on_behalf_of")
	ErrReplay            = errors.New("task grant nonce was already used")
)

const defaultClockSkew = 30 * time.Second

// Signer signs canonical task-grant claims with the dispatcher's Ed25519 key.
type Signer struct {
	PrivateKey ed25519.PrivateKey
}

// Sign validates and signs a task grant. Existing signature data is ignored.
func (s Signer) Sign(taskGrant TaskGrant) (TaskGrant, error) {
	if len(s.PrivateKey) != ed25519.PrivateKeySize {
		return TaskGrant{}, errors.New("invalid Ed25519 private key")
	}
	if err := validateRequiredClaims(taskGrant); err != nil {
		return TaskGrant{}, err
	}

	payload, err := canonicalPayload(taskGrant)
	if err != nil {
		return TaskGrant{}, fmt.Errorf("canonicalize task grant: %w", err)
	}
	taskGrant.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.PrivateKey, payload))
	return taskGrant, nil
}

// Ed25519Verifier verifies signatures, time bounds, required accountability claims, and replay.
type Ed25519Verifier struct {
	PublicKey    ed25519.PublicKey
	Nonces       NonceStore
	Clock        func() time.Time
	MaxClockSkew time.Duration
}

// Verify authenticates a grant and atomically consumes its nonce.
func (v Ed25519Verifier) Verify(ctx context.Context, taskGrant TaskGrant) error {
	if len(v.PublicKey) != ed25519.PublicKeySize {
		return errors.New("invalid Ed25519 public key")
	}
	if v.Nonces == nil {
		return errors.New("nonce store is required")
	}

	signature, err := base64.RawURLEncoding.DecodeString(taskGrant.Signature)
	if err != nil {
		return fmt.Errorf("%w: malformed encoding", ErrInvalidSignature)
	}
	payload, err := canonicalPayload(taskGrant)
	if err != nil {
		return fmt.Errorf("canonicalize task grant: %w", err)
	}
	if !ed25519.Verify(v.PublicKey, payload, signature) {
		return ErrInvalidSignature
	}
	if err := validateRequiredClaims(taskGrant); err != nil {
		return err
	}

	now := time.Now().UTC()
	if v.Clock != nil {
		now = v.Clock().UTC()
	}
	clockSkew := v.MaxClockSkew
	if clockSkew == 0 {
		clockSkew = defaultClockSkew
	}
	if taskGrant.IssuedAt.After(now.Add(clockSkew)) {
		return ErrFutureIssued
	}
	if !now.Before(taskGrant.ExpiresAt()) {
		return ErrExpired
	}

	used, err := v.Nonces.Use(ctx, taskGrant.Nonce, now, taskGrant.ExpiresAt())
	if err != nil {
		return fmt.Errorf("consume task grant nonce: %w", err)
	}
	if !used {
		return ErrReplay
	}
	return nil
}

type canonicalGrant struct {
	RequestID   string    `json:"request_id"`
	Repo        string    `json:"repo"`
	CommitSHA   string    `json:"commit_sha"`
	Operation   Operation `json:"operation"`
	Environment string    `json:"environment"`
	VaultRole   string    `json:"vault_role"`
	TTLSeconds  int64     `json:"ttl"`
	Nonce       string    `json:"nonce"`
	IssuedAt    string    `json:"issued_at"`
	OnBehalfOf  string    `json:"on_behalf_of"`
	TicketID    string    `json:"ticket_id"`
}

func canonicalPayload(taskGrant TaskGrant) ([]byte, error) {
	return json.Marshal(canonicalGrant{
		RequestID:   taskGrant.RequestID,
		Repo:        taskGrant.Repo,
		CommitSHA:   taskGrant.CommitSHA,
		Operation:   taskGrant.Operation,
		Environment: taskGrant.Environment,
		VaultRole:   taskGrant.VaultRole,
		TTLSeconds:  taskGrant.TTLSeconds,
		Nonce:       taskGrant.Nonce,
		IssuedAt:    taskGrant.IssuedAt.UTC().Format(time.RFC3339Nano),
		OnBehalfOf:  taskGrant.OnBehalfOf,
		TicketID:    taskGrant.TicketID,
	})
}

func validateRequiredClaims(taskGrant TaskGrant) error {
	if strings.TrimSpace(taskGrant.OnBehalfOf) == "" {
		return ErrMissingOnBehalfOf
	}
	if strings.TrimSpace(taskGrant.RequestID) == "" ||
		strings.TrimSpace(taskGrant.Repo) == "" ||
		strings.TrimSpace(taskGrant.CommitSHA) == "" ||
		strings.TrimSpace(string(taskGrant.Operation)) == "" ||
		strings.TrimSpace(taskGrant.Environment) == "" ||
		strings.TrimSpace(taskGrant.VaultRole) == "" ||
		strings.TrimSpace(taskGrant.Nonce) == "" ||
		taskGrant.IssuedAt.IsZero() || taskGrant.TTLSeconds <= 0 {
		return ErrMissingClaim
	}
	return nil
}

// GenerateKeyPair creates a dispatcher Ed25519 key pair.
func GenerateKeyPair(random io.Reader) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if random == nil {
		random = rand.Reader
	}
	publicKey, privateKey, err := ed25519.GenerateKey(random)
	if err != nil {
		return nil, nil, fmt.Errorf("generate Ed25519 key: %w", err)
	}
	return publicKey, privateKey, nil
}

// MarshalPublicKeyPEM serializes an Ed25519 public key as PKIX PEM.
func MarshalPublicKeyPEM(publicKey ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// MarshalPrivateKeyPEM serializes an Ed25519 private key as PKCS#8 PEM.
func MarshalPrivateKeyPEM(privateKey ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParsePublicKeyPEM parses an Ed25519 PKIX public key.
func ParsePublicKeyPEM(data []byte) (ed25519.PublicKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || len(rest) != 0 {
		return nil, errors.New("decode public key PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("public key is not Ed25519")
	}
	return publicKey, nil
}

// ParsePrivateKeyPEM parses an Ed25519 PKCS#8 private key.
func ParsePrivateKeyPEM(data []byte) (ed25519.PrivateKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || len(rest) != 0 {
		return nil, errors.New("decode private key PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not Ed25519")
	}
	return privateKey, nil
}
