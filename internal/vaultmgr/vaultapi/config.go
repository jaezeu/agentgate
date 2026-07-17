package vaultapi

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	hashicorpapi "github.com/hashicorp/vault/api"
	"github.com/jaezeu/agentgate/internal/audit"
)

const (
	maxVaultNameLength = 128
	maxRequestTimeout  = 30 * time.Second
)

var vaultNamePartPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

// ClientProvider returns an independently owned Vault API client authorized as
// AgentGate's control-plane identity. Implementations may mint a fresh,
// short-lived token from AgentGate's SPIFFE identity.
type ClientProvider interface {
	Client(context.Context) (*hashicorpapi.Client, error)
}

// ClientProviderFunc adapts a function to ClientProvider.
type ClientProviderFunc func(context.Context) (*hashicorpapi.Client, error)

func (f ClientProviderFunc) Client(ctx context.Context) (*hashicorpapi.Client, error) {
	return f(ctx)
}

// Config contains all Vault manager dependencies and path boundaries.
type Config struct {
	VaultAddress   string
	Namespace      string
	AuthMount      string
	RolePrefix     string
	PolicyPrefix   string
	AWSMount       string
	RequestTimeout time.Duration
	Clock          func() time.Time
	ClientProvider ClientProvider
	AuditStore     audit.AuditStore
}

// New constructs a credential-blind Vault control-plane manager.
func New(config Config) (*Manager, error) {
	address, err := canonicalVaultAddress(config.VaultAddress)
	if err != nil {
		return nil, fieldError(ErrInvalidConfiguration, "vault_address", err.Error())
	}
	namespace, err := canonicalOptionalVaultPath(config.Namespace)
	if err != nil || namespace != config.Namespace {
		return nil, fieldError(ErrInvalidConfiguration, "namespace", "must be a canonical Vault namespace path")
	}
	authMount, err := canonicalVaultPath(config.AuthMount)
	if err != nil || authMount != config.AuthMount {
		return nil, fieldError(ErrInvalidConfiguration, "auth_mount", "must be a canonical Vault mount path")
	}
	awsMount, err := canonicalVaultPath(config.AWSMount)
	if err != nil || awsMount != config.AWSMount {
		return nil, fieldError(ErrInvalidConfiguration, "aws_mount", "must be a canonical Vault mount path")
	}
	if err := validateNamePrefix(config.RolePrefix); err != nil {
		return nil, fieldError(ErrInvalidConfiguration, "role_prefix", err.Error())
	}
	if err := validateNamePrefix(config.PolicyPrefix); err != nil {
		return nil, fieldError(ErrInvalidConfiguration, "policy_prefix", err.Error())
	}
	if config.RequestTimeout <= 0 || config.RequestTimeout > maxRequestTimeout {
		return nil, fieldError(
			ErrInvalidConfiguration,
			"request_timeout",
			"must be greater than zero and no more than 30 seconds",
		)
	}
	if config.Clock == nil {
		return nil, fieldError(ErrInvalidConfiguration, "clock", "is required")
	}
	if config.ClientProvider == nil {
		return nil, fieldError(ErrInvalidConfiguration, "client_provider", "is required")
	}
	if config.AuditStore == nil {
		return nil, fieldError(ErrInvalidConfiguration, "audit_store", "is required")
	}

	return &Manager{
		address:        address,
		namespace:      namespace,
		authMount:      authMount,
		rolePrefix:     config.RolePrefix,
		policyPrefix:   config.PolicyPrefix,
		awsMount:       awsMount,
		requestTimeout: config.RequestTimeout,
		clock:          config.Clock,
		clientProvider: config.ClientProvider,
		auditStore:     config.AuditStore,
		operationLock:  make(chan struct{}, 1),
	}, nil
}

func canonicalVaultAddress(rawAddress string) (string, error) {
	if rawAddress == "" || strings.TrimSpace(rawAddress) != rawAddress {
		return "", fmt.Errorf("must be a non-empty URL without surrounding whitespace")
	}
	parsed, err := url.ParseRequestURI(rawAddress)
	if err != nil {
		return "", fmt.Errorf("must be a valid URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("scheme must be http or https")
	}
	if parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("must contain only scheme and authority")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", fmt.Errorf("must not contain a path")
	}
	parsed.Path = ""
	return parsed.String(), nil
}

func canonicalVaultPath(rawPath string) (string, error) {
	if rawPath == "" || strings.TrimSpace(rawPath) != rawPath {
		return "", fmt.Errorf("must be non-empty without surrounding whitespace")
	}
	if strings.Contains(rawPath, `\`) {
		return "", fmt.Errorf("must not contain backslashes")
	}
	canonical := strings.Trim(rawPath, "/")
	if canonical == "" {
		return "", fmt.Errorf("must contain at least one segment")
	}
	for _, segment := range strings.Split(canonical, "/") {
		if segment == "." || segment == ".." || !vaultNamePartPattern.MatchString(segment) {
			return "", fmt.Errorf("contains an unsafe path segment")
		}
	}
	return canonical, nil
}

func canonicalOptionalVaultPath(rawPath string) (string, error) {
	if rawPath == "" {
		return "", nil
	}
	return canonicalVaultPath(rawPath)
}

func validateNamePrefix(prefix string) error {
	if prefix == "" {
		return fmt.Errorf("must be non-empty")
	}
	if len(prefix) >= maxVaultNameLength {
		return fmt.Errorf("is too long")
	}
	if !vaultNamePartPattern.MatchString(prefix) {
		return fmt.Errorf("must contain only letters, digits, hyphens, and underscores")
	}
	return nil
}

func fieldError(kind error, field, reason string) *FieldError {
	return &FieldError{Kind: kind, Field: field, Reason: reason}
}
