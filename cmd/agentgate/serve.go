package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	hashicorpapi "github.com/hashicorp/vault/api"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jaezeu/agentgate/internal/api"
	"github.com/jaezeu/agentgate/internal/approval"
	"github.com/jaezeu/agentgate/internal/audit"
	"github.com/jaezeu/agentgate/internal/authz"
	"github.com/jaezeu/agentgate/internal/expiry"
	"github.com/jaezeu/agentgate/internal/grant"
	"github.com/jaezeu/agentgate/internal/svid"
	"github.com/jaezeu/agentgate/internal/vaultmgr/vaultapi"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	defaultDatabaseURLEnvironment = "AGENTGATE_DATABASE_URL"
	// #nosec G101 -- this is an environment variable name, not a credential.
	defaultHumanTokenEnvironment = "AGENTGATE_POC_APPROVER_TOKEN"
	defaultWebhookURLEnvironment = "AGENTGATE_APPROVAL_WEBHOOK_URL"
)

type serveConfig struct {
	listenAddress            string
	tlsCertificatePath       string
	tlsPrivateKeyPath        string
	svidTrustBundlePath      string
	allowedTrustDomains      string
	dispatcherPublicKeyPath  string
	databaseURLEnvironment   string
	pocStaticHumanAuth       bool
	humanTokenEnvironment    string
	pocHumanSubject          string
	humanOIDCIssuer          string
	humanOIDCAudience        string
	webhookURLEnvironment    string
	publicBaseURL            string
	vaultAddress             string
	vaultNamespace           string
	vaultAuthMount           string
	vaultRolePrefix          string
	vaultPolicyPrefix        string
	vaultAWSMount            string
	vaultKubernetesMount     string
	vaultRequestTimeout      time.Duration
	vaultCACertificatePath   string
	vaultTLSServerName       string
	vaultManagementAuthMount string
	vaultManagementRole      string
	vaultManagementAudience  string
	workloadAPIAddress       string
	dashboardDirectory       string
}

type applicationResources struct {
	database         *sql.DB
	jwtSource        *workloadapi.JWTSource
	cancelBackground context.CancelFunc
	backgroundDone   chan struct{}
}

type certificateReloader struct {
	certificatePath string
	privateKeyPath  string
	mu              sync.Mutex
	certificate     *tls.Certificate
	lastWarning     time.Time
}

func runServe(arguments []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runServeContext(ctx, arguments)
}

func runServeContext(ctx context.Context, arguments []string) error {
	config, err := parseServeConfig(arguments)
	if err != nil {
		return err
	}
	startupContext, cancelStartup := context.WithTimeout(ctx, 20*time.Second)
	defer cancelStartup()

	handler, tlsConfig, resources, err := buildApplication(startupContext, ctx, config)
	if err != nil {
		closeApplicationResources(resources)
		return err
	}
	defer closeApplicationResources(resources)

	listener, err := net.Listen("tcp", config.listenAddress)
	if err != nil {
		return fmt.Errorf("listen for AgentGate API: %w", err)
	}
	defer func() { _ = listener.Close() }()
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		TLSConfig:         tlsConfig,
	}

	serverError := make(chan error, 1)
	go func() {
		slog.Info(
			"AgentGate API listening",
			"event",
			"server_listening",
			"address",
			listener.Addr().String(),
		)
		serverError <- server.ServeTLS(listener, "", "")
	}()

	select {
	case err := <-serverError:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve AgentGate API: %w", err)
		}
		return nil
	case <-ctx.Done():
		shutdownContext, cancelShutdown := context.WithTimeout(
			context.Background(),
			10*time.Second,
		)
		defer cancelShutdown()
		if err := server.Shutdown(shutdownContext); err != nil {
			return fmt.Errorf("shut down AgentGate API: %w", err)
		}
		return nil
	}
}

func parseServeConfig(arguments []string) (serveConfig, error) {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	var config serveConfig
	flags.StringVar(&config.listenAddress, "listen", ":8443", "HTTPS listener address")
	flags.StringVar(&config.tlsCertificatePath, "tls-cert", "", "AgentGate server certificate PEM")
	flags.StringVar(&config.tlsPrivateKeyPath, "tls-key", "", "AgentGate server private key PEM")
	flags.StringVar(&config.svidTrustBundlePath, "svid-trust-bundle", "", "SPIFFE X.509 trust bundle PEM, or domain=path entries when several trust domains are allowed")
	flags.StringVar(&config.allowedTrustDomains, "allowed-trust-domains", "", "comma-separated SPIFFE trust domains")
	flags.StringVar(&config.dispatcherPublicKeyPath, "dispatcher-public-key", "", "dispatcher Ed25519 public key PEM")
	flags.StringVar(
		&config.databaseURLEnvironment,
		"database-url-env",
		defaultDatabaseURLEnvironment,
		"environment variable holding the PostgreSQL URL",
	)
	flags.BoolVar(
		&config.pocStaticHumanAuth,
		"poc-static-human-auth",
		false,
		"explicitly enable the PoC-only static human bearer token",
	)
	flags.StringVar(
		&config.humanTokenEnvironment,
		"poc-human-token-env",
		defaultHumanTokenEnvironment,
		"environment variable holding the PoC-only human token",
	)
	flags.StringVar(
		&config.pocHumanSubject,
		"poc-human-subject",
		"poc-static-approver",
		"audit subject for the PoC-only human token",
	)
	flags.StringVar(&config.humanOIDCIssuer, "human-oidc-issuer", "", "human OIDC issuer URL")
	flags.StringVar(&config.humanOIDCAudience, "human-oidc-audience", "", "human OIDC audience")
	flags.StringVar(
		&config.webhookURLEnvironment,
		"webhook-url-env",
		defaultWebhookURLEnvironment,
		"environment variable holding the approval webhook URL",
	)
	flags.StringVar(&config.publicBaseURL, "public-base-url", "", "public AgentGate URL used in approval notifications")
	flags.StringVar(&config.vaultAddress, "vault-address", "", "Vault API address")
	flags.StringVar(&config.vaultNamespace, "vault-namespace", "", "Vault namespace")
	flags.StringVar(&config.vaultAuthMount, "vault-auth-mount", "jwt", "agent JWT auth mount")
	flags.StringVar(&config.vaultRolePrefix, "vault-role-prefix", "agentgate-", "request role name prefix")
	flags.StringVar(&config.vaultPolicyPrefix, "vault-policy-prefix", "agentgate-", "request policy name prefix")
	flags.StringVar(&config.vaultAWSMount, "vault-aws-mount", "aws", "Vault AWS secrets mount serving the terraform operations")
	flags.StringVar(
		&config.vaultKubernetesMount,
		"vault-kubernetes-mount",
		"",
		"optional Vault Kubernetes secrets mount enabling the kubernetes-inspect profile",
	)
	flags.DurationVar(&config.vaultRequestTimeout, "vault-request-timeout", 10*time.Second, "Vault control-plane request timeout")
	flags.StringVar(&config.vaultCACertificatePath, "vault-ca-cert", "", "Vault server CA certificate PEM")
	flags.StringVar(&config.vaultTLSServerName, "vault-tls-server-name", "", "Vault TLS server name")
	flags.StringVar(
		&config.vaultManagementAuthMount,
		"vault-management-auth-mount",
		"jwt",
		"JWT auth mount for AgentGate's own SPIFFE identity",
	)
	flags.StringVar(
		&config.vaultManagementRole,
		"vault-management-role",
		"",
		"Vault JWT role for AgentGate's own SPIFFE identity",
	)
	flags.StringVar(
		&config.vaultManagementAudience,
		"vault-management-audience",
		"vault",
		"JWT-SVID audience for AgentGate's Vault login",
	)
	flags.StringVar(
		&config.workloadAPIAddress,
		"workload-api-addr",
		"",
		"SPIFFE Workload API address; defaults to SPIFFE_ENDPOINT_SOCKET",
	)
	flags.StringVar(
		&config.dashboardDirectory,
		"dashboard-dir",
		"",
		"optional directory containing a built dashboard SPA",
	)
	if err := flags.Parse(arguments); err != nil {
		return serveConfig{}, err
	}
	if flags.NArg() != 0 {
		return serveConfig{}, errors.New("serve does not accept positional arguments")
	}
	for name, value := range map[string]string{
		"--tls-cert":              config.tlsCertificatePath,
		"--tls-key":               config.tlsPrivateKeyPath,
		"--svid-trust-bundle":     config.svidTrustBundlePath,
		"--allowed-trust-domains": config.allowedTrustDomains,
		"--dispatcher-public-key": config.dispatcherPublicKeyPath,
		"--public-base-url":       config.publicBaseURL,
		"--vault-address":         config.vaultAddress,
		"--vault-management-role": config.vaultManagementRole,
		"--database-url-env":      config.databaseURLEnvironment,
		"--webhook-url-env":       config.webhookURLEnvironment,
	} {
		if strings.TrimSpace(value) == "" {
			return serveConfig{}, fmt.Errorf("%s is required", name)
		}
	}
	if config.pocStaticHumanAuth {
		if config.humanOIDCIssuer != "" || config.humanOIDCAudience != "" {
			return serveConfig{}, errors.New("PoC static human auth and OIDC configuration are mutually exclusive")
		}
	} else if config.humanOIDCIssuer == "" || config.humanOIDCAudience == "" {
		return serveConfig{}, errors.New("human OIDC issuer and audience are required outside explicit PoC mode")
	}
	if config.vaultRequestTimeout <= 0 || config.vaultRequestTimeout > 30*time.Second {
		return serveConfig{}, errors.New("vault request timeout must be between zero and 30 seconds")
	}
	return config, nil
}

func buildApplication(
	ctx context.Context,
	lifecycleContext context.Context,
	config serveConfig,
) (http.Handler, *tls.Config, applicationResources, error) {
	var resources applicationResources
	allowedTrustDomains, err := parseTrustDomains(config.allowedTrustDomains)
	if err != nil {
		return nil, nil, resources, err
	}
	unionRoots, rootsByTrustDomain, err := loadTrustBundles(config.svidTrustBundlePath, allowedTrustDomains)
	if err != nil {
		return nil, nil, resources, err
	}
	serverTLS, err := loadServerTLS(config, unionRoots)
	if err != nil {
		return nil, nil, resources, err
	}
	publicKeyData, err := os.ReadFile(config.dispatcherPublicKeyPath) // #nosec G304 -- path is explicit startup configuration.
	if err != nil {
		return nil, nil, resources, errors.New("read dispatcher public key")
	}
	publicKey, err := grant.ParsePublicKeyPEM(publicKeyData)
	if err != nil {
		return nil, nil, resources, errors.New("parse dispatcher public key")
	}

	databaseURL, err := requiredEnvironment(config.databaseURLEnvironment)
	if err != nil {
		return nil, nil, resources, err
	}
	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, nil, resources, errors.New("initialize PostgreSQL connection")
	}
	resources.database = database
	database.SetMaxOpenConns(20)
	database.SetMaxIdleConns(5)
	database.SetConnMaxLifetime(30 * time.Minute)
	if err := verifyDatabaseSchema(ctx, database); err != nil {
		_ = database.Close()
		resources.database = nil
		return nil, nil, resources, err
	}

	requestStore := approval.NewPostgresStore(database)
	auditStore := audit.NewPostgresStore(database)
	nonceStore := grant.NewPostgresNonceStore(database)
	policyEngine, err := authz.NewEmbeddedPolicyEngine(ctx)
	if err != nil {
		return nil, nil, resources, errors.New("initialize embedded authorization policy")
	}
	humanAuthenticator, err := buildHumanAuthenticator(ctx, config)
	if err != nil {
		return nil, nil, resources, err
	}
	webhookURL, err := requiredEnvironment(config.webhookURLEnvironment)
	if err != nil {
		return nil, nil, resources, err
	}
	notifier, err := approval.NewHTTPNotifier(approval.WebhookConfig{
		URL:           webhookURL,
		PublicBaseURL: config.publicBaseURL,
		Logger:        slog.Default(),
	}, requestStore)
	if err != nil {
		return nil, nil, resources, errors.New("initialize approval webhook notifier")
	}

	jwtOptions := []workloadapi.JWTSourceOption{}
	if config.workloadAPIAddress != "" {
		jwtOptions = append(
			jwtOptions,
			workloadapi.WithClientOptions(workloadapi.WithAddr(config.workloadAPIAddress)),
		)
	}
	// The context passed to NewJWTSource only bounds the wait for the first
	// Workload API update (the watch goroutines run under their own background
	// context until Close), so the startup timeout applies here: an
	// unreachable SPIRE agent must fail startup, not hang it forever.
	jwtSource, err := workloadapi.NewJWTSource(ctx, jwtOptions...)
	if err != nil {
		return nil, nil, resources, errors.New("initialize SPIFFE JWT source")
	}
	resources.jwtSource = jwtSource
	vaultClientConfig, err := buildVaultClientConfig(config)
	if err != nil {
		return nil, nil, resources, err
	}
	vaultBaseClient, err := hashicorpapi.NewClient(vaultClientConfig)
	if err != nil {
		return nil, nil, resources, errors.New("initialize Vault API client")
	}
	vaultBaseClient.SetNamespace(config.vaultNamespace)
	secretsMounts := map[string]string{
		string(grant.OperationTerraformPlan):  config.vaultAWSMount,
		string(grant.OperationTerraformApply): config.vaultAWSMount,
	}
	if config.vaultKubernetesMount != "" {
		secretsMounts[string(grant.OperationKubernetesInspect)] = config.vaultKubernetesMount
	}
	vaultManager, err := vaultapi.New(vaultapi.Config{
		VaultAddress:   config.vaultAddress,
		Namespace:      config.vaultNamespace,
		AuthMount:      config.vaultAuthMount,
		RolePrefix:     config.vaultRolePrefix,
		PolicyPrefix:   config.vaultPolicyPrefix,
		SecretsMounts:  secretsMounts,
		RequestTimeout: config.vaultRequestTimeout,
		Clock:          func() time.Time { return time.Now().UTC() },
		ClientProvider: &spiffeVaultClientProvider{
			baseClient: vaultBaseClient,
			namespace:  config.vaultNamespace,
			authMount:  config.vaultManagementAuthMount,
			role:       config.vaultManagementRole,
			audience:   config.vaultManagementAudience,
			jwtSource:  jwtSource,
		},
		AuditStore: auditStore,
	})
	if err != nil {
		return nil, nil, resources, errors.New("initialize Vault manager")
	}

	handler, err := api.NewRouter(api.Config{
		Version: version,
		Logger:  slog.Default(),
	}, api.Dependencies{
		SVIDValidator: svid.X509Validator{
			Roots:               unionRoots,
			RootsByTrustDomain:  rootsByTrustDomain,
			AllowedTrustDomains: allowedTrustDomains,
		},
		GrantVerifier: grant.Ed25519Verifier{
			PublicKey: publicKey,
			Nonces:    nonceStore,
		},
		PolicyEngine:       policyEngine,
		VaultManager:       vaultManager,
		AuditStore:         auditStore,
		RequestStore:       requestStore,
		ApprovalNotifier:   notifier,
		HumanAuthenticator: humanAuthenticator,
		ReadinessChecks: []func(context.Context) error{
			func(readinessContext context.Context) error {
				return verifyDatabaseSchema(readinessContext, database)
			},
		},
	})
	if err != nil {
		return nil, nil, resources, errors.New("initialize AgentGate API")
	}
	handler, err = withDashboard(handler, config.dashboardDirectory)
	if err != nil {
		return nil, nil, resources, errors.New("initialize dashboard static serving")
	}
	expiryWorker, err := expiry.NewWorker(requestStore, vaultManager, slog.Default())
	if err != nil {
		return nil, nil, resources, errors.New("initialize expired binding worker")
	}
	backgroundContext, cancelBackground := context.WithCancel(lifecycleContext)
	resources.cancelBackground = cancelBackground
	resources.backgroundDone = make(chan struct{})
	go func() {
		defer close(resources.backgroundDone)
		expiryWorker.Run(backgroundContext)
	}()
	return handler, serverTLS, resources, nil
}

func closeApplicationResources(resources applicationResources) {
	if resources.cancelBackground != nil {
		resources.cancelBackground()
		<-resources.backgroundDone
	}
	if resources.jwtSource != nil {
		_ = resources.jwtSource.Close()
	}
	if resources.database != nil {
		_ = resources.database.Close()
	}
}

func loadServerTLS(config serveConfig, roots *x509.CertPool) (*tls.Config, error) {
	reloader := &certificateReloader{
		certificatePath: config.tlsCertificatePath,
		privateKeyPath:  config.tlsPrivateKeyPath,
	}
	certificate, err := reloader.load()
	if err != nil {
		return nil, errors.New("load AgentGate TLS certificate")
	}
	reloader.certificate = certificate

	return &tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: reloader.getCertificate,
		ClientAuth:     tls.RequestClientCert,
		ClientCAs:      roots,
	}, nil
}

// loadTrustBundles resolves --svid-trust-bundle into per-trust-domain root
// pools plus their union (for the TLS handshake hint list). A bare PEM path
// is only accepted with exactly one allowed trust domain: a flat pool shared
// by several domains would let any listed CA issue identities in every
// domain, so multi-domain deployments must bind each domain to its own
// bundle with domain=path entries.
func loadTrustBundles(
	raw string,
	allowedTrustDomains map[string]struct{},
) (*x509.CertPool, map[string]*x509.CertPool, error) {
	union := x509.NewCertPool()
	byTrustDomain := make(map[string]*x509.CertPool)

	if !strings.Contains(raw, "=") {
		if len(allowedTrustDomains) != 1 {
			return nil, nil, errors.New(
				"a single SPIFFE trust bundle requires exactly one allowed trust domain; use domain=path bundle entries",
			)
		}
		pool, err := appendTrustBundle(raw, union)
		if err != nil {
			return nil, nil, err
		}
		for trustDomain := range allowedTrustDomains {
			byTrustDomain[trustDomain] = pool
		}
		return union, byTrustDomain, nil
	}

	for _, entry := range strings.Split(raw, ",") {
		domainPart, path, found := strings.Cut(strings.TrimSpace(entry), "=")
		domainPart = strings.TrimSpace(domainPart)
		path = strings.TrimSpace(path)
		if !found || domainPart == "" || path == "" {
			return nil, nil, errors.New("SPIFFE trust bundle entries must be domain=path")
		}
		trustDomain, err := spiffeid.TrustDomainFromString(domainPart)
		if err != nil {
			return nil, nil, errors.New("SPIFFE trust bundle entry names an invalid trust domain")
		}
		canonical := trustDomain.String()
		if _, allowed := allowedTrustDomains[canonical]; !allowed {
			return nil, nil, errors.New("SPIFFE trust bundle entry names a trust domain that is not allowed")
		}
		if _, duplicate := byTrustDomain[canonical]; duplicate {
			return nil, nil, errors.New("SPIFFE trust bundle entries name a trust domain twice")
		}
		pool, err := appendTrustBundle(path, union)
		if err != nil {
			return nil, nil, err
		}
		byTrustDomain[canonical] = pool
	}
	for trustDomain := range allowedTrustDomains {
		if _, bound := byTrustDomain[trustDomain]; !bound {
			return nil, nil, errors.New("every allowed trust domain requires a SPIFFE trust bundle entry")
		}
	}
	return union, byTrustDomain, nil
}

func appendTrustBundle(path string, union *x509.CertPool) (*x509.CertPool, error) {
	bundle, err := os.ReadFile(path) // #nosec G304 -- path is explicit startup configuration.
	if err != nil {
		return nil, errors.New("read SPIFFE trust bundle")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(bundle) {
		return nil, errors.New("SPIFFE trust bundle contains no certificates")
	}
	union.AppendCertsFromPEM(bundle)
	return pool, nil
}

func (r *certificateReloader) load() (*tls.Certificate, error) {
	certificate, err := tls.LoadX509KeyPair(
		r.certificatePath,
		r.privateKeyPath,
	)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, err
	}
	certificate.Leaf = leaf
	return &certificate, nil
}

func (r *certificateReloader) getCertificate(
	_ *tls.ClientHelloInfo,
) (*tls.Certificate, error) {
	certificate, loadErr := r.load()
	r.mu.Lock()
	defer r.mu.Unlock()
	if loadErr == nil {
		r.certificate = certificate
		return certificate, nil
	}

	now := time.Now().UTC()
	if r.certificate == nil ||
		r.certificate.Leaf == nil ||
		!now.Before(r.certificate.Leaf.NotAfter) {
		return nil, errors.New("reload AgentGate TLS certificate")
	}
	if r.lastWarning.IsZero() || now.Sub(r.lastWarning) >= time.Minute {
		slog.Warn(
			"serving the last valid AgentGate TLS certificate after a reload failure",
			"event",
			"tls_certificate_reload_failed",
		)
		r.lastWarning = now
	}
	return r.certificate, nil
}

func parseTrustDomains(raw string) (map[string]struct{}, error) {
	trustDomains := make(map[string]struct{})
	for _, candidate := range strings.Split(raw, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			return nil, errors.New("allowed SPIFFE trust domains contain an empty value")
		}
		trustDomain, err := spiffeid.TrustDomainFromString(candidate)
		if err != nil {
			return nil, errors.New("allowed SPIFFE trust domain is invalid")
		}
		trustDomains[trustDomain.String()] = struct{}{}
	}
	if len(trustDomains) == 0 {
		return nil, errors.New("at least one SPIFFE trust domain is required")
	}
	return trustDomains, nil
}

func buildHumanAuthenticator(
	ctx context.Context,
	config serveConfig,
) (api.HumanAuthenticator, error) {
	if config.pocStaticHumanAuth {
		token, err := requiredEnvironment(config.humanTokenEnvironment)
		if err != nil {
			return nil, err
		}
		authenticator, err := api.NewPoCStaticTokenAuthenticator(
			true,
			token,
			config.pocHumanSubject,
		)
		if err != nil {
			return nil, errors.New("initialize PoC static human authentication")
		}
		return authenticator, nil
	}
	authenticator, err := api.NewOIDCAuthenticator(
		ctx,
		config.humanOIDCIssuer,
		config.humanOIDCAudience,
	)
	if err != nil {
		return nil, errors.New("initialize human OIDC authentication")
	}
	return authenticator, nil
}

func buildVaultClientConfig(config serveConfig) (*hashicorpapi.Config, error) {
	clientConfig := hashicorpapi.DefaultConfig()
	clientConfig.Address = config.vaultAddress
	clientConfig.DisableRedirects = true
	if err := clientConfig.ConfigureTLS(&hashicorpapi.TLSConfig{
		CACert:        config.vaultCACertificatePath,
		TLSServerName: config.vaultTLSServerName,
	}); err != nil {
		return nil, errors.New("configure Vault TLS")
	}
	return clientConfig, nil
}

func verifyDatabaseSchema(ctx context.Context, database *sql.DB) error {
	if database == nil {
		return errors.New("PostgreSQL connection is required")
	}
	queries := []string{
		`SELECT request_id, binding_state, grant_hash FROM access_requests LIMIT 0`,
		`SELECT request_id, state, version FROM approvals LIMIT 0`,
		`SELECT nonce, expires_at FROM consumed_grant_nonces LIMIT 0`,
		`SELECT event_id, request_id, task_grant FROM audit_events LIMIT 0`,
	}
	for _, query := range queries {
		rows, err := database.QueryContext(ctx, query)
		if err != nil {
			return errors.New("PostgreSQL schema is not ready")
		}
		if err := rows.Close(); err != nil {
			return errors.New("close PostgreSQL readiness query")
		}
	}
	var expiryMigrationReady bool
	if err := database.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM pg_constraint
			WHERE conrelid = 'access_requests'::regclass
			  AND conname = 'access_requests_binding_state_check'
			  AND position('revoking' IN pg_get_constraintdef(oid)) > 0
		)
	`).Scan(&expiryMigrationReady); err != nil || !expiryMigrationReady {
		return errors.New("PostgreSQL expiry migration is not ready")
	}
	return nil
}

func requiredEnvironment(name string) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", errors.New("runtime secret environment variable name is required")
	}
	value, exists := os.LookupEnv(name)
	if !exists || value == "" {
		return "", fmt.Errorf("required runtime environment variable %s is not set", name)
	}
	return value, nil
}
