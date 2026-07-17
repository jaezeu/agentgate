package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jaezeu/agentgate/internal/approval"
	"github.com/jaezeu/agentgate/internal/authz"
	"github.com/jaezeu/agentgate/internal/grant"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	defaultRunTimeout   = 14 * time.Minute
	defaultPollInterval = 2 * time.Second
)

type commandConfig struct {
	agentGateURL      string
	agentGateID       spiffeid.ID
	grantFile         string
	requestedRole     string
	workloadAPIAddr   string
	vaultTLSServer    string
	runTimeout        time.Duration
	pollInterval      time.Duration
	terraformBinary   string
	terraformWorkRoot string
	awsRegion         string
	demoBucket        string
	demoPrefix        string
}

type runResult struct {
	RequestID          string                 `json:"request_id"`
	SPIFFEID           string                 `json:"spiffe_id"`
	Decision           authz.DecisionKind     `json:"decision"`
	ApprovalState      approval.ApprovalState `json:"approval_state"`
	BindingState       approval.BindingState  `json:"binding_state"`
	VaultAuthRole      string                 `json:"vault_auth_role"`
	AWSRoleSessionName string                 `json:"aws_role_session_name"`
	Terraform          terraformResult        `json:"terraform"`
}

func main() {
	if err := runMain(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		_, _ = fmt.Fprintf(os.Stderr, "agent-sim: %s\n", err)
		os.Exit(1)
	}
}

func runMain(arguments []string, stdout, stderr io.Writer) error {
	config, err := parseFlags(arguments, stderr)
	if err != nil {
		return err
	}

	signalContext, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()
	ctx, cancel := context.WithTimeout(signalContext, config.runTimeout)
	defer cancel()

	result, err := runAgent(ctx, config, stderr)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(result); err != nil {
		return errors.New("encode credential-free agent result")
	}
	return nil
}

func parseFlags(arguments []string, stderr io.Writer) (commandConfig, error) {
	flags := flag.NewFlagSet("agent-sim", flag.ContinueOnError)
	flags.SetOutput(stderr)

	agentGateURL := flags.String(
		"agentgate-url",
		"https://agentgate.agentgate.svc.cluster.local:8443/v1/access-requests",
		"AgentGate workload access endpoint",
	)
	grantFile := flags.String("grant-file", "", "path to the signed task grant JSON")
	requestedRole := flags.String(
		"vault-role",
		"",
		"optional assertion that must equal the Vault role in the signed grant",
	)
	agentGateID := flags.String(
		"agentgate-id",
		"spiffe://sandbox.agentgate.test/ns/agentgate/sa/agentgate",
		"expected AgentGate SPIFFE ID",
	)
	workloadAPIAddress := flags.String(
		"workload-api-addr",
		"",
		"SPIFFE Workload API address; defaults to SPIFFE_ENDPOINT_SOCKET",
	)
	vaultTLSServer := flags.String(
		"vault-tls-server-name",
		"",
		"optional Vault TLS DNS name override",
	)
	runTimeout := flags.Duration("timeout", defaultRunTimeout, "overall request and plan timeout")
	pollInterval := flags.Duration(
		"approval-poll-interval",
		defaultPollInterval,
		"pending approval poll interval",
	)
	terraformBinary := flags.String("terraform-bin", "terraform", "Terraform executable")
	terraformWorkRoot := flags.String(
		"terraform-work-root",
		"",
		"parent directory for the ephemeral Terraform working directory",
	)
	awsRegion := flags.String("aws-region", "", "AWS region for the governed demo target")
	demoBucket := flags.String("demo-bucket", "", "governed demo S3 bucket")
	demoPrefix := flags.String("demo-prefix", "", "governed demo S3 key prefix")

	if err := flags.Parse(arguments); err != nil {
		return commandConfig{}, err
	}
	if flags.NArg() != 0 {
		return commandConfig{}, errors.New("positional arguments are not supported")
	}
	id, err := spiffeid.FromString(strings.TrimSpace(*agentGateID))
	if err != nil {
		return commandConfig{}, errors.New("agentgate-id must be a valid SPIFFE ID")
	}
	config := commandConfig{
		agentGateURL:      strings.TrimSpace(*agentGateURL),
		agentGateID:       id,
		grantFile:         strings.TrimSpace(*grantFile),
		requestedRole:     strings.TrimSpace(*requestedRole),
		workloadAPIAddr:   strings.TrimSpace(*workloadAPIAddress),
		vaultTLSServer:    strings.TrimSpace(*vaultTLSServer),
		runTimeout:        *runTimeout,
		pollInterval:      *pollInterval,
		terraformBinary:   strings.TrimSpace(*terraformBinary),
		terraformWorkRoot: strings.TrimSpace(*terraformWorkRoot),
		awsRegion:         strings.TrimSpace(*awsRegion),
		demoBucket:        strings.TrimSpace(*demoBucket),
		demoPrefix:        strings.TrimSpace(*demoPrefix),
	}
	if err := validateCommandConfig(config); err != nil {
		return commandConfig{}, err
	}
	return config, nil
}

func validateCommandConfig(config commandConfig) error {
	switch {
	case config.grantFile == "":
		return errors.New("grant-file is required")
	case config.runTimeout <= 0 || config.runTimeout > 15*time.Minute:
		return errors.New("timeout must be greater than zero and no more than 15 minutes")
	case config.pollInterval < 250*time.Millisecond || config.pollInterval > time.Minute:
		return errors.New("approval-poll-interval must be between 250ms and one minute")
	case config.terraformBinary == "":
		return errors.New("terraform-bin is required")
	}
	if _, err := validateAgentGateURL(config.agentGateURL); err != nil {
		return err
	}
	return validateDemoInputs(terraformInputs{
		AWSRegion:  config.awsRegion,
		DemoBucket: config.demoBucket,
		DemoPrefix: config.demoPrefix,
	})
}

func runAgent(
	ctx context.Context,
	config commandConfig,
	terraformOutput io.Writer,
) (result runResult, runErr error) {
	taskGrant, err := loadGrant(config.grantFile)
	if err != nil {
		return runResult{}, err
	}
	if config.requestedRole != "" && config.requestedRole != taskGrant.VaultRole {
		return runResult{}, errors.New("vault-role does not match the signed task grant")
	}

	x509Options := []workloadapi.X509SourceOption{}
	if config.workloadAPIAddr != "" {
		x509Options = append(
			x509Options,
			workloadapi.WithClientOptions(workloadapi.WithAddr(config.workloadAPIAddr)),
		)
	}
	x509Source, err := workloadapi.NewX509Source(ctx, x509Options...)
	if err != nil {
		return runResult{}, errors.New("initialize SPIFFE X509 source")
	}
	defer func() {
		if err := x509Source.Close(); err != nil && runErr == nil {
			runErr = errors.New("close SPIFFE X509 source")
		}
	}()
	x509SVID, err := x509Source.GetX509SVID()
	if err != nil {
		return runResult{}, errors.New("obtain workload X509-SVID")
	}

	httpClient := &http.Client{
		Timeout: 15 * time.Second,
		Transport: newAgentGateTransport(
			x509Source,
			x509Source,
			config.agentGateID,
		),
		CheckRedirect: rejectRedirect,
	}
	defer closeHTTPTransport(httpClient.Transport)

	decision, descriptor, err := obtainRedemptionDescriptor(
		ctx,
		httpClient,
		config.agentGateURL,
		taskGrant,
		config.pollInterval,
		time.Now,
	)
	if err != nil {
		return runResult{}, err
	}

	runner := terraformRunner{
		binary:   config.terraformBinary,
		workRoot: config.terraformWorkRoot,
		output:   terraformOutput,
	}
	workDirectory, cleanupWorkDirectory, err := runner.prepare()
	if err != nil {
		return runResult{}, err
	}
	defer cleanupWorkDirectory()
	if err := runner.initialize(ctx, workDirectory); err != nil {
		return runResult{}, err
	}

	credentials, err := obtainVaultCredentials(
		ctx,
		config,
		x509Source,
		x509SVID.ID,
		descriptor,
	)
	if err != nil {
		return runResult{}, err
	}
	defer credentials.clear()

	terraformResult, err := runner.plan(ctx, workDirectory, terraformInputs{
		AWSRegion:  config.awsRegion,
		DemoBucket: config.demoBucket,
		DemoPrefix: config.demoPrefix,
		RequestID:  taskGrant.RequestID,
	}, credentials)
	if err != nil {
		return runResult{}, err
	}

	return runResult{
		RequestID:          taskGrant.RequestID,
		SPIFFEID:           x509SVID.ID.String(),
		Decision:           decision.Decision.Kind,
		ApprovalState:      decision.Approval,
		BindingState:       decision.BindingState,
		VaultAuthRole:      descriptor.AuthRole,
		AWSRoleSessionName: taskGrant.RequestID,
		Terraform:          terraformResult,
	}, nil
}

func obtainVaultCredentials(
	ctx context.Context,
	config commandConfig,
	x509Source *workloadapi.X509Source,
	workloadID spiffeid.ID,
	descriptor authz.RedemptionDescriptor,
) (*awsCredentials, error) {
	jwtOptions := []workloadapi.JWTSourceOption{}
	if config.workloadAPIAddr != "" {
		jwtOptions = append(
			jwtOptions,
			workloadapi.WithClientOptions(workloadapi.WithAddr(config.workloadAPIAddr)),
		)
	}
	jwtSource, err := workloadapi.NewJWTSource(ctx, jwtOptions...)
	if err != nil {
		return nil, errors.New("initialize SPIFFE JWT source")
	}
	jwt, err := fetchVaultJWT(
		ctx,
		jwtSource,
		workloadID,
		descriptor.Audience,
		time.Now,
	)
	closeErr := jwtSource.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, errors.New("close SPIFFE JWT source")
	}

	vaultClient, closeVaultClient, err := newDirectVaultClient(
		descriptor,
		x509Source,
		workloadID.TrustDomain(),
		config.vaultTLSServer,
	)
	if err != nil {
		return nil, err
	}
	defer closeVaultClient()
	return redeemVaultCredentials(ctx, vaultClient, descriptor, jwt, time.Now)
}

func loadGrant(path string) (taskGrant grant.TaskGrant, loadErr error) {
	file, err := os.Open(path) // #nosec G304 -- the grant path is explicit operator configuration.
	if err != nil {
		return grant.TaskGrant{}, errors.New("open signed task grant")
	}
	defer func() {
		if err := file.Close(); err != nil && loadErr == nil {
			loadErr = errors.New("close signed task grant")
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return grant.TaskGrant{}, errors.New("inspect signed task grant")
	}
	if info.Size() <= 0 || info.Size() > 64<<10 {
		return grant.TaskGrant{}, errors.New("signed task grant must be between 1 and 65536 bytes")
	}

	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&taskGrant); err != nil {
		return grant.TaskGrant{}, errors.New("decode signed task grant")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return grant.TaskGrant{}, errors.New("signed task grant must contain one JSON object")
	}
	return taskGrant, nil
}
