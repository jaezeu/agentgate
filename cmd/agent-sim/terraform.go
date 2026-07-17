package main

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const maxTerraformOutputBytes = 1 << 20

var (
	//go:embed terraform/main.tf
	demoTerraformSource []byte

	awsAccessKeyOutputPattern = regexp.MustCompile(`(?:AKIA|ASIA)[A-Z0-9]{16}`)
	jwtOutputPattern          = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)
	vaultTokenOutputPattern   = regexp.MustCompile(`\b(?:hvs|hvb|hvr|s)\.[A-Za-z0-9_-]{8,}\b`)
	credentialLabelPattern    = regexp.MustCompile(`(?i)(AWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN|SECURITY_TOKEN)\s*[=:]\s*)[^\s]+`)
	awsRegionPattern          = regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z]+-\d+$`)
	s3BucketPattern           = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*[a-z0-9]$`)
	s3PrefixPattern           = regexp.MustCompile(`^[A-Za-z0-9_./-]+$`)
)

type terraformInputs struct {
	AWSRegion  string
	DemoBucket string
	DemoPrefix string
	RequestID  string
}

type terraformResult struct {
	Initialized    bool `json:"initialized"`
	PlanCompleted  bool `json:"plan_completed"`
	ChangesPresent bool `json:"changes_present"`
}

type terraformRunner struct {
	binary   string
	workRoot string
	output   io.Writer
}

type commandOutput struct {
	content   []byte
	truncated bool
	exitCode  int
}

type boundedBuffer struct {
	buffer    bytes.Buffer
	remaining int
	truncated bool
}

func (buffer *boundedBuffer) Write(value []byte) (int, error) {
	originalLength := len(value)
	if buffer.remaining <= 0 {
		buffer.truncated = buffer.truncated || originalLength > 0
		return originalLength, nil
	}
	writable := value
	if len(writable) > buffer.remaining {
		writable = writable[:buffer.remaining]
		buffer.truncated = true
	}
	_, _ = buffer.buffer.Write(writable)
	buffer.remaining -= len(writable)
	return originalLength, nil
}

func validateDemoInputs(inputs terraformInputs) error {
	switch {
	case !awsRegionPattern.MatchString(inputs.AWSRegion):
		return errors.New("aws-region is invalid")
	case len(inputs.DemoBucket) < 3 ||
		len(inputs.DemoBucket) > 63 ||
		!s3BucketPattern.MatchString(inputs.DemoBucket) ||
		strings.Contains(inputs.DemoBucket, ".."):
		return errors.New("demo-bucket is invalid")
	case inputs.DemoPrefix == "" ||
		len(inputs.DemoPrefix) > 256 ||
		strings.HasPrefix(inputs.DemoPrefix, "/") ||
		!strings.HasSuffix(inputs.DemoPrefix, "/") ||
		strings.Contains(inputs.DemoPrefix, "..") ||
		!s3PrefixPattern.MatchString(inputs.DemoPrefix):
		return errors.New("demo-prefix is invalid")
	}
	if inputs.RequestID != "" && !validRequestID(inputs.RequestID) {
		return errors.New("terraform request ID is invalid")
	}
	return nil
}

func (runner terraformRunner) prepare() (string, func(), error) {
	parent := runner.workRoot
	if parent != "" {
		info, err := os.Stat(parent)
		if err != nil || !info.IsDir() {
			return "", nil, errors.New("terraform-work-root must be an existing directory")
		}
	}
	workDirectory, err := os.MkdirTemp(parent, "agentgate-terraform-")
	if err != nil {
		return "", nil, errors.New("create ephemeral Terraform working directory")
	}
	cleanup := func() {
		_ = os.RemoveAll(workDirectory)
	}
	if err := os.Chmod(workDirectory, 0o700); err != nil { // #nosec G302 -- directories require owner execute permission.
		cleanup()
		return "", nil, errors.New("protect ephemeral Terraform working directory")
	}
	if err := os.WriteFile(
		filepath.Join(workDirectory, "main.tf"),
		demoTerraformSource,
		0o600,
	); err != nil {
		cleanup()
		return "", nil, errors.New("write embedded Terraform demo configuration")
	}
	return workDirectory, cleanup, nil
}

func (runner terraformRunner) initialize(ctx context.Context, workDirectory string) error {
	result, err := runner.runCommand(
		ctx,
		workDirectory,
		"init",
		[]string{"init", "-backend=false", "-input=false", "-no-color"},
		baseTerraformEnvironment(workDirectory),
		nil,
	)
	if writeErr := runner.writeOutput("init", result); writeErr != nil {
		return writeErr
	}
	if err != nil {
		return safeTerraformFailure("init", result.exitCode, err)
	}
	return nil
}

func (runner terraformRunner) plan(
	ctx context.Context,
	workDirectory string,
	inputs terraformInputs,
	credentials *awsCredentials,
) (terraformResult, error) {
	if err := validateDemoInputs(inputs); err != nil {
		return terraformResult{}, err
	}
	if credentials == nil ||
		credentials.accessKeyID == "" ||
		credentials.secretAccessKey == "" ||
		credentials.sessionToken == "" {
		return terraformResult{}, errors.New("terraform plan requires in-memory STS credentials")
	}
	defer credentials.clear()
	environment := append(baseTerraformEnvironment(workDirectory),
		"AWS_ACCESS_KEY_ID="+credentials.accessKeyID,
		"AWS_SECRET_ACCESS_KEY="+credentials.secretAccessKey,
		"AWS_SESSION_TOKEN="+credentials.sessionToken,
		"AWS_REGION="+inputs.AWSRegion,
		"AWS_DEFAULT_REGION="+inputs.AWSRegion,
		"AWS_EC2_METADATA_DISABLED=true",
		"TF_VAR_aws_region="+inputs.AWSRegion,
		"TF_VAR_demo_bucket_name="+inputs.DemoBucket,
		"TF_VAR_demo_bucket_prefix="+inputs.DemoPrefix,
		"TF_VAR_request_id="+inputs.RequestID,
	)
	secrets := []string{
		credentials.accessKeyID,
		credentials.secretAccessKey,
		credentials.sessionToken,
	}
	defer clearStrings(secrets)
	result, err := runner.runCommand(
		ctx,
		workDirectory,
		"plan",
		[]string{
			"plan",
			"-input=false",
			"-lock=false",
			"-no-color",
			"-detailed-exitcode",
		},
		environment,
		secrets,
	)
	if writeErr := runner.writeOutput("plan", result); writeErr != nil {
		return terraformResult{}, writeErr
	}
	if err != nil && result.exitCode != 2 {
		return terraformResult{}, safeTerraformFailure("plan", result.exitCode, err)
	}
	return terraformResult{
		Initialized:    true,
		PlanCompleted:  true,
		ChangesPresent: result.exitCode == 2,
	}, nil
}

func (runner terraformRunner) runCommand(
	ctx context.Context,
	workDirectory string,
	phase string,
	arguments []string,
	environment []string,
	secrets []string,
) (commandOutput, error) {
	buffer := &boundedBuffer{remaining: maxTerraformOutputBytes}
	// #nosec G204 -- the executable is explicit operator configuration and arguments are fixed internally.
	command := exec.CommandContext(ctx, runner.binary, arguments...)
	command.Dir = workDirectory
	command.Env = environment
	command.Stdout = buffer
	command.Stderr = buffer
	if err := command.Start(); err != nil {
		clearStrings(environment)
		command.Env = nil
		return commandOutput{exitCode: -1}, fmt.Errorf("start Terraform %s", phase)
	}
	clearStrings(environment)
	command.Env = nil
	waitErr := command.Wait()
	exitCode := 0
	if waitErr != nil {
		var exitError *exec.ExitError
		if errors.As(waitErr, &exitError) {
			exitCode = exitError.ExitCode()
		} else {
			exitCode = -1
		}
	}
	rawOutput := buffer.buffer.Bytes()
	content := scrubTerraformOutput(rawOutput, secrets)
	clearBytes(rawOutput)
	buffer.buffer.Reset()
	return commandOutput{
		content:   content,
		truncated: buffer.truncated,
		exitCode:  exitCode,
	}, waitErr
}

func (runner terraformRunner) writeOutput(phase string, output commandOutput) error {
	if runner.output == nil {
		return nil
	}
	if _, err := fmt.Fprintf(runner.output, "----- terraform %s (scrubbed) -----\n", phase); err != nil {
		return errors.New("write scrubbed Terraform output")
	}
	if len(output.content) > 0 {
		if _, err := runner.output.Write(output.content); err != nil {
			return errors.New("write scrubbed Terraform output")
		}
		if output.content[len(output.content)-1] != '\n' {
			if _, err := io.WriteString(runner.output, "\n"); err != nil {
				return errors.New("write scrubbed Terraform output")
			}
		}
	}
	if output.truncated {
		if _, err := io.WriteString(
			runner.output,
			"[Terraform output truncated at 1048576 bytes]\n",
		); err != nil {
			return errors.New("write Terraform truncation notice")
		}
	}
	return nil
}

func baseTerraformEnvironment(workDirectory string) []string {
	environment := []string{
		"PATH=" + environmentValue("PATH", "/usr/local/bin:/usr/bin:/bin"),
		"HOME=" + workDirectory,
		"TMPDIR=" + workDirectory,
		"TF_DATA_DIR=" + filepath.Join(workDirectory, ".terraform-data"),
		"TF_IN_AUTOMATION=1",
		"CHECKPOINT_DISABLE=1",
	}
	for _, name := range []string{"LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR"} {
		if value := os.Getenv(name); value != "" {
			environment = append(environment, name+"="+value)
		}
	}
	return environment
}

func environmentValue(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func scrubTerraformOutput(output []byte, secrets []string) []byte {
	scrubbed := string(output)
	for _, secret := range secrets {
		if secret != "" {
			scrubbed = strings.ReplaceAll(scrubbed, secret, "[REDACTED]")
		}
	}
	scrubbed = credentialLabelPattern.ReplaceAllString(scrubbed, "${1}[REDACTED]")
	scrubbed = awsAccessKeyOutputPattern.ReplaceAllString(scrubbed, "[REDACTED]")
	scrubbed = jwtOutputPattern.ReplaceAllString(scrubbed, "[REDACTED]")
	scrubbed = vaultTokenOutputPattern.ReplaceAllString(scrubbed, "[REDACTED]")
	return []byte(scrubbed)
}

func safeTerraformFailure(phase string, exitCode int, err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("terraform %s timed out", phase)
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("terraform %s was canceled", phase)
	case exitCode >= 0:
		return fmt.Errorf("terraform %s failed with exit code %d", phase, exitCode)
	default:
		return fmt.Errorf("terraform %s failed", phase)
	}
}

func clearStrings(values []string) {
	for index := range values {
		values[index] = ""
	}
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func validRequestID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, character := range value {
		switch index {
		case 8, 13, 18, 23:
			if character != '-' {
				return false
			}
		default:
			if !strings.ContainsRune("0123456789abcdefABCDEF", character) {
				return false
			}
		}
	}
	return true
}
