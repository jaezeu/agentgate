package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jaezeu/agentgate/internal/grant"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "orchestrator-stub:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	flags := flag.NewFlagSet("orchestrator-stub", flag.ContinueOnError)
	privateKeyPath := flags.String("private-key", "dispatcher-private.pem", "dispatcher Ed25519 private key")
	repository := flags.String("repo", "", "repository identifier")
	commitSHA := flags.String("commit-sha", "", "40-character Git commit SHA")
	operation := flags.String("operation", string(grant.OperationTerraformPlan), "terraform-plan, terraform-apply, or kubernetes-inspect")
	environment := flags.String("environment", "sandbox", "target environment")
	vaultRole := flags.String("vault-role", "", "requested Vault AWS role")
	ttl := flags.Duration("ttl", 15*time.Minute, "grant lifetime")
	onBehalfOf := flags.String("on-behalf-of", "", "human identity from dispatcher SSO context")
	ticketID := flags.String("ticket-id", "", "human request or ticket identifier")
	requestID := flags.String("request-id", "", "request correlation ID; generated when omitted")
	nonce := flags.String("nonce", "", "single-use nonce; generated when omitted")
	tamper := flags.Bool("tamper", false, "alter a signed claim to demonstrate signature rejection")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	switch grant.Operation(*operation) {
	case grant.OperationTerraformPlan, grant.OperationTerraformApply, grant.OperationKubernetesInspect:
	default:
		return errors.New("--operation must be terraform-plan, terraform-apply, or kubernetes-inspect")
	}
	if *ttl <= 0 || *ttl%time.Second != 0 {
		return errors.New("--ttl must be a positive whole number of seconds")
	}

	privatePEM, err := os.ReadFile(*privateKeyPath)
	if err != nil {
		return fmt.Errorf("read private key: %w", err)
	}
	privateKey, err := grant.ParsePrivateKeyPEM(privatePEM)
	if err != nil {
		return err
	}
	if *requestID == "" {
		*requestID, err = randomUUID()
		if err != nil {
			return err
		}
	}
	if *nonce == "" {
		*nonce, err = randomHex(32)
		if err != nil {
			return err
		}
	}

	taskGrant, err := (grant.Signer{PrivateKey: privateKey}).Sign(grant.TaskGrant{
		RequestID:   *requestID,
		Repo:        *repository,
		CommitSHA:   *commitSHA,
		Operation:   grant.Operation(*operation),
		Environment: *environment,
		VaultRole:   *vaultRole,
		TTLSeconds:  int64(*ttl / time.Second),
		Nonce:       *nonce,
		IssuedAt:    time.Now().UTC(),
		OnBehalfOf:  *onBehalfOf,
		TicketID:    *ticketID,
	})
	if err != nil {
		return fmt.Errorf("sign task grant: %w", err)
	}
	if *tamper {
		taskGrant.CommitSHA = "ffffffffffffffffffffffffffffffffffffffff"
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(taskGrant)
}

func randomUUID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate request ID: %w", err)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func randomHex(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	return hex.EncodeToString(value), nil
}
