package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jaezeu/agentgate/internal/vaultmgr"
)

const maxCLIResponseBytes = int64(64 << 10)

type revokeCommandResponse struct {
	RequestID  string                    `json:"request_id"`
	Revocation vaultmgr.RevocationReport `json:"revocation"`
}

type commandErrorResponse struct {
	Error struct {
		Code string `json:"code"`
	} `json:"error"`
}

func runRevoke(arguments []string) error {
	return runRevokeWith(arguments, os.LookupEnv, os.Stdout)
}

func runRevokeWith(
	arguments []string,
	lookupEnvironment func(string) (string, bool),
	output io.Writer,
) error {
	flags := flag.NewFlagSet("revoke", flag.ContinueOnError)
	apiURL := flags.String("api-url", "https://127.0.0.1:8443", "AgentGate API base URL")
	requestID := flags.String("request-id", "", "request ID to revoke")
	tokenEnvironment := flags.String(
		"human-token-env",
		defaultHumanTokenEnvironment,
		"environment variable holding the human bearer token",
	)
	certificateAuthority := flags.String("ca-cert", "", "AgentGate server CA certificate PEM")
	tlsServerName := flags.String("tls-server-name", "", "AgentGate TLS server name")
	allowInsecureHTTP := flags.Bool(
		"allow-insecure-http",
		false,
		"explicitly permit plaintext HTTP for a local PoC",
	)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("revoke does not accept positional arguments")
	}
	if !validCommandRequestID(*requestID) {
		return errors.New("--request-id must be a UUID")
	}
	token, exists := lookupEnvironment(*tokenEnvironment)
	if !exists || token == "" {
		return fmt.Errorf("required runtime environment variable %s is not set", *tokenEnvironment)
	}
	endpoint, err := revokeEndpoint(*apiURL, *requestID, *allowInsecureHTTP)
	if err != nil {
		return err
	}
	transport, err := revokeTransport(*certificateAuthority, *tlsServerName)
	if err != nil {
		return err
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("AgentGate revoke redirects are disabled")
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		bytes.NewReader([]byte("{}")),
	)
	if err != nil {
		return errors.New("create revoke request")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)

	response, err := client.Do(request)
	if err != nil {
		return errors.New("send revoke request")
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxCLIResponseBytes+1))
	if err != nil {
		return errors.New("read revoke response")
	}
	if int64(len(body)) > maxCLIResponseBytes {
		return errors.New("revoke response exceeds size limit")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		var errorResponse commandErrorResponse
		if json.Unmarshal(body, &errorResponse) == nil && errorResponse.Error.Code != "" {
			return fmt.Errorf(
				"revoke failed with HTTP %d (%s)",
				response.StatusCode,
				errorResponse.Error.Code,
			)
		}
		return fmt.Errorf("revoke failed with HTTP %d", response.StatusCode)
	}
	mediaType, _, mediaTypeErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaTypeErr != nil || mediaType != "application/json" {
		return errors.New("revoke response must use application/json")
	}

	var result revokeCommandResponse
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return errors.New("decode revoke response")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("decode revoke response trailer")
	}
	if result.RequestID != *requestID ||
		result.Revocation.RequestID != *requestID ||
		!result.Revocation.STSCredentialsMayRemain {
		return errors.New("revoke response is missing required STS expiry warning")
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		return errors.New("write revoke response")
	}
	return nil
}

func revokeEndpoint(rawBaseURL, requestID string, allowInsecureHTTP bool) (string, error) {
	baseURL, err := url.Parse(rawBaseURL)
	if err != nil ||
		baseURL.Host == "" ||
		baseURL.User != nil ||
		baseURL.RawQuery != "" ||
		baseURL.Fragment != "" {
		return "", errors.New("--api-url must be an absolute URL without user info, query, or fragment")
	}
	if baseURL.Scheme != "https" && (!allowInsecureHTTP || baseURL.Scheme != "http") {
		return "", errors.New("--api-url must use HTTPS unless --allow-insecure-http is explicit")
	}
	baseURL.Path = strings.TrimRight(baseURL.Path, "/") +
		"/v1/requests/" + url.PathEscape(requestID) + "/revoke"
	return baseURL.String(), nil
}

func revokeTransport(certificateAuthority, serverName string) (*http.Transport, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: serverName,
	}
	if certificateAuthority != "" {
		certificateData, err := os.ReadFile(certificateAuthority) // #nosec G304 -- path is explicit CLI configuration.
		if err != nil {
			return nil, errors.New("read AgentGate CA certificate")
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(certificateData) {
			return nil, errors.New("AgentGate CA file contains no certificates")
		}
		tlsConfig.RootCAs = roots
	}
	return &http.Transport{
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConns:          2,
	}, nil
}

func validCommandRequestID(value string) bool {
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
