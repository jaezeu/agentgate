package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	hashicorpapi "github.com/hashicorp/vault/api"
	"github.com/jaezeu/agentgate/internal/authz"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	maxJWTSVIDLifetime  = 5 * time.Minute
	minJWTValidity      = 10 * time.Second
	maxVaultLease       = 15 * time.Minute
	vaultRequestTimeout = 10 * time.Second
)

var stsAccessKeyPattern = regexp.MustCompile(`^ASIA[A-Z0-9]{16}$`)

type jwtSVIDSource interface {
	FetchJWTSVID(context.Context, jwtsvid.Params) (*jwtsvid.SVID, error)
}

type awsCredentials struct {
	accessKeyID     string
	secretAccessKey string
	sessionToken    string
}

func (credentials *awsCredentials) clear() {
	if credentials == nil {
		return
	}
	credentials.accessKeyID = ""
	credentials.secretAccessKey = ""
	credentials.sessionToken = ""
}

func fetchVaultJWT(
	ctx context.Context,
	source jwtSVIDSource,
	expectedID spiffeid.ID,
	audience string,
	now func() time.Time,
) (string, error) {
	if source == nil || expectedID.IsZero() || audience != "vault" {
		return "", errors.New("invalid JWT-SVID request")
	}
	svid, err := source.FetchJWTSVID(ctx, jwtsvid.Params{Audience: audience})
	if err != nil {
		return "", errors.New("fetch workload JWT-SVID")
	}
	currentTime := now().UTC()
	if svid == nil ||
		svid.ID != expectedID ||
		len(svid.Audience) != 1 ||
		svid.Audience[0] != audience ||
		svid.Expiry.Before(currentTime.Add(minJWTValidity)) ||
		svid.Expiry.After(currentTime.Add(maxJWTSVIDLifetime)) {
		return "", errors.New("workload JWT-SVID violates identity, audience, or lifetime constraints")
	}
	token := svid.Marshal()
	if token == "" {
		return "", errors.New("workload JWT-SVID is empty")
	}
	return token, nil
}

func newDirectVaultClient(
	descriptor authz.RedemptionDescriptor,
	bundleSource x509bundle.Source,
	trustDomain spiffeid.TrustDomain,
	tlsServerName string,
) (*hashicorpapi.Client, func(), error) {
	if bundleSource == nil || trustDomain.IsZero() {
		return nil, nil, errors.New("SPIFFE trust bundle source is required for Vault")
	}
	vaultURL, err := url.Parse(descriptor.VaultAddress)
	if err != nil {
		return nil, nil, errors.New("parse Vault address")
	}
	serverName := strings.TrimSpace(tlsServerName)
	if serverName == "" {
		serverName = vaultURL.Hostname()
	}
	if serverName == "" || strings.ContainsAny(serverName, "/\\\x00\r\n") {
		return nil, nil, errors.New("vault TLS server name is invalid")
	}

	bundle, err := bundleSource.GetX509BundleForTrustDomain(trustDomain)
	if err != nil {
		return nil, nil, errors.New("obtain SPIFFE trust bundle for Vault")
	}
	roots := x509.NewCertPool()
	for _, authority := range bundle.X509Authorities() {
		roots.AddCert(authority)
	}
	if len(bundle.X509Authorities()) == 0 {
		return nil, nil, errors.New("SPIFFE trust bundle for Vault is empty")
	}

	transport := &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          2,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: vaultRequestTimeout,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
			ServerName: serverName,
		},
	}
	httpClient := &http.Client{
		Transport:     transport,
		Timeout:       vaultRequestTimeout,
		CheckRedirect: rejectRedirect,
	}
	client, err := hashicorpapi.NewClient(&hashicorpapi.Config{
		Address:          descriptor.VaultAddress,
		HttpClient:       httpClient,
		MaxRetries:       0,
		Timeout:          vaultRequestTimeout,
		DisableRedirects: true,
	})
	if err != nil {
		transport.CloseIdleConnections()
		return nil, nil, errors.New("initialize direct Vault client")
	}
	cleanup := func() {
		client.ClearToken()
		transport.CloseIdleConnections()
	}
	return client, cleanup, nil
}

func redeemVaultCredentials(
	ctx context.Context,
	client *hashicorpapi.Client,
	descriptor authz.RedemptionDescriptor,
	jwt string,
	now func() time.Time,
) (*awsCredentials, error) {
	if client == nil || jwt == "" {
		return nil, errors.New("direct Vault redemption requires a client and JWT-SVID")
	}
	loginData := map[string]interface{}{
		"role": descriptor.AuthRole,
		"jwt":  jwt,
	}
	loginResponse, err := client.Logical().WriteWithContext(
		ctx,
		"auth/"+descriptor.AuthMount+"/login",
		loginData,
	)
	delete(loginData, "jwt")
	delete(loginData, "role")
	if err != nil {
		return nil, safeVaultFailure("Vault JWT login", err)
	}
	if loginResponse == nil ||
		loginResponse.Auth == nil ||
		loginResponse.Auth.ClientToken == "" {
		clearVaultSecret(loginResponse)
		return nil, errors.New("vault JWT login returned no client authorization")
	}
	if err := validateBoundedVaultLifetime(
		time.Duration(loginResponse.Auth.LeaseDuration) * time.Second,
	); err != nil {
		clearVaultSecret(loginResponse)
		return nil, err
	}
	client.SetToken(loginResponse.Auth.ClientToken)
	loginResponse.Auth.ClientToken = ""
	clearVaultSecret(loginResponse)
	defer client.ClearToken()

	redemptionTime := now().UTC()
	remainingTTL := descriptor.ExpiresAt.Sub(redemptionTime).Truncate(time.Second)
	if remainingTTL <= 0 || remainingTTL > maxVaultLease {
		return nil, errors.New("vault descriptor has no valid remaining lease window")
	}
	credentialResponse, err := client.Logical().ReadWithDataWithContext(
		ctx,
		descriptor.SecretsPath,
		map[string][]string{
			"role_session_name": {descriptor.RequestID},
			"ttl":               {strconv.FormatInt(int64(remainingTTL/time.Second), 10) + "s"},
		},
	)
	if err != nil {
		return nil, safeVaultFailure("Vault AWS credential read", err)
	}
	defer clearVaultSecret(credentialResponse)
	if credentialResponse == nil ||
		credentialResponse.Data == nil ||
		credentialResponse.LeaseID == "" {
		return nil, errors.New("vault AWS credential read returned no dynamic lease")
	}
	if err := validateVaultLifetime(
		time.Duration(credentialResponse.LeaseDuration)*time.Second,
		descriptor.ExpiresAt,
		now().UTC(),
	); err != nil {
		return nil, err
	}

	credentials := &awsCredentials{}
	var ok bool
	credentials.accessKeyID, ok = credentialResponse.Data["access_key"].(string)
	if !ok {
		credentials.clear()
		return nil, errors.New("vault AWS response omitted the STS access key ID")
	}
	credentials.secretAccessKey, ok = credentialResponse.Data["secret_key"].(string)
	if !ok {
		credentials.clear()
		return nil, errors.New("vault AWS response omitted the STS secret access key")
	}
	credentials.sessionToken, ok = credentialResponse.Data["security_token"].(string)
	if !ok {
		credentials.clear()
		return nil, errors.New("vault AWS response omitted the STS session token")
	}
	if !stsAccessKeyPattern.MatchString(credentials.accessKeyID) ||
		!validCredentialValue(credentials.secretAccessKey, 16, 256) ||
		!validCredentialValue(credentials.sessionToken, 32, 16<<10) {
		credentials.clear()
		return nil, errors.New("vault AWS response did not contain bounded STS credentials")
	}
	return credentials, nil
}

func validateVaultLifetime(lifetime time.Duration, expiresAt, now time.Time) error {
	if err := validateBoundedVaultLifetime(lifetime); err != nil {
		return err
	}
	if now.Add(lifetime).After(expiresAt.Add(5 * time.Second)) {
		return errors.New("vault lease exceeds the AgentGate access window")
	}
	return nil
}

func validateBoundedVaultLifetime(lifetime time.Duration) error {
	if lifetime <= 0 || lifetime > maxVaultLease {
		return errors.New("vault returned an invalid lease lifetime")
	}
	return nil
}

func validCredentialValue(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return false
		}
	}
	return true
}

func clearVaultSecret(secret *hashicorpapi.Secret) {
	if secret == nil {
		return
	}
	if secret.Auth != nil {
		secret.Auth.ClientToken = ""
		secret.Auth.Accessor = ""
		secret.Auth.EntityID = ""
		for key := range secret.Auth.Metadata {
			secret.Auth.Metadata[key] = ""
			delete(secret.Auth.Metadata, key)
		}
		secret.Auth.Metadata = nil
	}
	for key := range secret.Data {
		secret.Data[key] = nil
		delete(secret.Data, key)
	}
	secret.Data = nil
	secret.LeaseID = ""
}

func safeVaultFailure(operation string, err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("%s timed out", operation)
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("%s was canceled", operation)
	}
	var responseError *hashicorpapi.ResponseError
	if errors.As(err, &responseError) && responseError.StatusCode != 0 {
		return fmt.Errorf("%s returned HTTP status %d", operation, responseError.StatusCode)
	}
	return fmt.Errorf("%s failed", operation)
}

var _ jwtSVIDSource = (*workloadapi.JWTSource)(nil)
