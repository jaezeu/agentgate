package grant

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func TestEd25519Verifier(t *testing.T) {
	t.Parallel()

	now := time.Date(2030, time.January, 2, 15, 4, 5, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(fixedSeed())
	publicKey := privateKey.Public().(ed25519.PublicKey)

	tests := []struct {
		name        string
		prepare     func(t *testing.T, signer Signer) TaskGrant
		verifyTwice bool
		wantError   error
	}{
		{
			name: "valid grant",
			prepare: func(t *testing.T, signer Signer) TaskGrant {
				return mustSign(t, signer, validGrant(now))
			},
		},
		{
			name: "expired grant",
			prepare: func(t *testing.T, signer Signer) TaskGrant {
				candidate := validGrant(now.Add(-20 * time.Minute))
				return mustSign(t, signer, candidate)
			},
			wantError: ErrExpired,
		},
		{
			name: "tampered grant",
			prepare: func(t *testing.T, signer Signer) TaskGrant {
				signed := mustSign(t, signer, validGrant(now))
				signed.Repo = "github.com/example/tampered"
				return signed
			},
			wantError: ErrInvalidSignature,
		},
		{
			name: "replayed nonce",
			prepare: func(t *testing.T, signer Signer) TaskGrant {
				return mustSign(t, signer, validGrant(now))
			},
			verifyTwice: true,
			wantError:   ErrReplay,
		},
		{
			name: "missing on_behalf_of",
			prepare: func(t *testing.T, _ Signer) TaskGrant {
				candidate := validGrant(now)
				candidate.OnBehalfOf = ""
				return signFixtureWithoutClaimValidation(t, privateKey, candidate)
			},
			wantError: ErrMissingOnBehalfOf,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			verifier := Ed25519Verifier{
				PublicKey: publicKey,
				Nonces:    NewMemoryNonceStore(),
				Clock:     func() time.Time { return now },
			}
			taskGrant := test.prepare(t, Signer{PrivateKey: privateKey})

			if test.verifyTwice {
				if err := verifier.Verify(context.Background(), taskGrant); err != nil {
					t.Fatalf("first Verify() error = %v", err)
				}
			}
			err := verifier.Verify(context.Background(), taskGrant)
			if !errors.Is(err, test.wantError) {
				t.Fatalf("Verify() error = %v, want %v", err, test.wantError)
			}
		})
	}
}

func TestSignerRejectsMissingOnBehalfOf(t *testing.T) {
	t.Parallel()

	privateKey := ed25519.NewKeyFromSeed(fixedSeed())
	candidate := validGrant(time.Date(2030, time.January, 2, 15, 4, 5, 0, time.UTC))
	candidate.OnBehalfOf = ""

	_, err := (Signer{PrivateKey: privateKey}).Sign(candidate)
	if !errors.Is(err, ErrMissingOnBehalfOf) {
		t.Fatalf("Sign() error = %v, want %v", err, ErrMissingOnBehalfOf)
	}
}

func TestKeyPEMRoundTrip(t *testing.T) {
	t.Parallel()

	privateKey := ed25519.NewKeyFromSeed(fixedSeed())
	publicKey := privateKey.Public().(ed25519.PublicKey)
	privatePEM, err := MarshalPrivateKeyPEM(privateKey)
	if err != nil {
		t.Fatalf("MarshalPrivateKeyPEM() error = %v", err)
	}
	publicPEM, err := MarshalPublicKeyPEM(publicKey)
	if err != nil {
		t.Fatalf("MarshalPublicKeyPEM() error = %v", err)
	}

	parsedPrivate, err := ParsePrivateKeyPEM(privatePEM)
	if err != nil {
		t.Fatalf("ParsePrivateKeyPEM() error = %v", err)
	}
	parsedPublic, err := ParsePublicKeyPEM(publicPEM)
	if err != nil {
		t.Fatalf("ParsePublicKeyPEM() error = %v", err)
	}
	if !privateKey.Equal(parsedPrivate) || !publicKey.Equal(parsedPublic) {
		t.Fatal("PEM round trip changed key material")
	}
}

func validGrant(issuedAt time.Time) TaskGrant {
	return TaskGrant{
		RequestID:   "018f47f2-4d8a-7b22-98e0-9b638c715d22",
		Repo:        "github.com/jaezeu/agentgate",
		CommitSHA:   "0123456789abcdef0123456789abcdef01234567",
		Operation:   OperationTerraformPlan,
		Environment: "sandbox",
		VaultRole:   "terraform-sandbox",
		TTLSeconds:  900,
		Nonce:       "fixed-fixture-nonce",
		IssuedAt:    issuedAt,
		OnBehalfOf:  "lecturer@example.edu",
		TicketID:    "LAB-42",
	}
}

func TestInvalidSignatureDoesNotConsumeValidNonce(t *testing.T) {
	t.Parallel()
	now := time.Date(2030, time.January, 2, 15, 4, 5, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(fixedSeed())
	valid := mustSign(t, Signer{PrivateKey: privateKey}, validGrant(now))
	tampered := valid
	tampered.Repo = "github.com/example/tampered"
	verifier := Ed25519Verifier{
		PublicKey: privateKey.Public().(ed25519.PublicKey),
		Nonces:    NewMemoryNonceStore(),
		Clock:     func() time.Time { return now },
	}

	if err := verifier.Verify(context.Background(), tampered); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered Verify() error = %v, want %v", err, ErrInvalidSignature)
	}
	if err := verifier.Verify(context.Background(), valid); err != nil {
		t.Fatalf("valid grant failed after tampered attempt: %v", err)
	}
}

func fixedSeed() []byte {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	return seed
}

func mustSign(t *testing.T, signer Signer, taskGrant TaskGrant) TaskGrant {
	t.Helper()
	signed, err := signer.Sign(taskGrant)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	return signed
}

func signFixtureWithoutClaimValidation(t *testing.T, privateKey ed25519.PrivateKey, taskGrant TaskGrant) TaskGrant {
	t.Helper()
	payload, err := canonicalPayload(taskGrant)
	if err != nil {
		t.Fatalf("canonicalPayload() error = %v", err)
	}
	taskGrant.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	return taskGrant
}
