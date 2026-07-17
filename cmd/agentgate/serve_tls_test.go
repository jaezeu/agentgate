package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCertificateReloaderKeepsValidCertificateDuringRotation(t *testing.T) {
	t.Parallel()

	certificatePath := filepath.Join(t.TempDir(), "tls.crt")
	privateKeyPath := filepath.Join(filepath.Dir(certificatePath), "tls.key")
	firstCertificate, firstKey := testCertificatePair(t, 1)
	secondCertificate, secondKey := testCertificatePair(t, 2)
	writeTestCertificatePair(t, certificatePath, privateKeyPath, firstCertificate, firstKey)

	reloader := &certificateReloader{
		certificatePath: certificatePath,
		privateKeyPath:  privateKeyPath,
	}
	initial, err := reloader.load()
	if err != nil {
		t.Fatalf("load initial certificate: %v", err)
	}
	reloader.certificate = initial

	if err := os.WriteFile(certificatePath, secondCertificate, 0o600); err != nil {
		t.Fatalf("write rotating certificate: %v", err)
	}
	duringRotation, err := reloader.getCertificate(nil)
	if err != nil {
		t.Fatalf("get certificate during non-atomic rotation: %v", err)
	}
	if duringRotation.Leaf.SerialNumber.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("serial during rotation = %s, want last valid serial 1", duringRotation.Leaf.SerialNumber)
	}

	if err := os.WriteFile(privateKeyPath, secondKey, 0o600); err != nil {
		t.Fatalf("write rotating private key: %v", err)
	}
	afterRotation, err := reloader.getCertificate(nil)
	if err != nil {
		t.Fatalf("get certificate after rotation: %v", err)
	}
	if afterRotation.Leaf.SerialNumber.Cmp(big.NewInt(2)) != 0 {
		t.Fatalf("serial after rotation = %s, want serial 2", afterRotation.Leaf.SerialNumber)
	}
}

func testCertificatePair(t *testing.T, serial int64) ([]byte, []byte) {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		publicKey,
		privateKey,
	)
	if err != nil {
		t.Fatalf("create test certificate: %v", err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal test key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER})
}

func writeTestCertificatePair(
	t *testing.T,
	certificatePath string,
	privateKeyPath string,
	certificate []byte,
	privateKey []byte,
) {
	t.Helper()

	if err := os.WriteFile(certificatePath, certificate, 0o600); err != nil {
		t.Fatalf("write test certificate: %v", err)
	}
	if err := os.WriteFile(privateKeyPath, privateKey, 0o600); err != nil {
		t.Fatalf("write test private key: %v", err)
	}
}
