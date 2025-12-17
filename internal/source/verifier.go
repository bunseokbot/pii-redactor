package source

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// Verifier defines the interface for signature verification
type Verifier interface {
	// Verify verifies the content against a signature
	Verify(content []byte, signature []byte) error

	// Type returns the verifier type
	Type() string
}

// RSAVerifier verifies signatures using RSA public key
type RSAVerifier struct {
	publicKey *rsa.PublicKey
}

// NewRSAVerifier creates a new RSA verifier from a PEM-encoded public key
func NewRSAVerifier(publicKeyPEM string) (*RSAVerifier, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		// Try parsing as PKCS1
		pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}
		return &RSAVerifier{publicKey: pubKey}, nil
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return &RSAVerifier{publicKey: rsaPub}, nil
}

// Type returns the verifier type
func (v *RSAVerifier) Type() string {
	return "rsa"
}

// Verify verifies the content against a signature
func (v *RSAVerifier) Verify(content []byte, signature []byte) error {
	// Compute hash
	hash := sha256.Sum256(content)

	// Verify signature
	err := rsa.VerifyPKCS1v15(v.publicKey, crypto.SHA256, hash[:], signature)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// Base64RSAVerifier wraps RSAVerifier to handle base64-encoded signatures
type Base64RSAVerifier struct {
	*RSAVerifier
}

// NewBase64RSAVerifier creates a new Base64RSAVerifier
func NewBase64RSAVerifier(publicKeyPEM string) (*Base64RSAVerifier, error) {
	rsaVerifier, err := NewRSAVerifier(publicKeyPEM)
	if err != nil {
		return nil, err
	}
	return &Base64RSAVerifier{RSAVerifier: rsaVerifier}, nil
}

// Verify verifies the content against a base64-encoded signature
func (v *Base64RSAVerifier) Verify(content []byte, signature []byte) error {
	// Decode base64 signature
	decoded, err := base64.StdEncoding.DecodeString(string(signature))
	if err != nil {
		return fmt.Errorf("failed to decode base64 signature: %w", err)
	}

	return v.RSAVerifier.Verify(content, decoded)
}

// NoOpVerifier is a verifier that always succeeds (for testing or disabled verification)
type NoOpVerifier struct{}

// NewNoOpVerifier creates a new no-op verifier
func NewNoOpVerifier() *NoOpVerifier {
	return &NoOpVerifier{}
}

// Type returns the verifier type
func (v *NoOpVerifier) Type() string {
	return "noop"
}

// Verify always returns nil (no verification)
func (v *NoOpVerifier) Verify(content []byte, signature []byte) error {
	return nil
}

// HashVerifier verifies content by comparing SHA256 hashes
type HashVerifier struct {
	expectedHash string
}

// NewHashVerifier creates a new hash verifier
func NewHashVerifier(expectedHash string) *HashVerifier {
	return &HashVerifier{expectedHash: expectedHash}
}

// Type returns the verifier type
func (v *HashVerifier) Type() string {
	return "sha256"
}

// Verify verifies the content hash matches the expected hash
func (v *HashVerifier) Verify(content []byte, signature []byte) error {
	hash := sha256.Sum256(content)
	computed := fmt.Sprintf("%x", hash)

	expected := v.expectedHash
	if len(signature) > 0 {
		expected = string(signature)
	}

	if computed != expected {
		return fmt.Errorf("hash mismatch: expected %s, got %s", expected, computed)
	}

	return nil
}

// VerificationResult holds the result of verification
type VerificationResult struct {
	// Verified indicates if verification was successful
	Verified bool

	// VerifierType is the type of verifier used
	VerifierType string

	// Error is the verification error if any
	Error error
}

// VerifyContent verifies content using the appropriate verifier
func VerifyContent(verifier Verifier, content []byte, signature []byte) *VerificationResult {
	result := &VerificationResult{
		VerifierType: verifier.Type(),
	}

	err := verifier.Verify(content, signature)
	if err != nil {
		result.Verified = false
		result.Error = err
	} else {
		result.Verified = true
	}

	return result
}
