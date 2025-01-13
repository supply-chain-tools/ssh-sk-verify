package attest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/ssh"
	"strings"
)

type AttestationData struct {
	PublicKey   []byte
	Attestation []byte
	Challenge   []byte
	MDS         []byte
}

type AttestationResult struct {
	MDSLegalHeader    string
	AuthenticatorData *AuthenticatorData
	MetadataBlobEntry *MetadataBlobEntry
	CertificateChain  []*x509.Certificate
	SSHPublicKey      *SSHPublicKey
}

func Verify(attestationData *AttestationData) (*AttestationResult, error) {
	attestation := &SSHAttestation{}
	err := ssh.Unmarshal(attestationData.Attestation, attestation)
	if err != nil {
		return nil, err
	}

	const expectedVersion = "ssh-sk-attest-v01"
	if attestation.Version != expectedVersion {
		return nil, fmt.Errorf("got '%s', expected '%s'", attestation.Version, expectedVersion)
	}

	authenticatorDataRaw, err := unpackAuthenticatorData(attestation)
	if err != nil {
		return nil, err
	}

	leafCert, err := verifyAttestationSignature(attestation, authenticatorDataRaw, attestationData.Challenge)
	if err != nil {
		return nil, err
	}

	authenticatorData, err := parseAuthenticatorData(authenticatorDataRaw)
	if err != nil {
		return nil, err
	}

	publicKeyToVerify, err := parsePublicKey(string(attestationData.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	err = verifyKey(publicKeyToVerify, authenticatorData)
	if err != nil {
		return nil, err
	}

	payload, err := parseAndVerifyMDS(attestationData.MDS)
	if err != nil {
		return nil, err
	}

	targetAAGUID, err := aaguidToString(authenticatorData.AttestedCredentialData.AAGUID)
	if err != nil {
		return nil, err
	}

	mdsEntry, err := getMatchingMDSEntry(payload, targetAAGUID)
	if err != nil {
		return nil, err
	}

	certificateChain, err := verifyChain(mdsEntry, leafCert)
	if err != nil {
		return nil, err
	}

	return &AttestationResult{
		MDSLegalHeader:    payload.LegalHeader,
		AuthenticatorData: authenticatorData,
		MetadataBlobEntry: mdsEntry,
		CertificateChain:  certificateChain,
		SSHPublicKey:      publicKeyToVerify,
	}, nil
}

func verifyChain(entry *MetadataBlobEntry, leafCert *x509.Certificate) ([]*x509.Certificate, error) {
	if len(entry.MetadataStatement.AttestationRootCertificates) != 1 {
		return nil, fmt.Errorf("expected one certificate for AAGUID '%s', got %d", entry.AAGUID, len(entry.MetadataStatement.AttestationRootCertificates))
	}
	rootRaw, err := base64.StdEncoding.DecodeString(entry.MetadataStatement.AttestationRootCertificates[0])
	if err != nil {
		return nil, err
	}

	root, err := x509.ParseCertificate(rootRaw)
	if err != nil {
		return nil, err
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)
	chain, err := leafCert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, err
	}

	if len(chain) != 1 || len(chain[0]) != 2 {
		return nil, fmt.Errorf("unexpected certificate chain length for AAGUID '%s'", entry.AAGUID)
	}

	return chain[0], nil
}

func verifyAttestationSignature(attestation *SSHAttestation, authenticatorDataRaw []byte, challengeData []byte) (*x509.Certificate, error) {
	challengeHash := sha256.Sum256(challengeData)
	signedPayload := append(authenticatorDataRaw, challengeHash[:]...)

	cert, err := x509.ParseCertificate([]byte(attestation.AttestationCertificate))
	if err != nil {
		return nil, err
	}

	// TODO support other signature types
	publicKey := cert.PublicKey.(*ecdsa.PublicKey)
	signedPayloadHash := sha256.Sum256(signedPayload)

	verified := ecdsa.VerifyASN1(publicKey, signedPayloadHash[:], []byte(attestation.EnrollmentSignature))
	if verified != true {
		return nil, fmt.Errorf("failed to verify attestation signature")
	}

	return cert, nil
}

func verifyKey(sshKey *SSHPublicKey, authenticatorData *AuthenticatorData) error {
	if !strings.HasPrefix(sshKey.Application, "ssh:") {
		return fmt.Errorf("application should have the prefix 'ssh:', got '%s'", sshKey.Application)
	}

	rpToVerify := sha256.Sum256([]byte(sshKey.Application))
	if !bytes.Equal(authenticatorData.RpIdHash, rpToVerify[:]) {
		return fmt.Errorf("rpIdHash/application mismatch")
	}

	if sshKey.KeyType == sshEd25519 {
		kty := authenticatorData.AttestedCredentialData.CredentialPublicKey[1].(int)
		alg := authenticatorData.AttestedCredentialData.CredentialPublicKey[3].(int)
		ecIdentifier := authenticatorData.AttestedCredentialData.CredentialPublicKey[-1].(int)

		// 1 is octet key pair // https://datatracker.ietf.org/doc/html/rfc8152#section-13
		if kty != 1 {
			return fmt.Errorf("invalid key type, got %d expected 1", kty)
		}

		// -8 is EdDSA // https://datatracker.ietf.org/doc/html/rfc8152#section-8.2
		if alg != -8 {
			return fmt.Errorf("invalid algorithm type, got %d expected -8", kty)
		}

		// 6 is Ed25519 // https://datatracker.ietf.org/doc/html/rfc8152#section-13.1
		if ecIdentifier != 6 {
			return fmt.Errorf("invalid ec identifier, got %d expected 6", kty)
		}

		publicKey := authenticatorData.AttestedCredentialData.CredentialPublicKey[-2].([]byte)
		if len(publicKey) != 32 {
			return fmt.Errorf("invalid public key length, got %d expected 32", len(publicKey))
		}

		if !bytes.Equal(publicKey, sshKey.publicKey) {
			return fmt.Errorf("public key mismatch")
		}

		return nil
	} else if sshKey.KeyType == sshNISTp256 {
		kty := authenticatorData.AttestedCredentialData.CredentialPublicKey[1].(int)
		alg := authenticatorData.AttestedCredentialData.CredentialPublicKey[3].(int)
		ecIdentifier := authenticatorData.AttestedCredentialData.CredentialPublicKey[-1].(int)

		// 2 is EC x and y coordinates // https://datatracker.ietf.org/doc/html/rfc8152#section-13
		if kty != 2 {
			return fmt.Errorf("invalid key type, got %d expected 2", kty)
		}

		// -7 is ES256 // https://datatracker.ietf.org/doc/html/rfc8152#section-8.1
		if alg != -7 {
			return fmt.Errorf("invalid algorithm type, got %d expected -7", kty)
		}

		// 1 is P-256 // https://datatracker.ietf.org/doc/html/rfc8152#section-13.1
		if ecIdentifier != 1 {
			return fmt.Errorf("invalid ec identifier, got %d expected 1", kty)
		}

		publicKeyX := authenticatorData.AttestedCredentialData.CredentialPublicKey[-2].([]byte)
		if len(publicKeyX) != 32 {
			return fmt.Errorf("invalid public key length, got %d expected 32", len(publicKeyX))
		}

		if !bytes.Equal(publicKeyX, sshKey.x) {
			return fmt.Errorf("public key mismatch x")
		}

		publicKeyY := authenticatorData.AttestedCredentialData.CredentialPublicKey[-3].([]byte)
		if len(publicKeyY) != 32 {
			return fmt.Errorf("invalid public key length, got %d expected 32", len(publicKeyX))
		}

		if !bytes.Equal(publicKeyY, sshKey.y) {
			return fmt.Errorf("public key mismatch y")
		}

		return nil
	}

	return fmt.Errorf("unsupported ssh key type '%s'", sshKey.KeyType)
}
