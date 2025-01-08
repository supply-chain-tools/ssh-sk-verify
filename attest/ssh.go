package attest

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/ssh"
	"strings"
)

// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f

const sshEd25519 = "sk-ssh-ed25519@openssh.com"
const sshNISTp256 = "sk-ecdsa-sha2-nistp256@openssh.com"

type SSHAttestation struct {
	Version                string
	AttestationCertificate string
	EnrollmentSignature    string
	AuthenticatorData      string
	ReservedFlags          uint32
	ReservedString         string
}

type SSHPublicKey struct {
	KeyType     string
	publicKey   []byte
	x           []byte
	y           []byte
	Application string
	Fingerprint string
}

type SSHPublicKeyEd25519 struct {
	KeyType     string
	Key         string
	Application string
}

type SSHPublicKeyECDSA struct {
	KeyType     string
	CurveName   string
	ECPoint     string
	Application string
}

func unpackAuthenticatorData(attestation *SSHAttestation) ([]byte, error) {
	authenticatorDataRaw, rest, err := cborReadArray([]byte(attestation.AuthenticatorData))
	if err != nil {
		return nil, err
	}

	if len(rest) != 0 {
		return nil, fmt.Errorf("unexpected extra bytes")
	}

	return authenticatorDataRaw, nil
}

func parsePublicKey(data string) (*SSHPublicKey, error) {
	parts := strings.Split(data, " ")
	rawKey, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %w", err)
	}

	fingerprint := sha256.Sum256(rawKey)
	fingerprintString := "SHA256:" + strings.TrimRight(base64.StdEncoding.EncodeToString(fingerprint[:]), "=")

	if parts[0] == sshEd25519 {
		publicKey := &SSHPublicKeyEd25519{}
		err = ssh.Unmarshal(rawKey, publicKey)
		if err != nil {
			return nil, err
		}

		if publicKey.KeyType != sshEd25519 {
			return nil, fmt.Errorf("inconsistent key types: got '%s', expected '%s", publicKey.KeyType, sshEd25519)
		}

		return &SSHPublicKey{
			KeyType:     publicKey.KeyType,
			publicKey:   []byte(publicKey.Key),
			Application: publicKey.Application,
			Fingerprint: fingerprintString,
		}, nil
	} else if parts[0] == sshNISTp256 {
		publicKey := &SSHPublicKeyECDSA{}
		err = ssh.Unmarshal(rawKey, publicKey)
		if err != nil {
			return nil, err
		}

		if publicKey.KeyType != sshNISTp256 {
			return nil, fmt.Errorf("inconsistent key types: got '%s', expected '%s", publicKey.KeyType, sshNISTp256)
		}

		if len(publicKey.ECPoint) != 1+2*32 {
			return nil, fmt.Errorf("invalid EC point length: got %d, expected 65", len(publicKey.ECPoint))
		}

		if publicKey.ECPoint[0] != 4 {
			return nil, fmt.Errorf("invalid EC point: got %d, expected 4 (uncompressed)", publicKey.ECPoint[0])
		}

		x := []byte(publicKey.ECPoint)[1 : 1+32]
		y := []byte(publicKey.ECPoint)[1+32 : 1+2*32]

		return &SSHPublicKey{
			KeyType:     publicKey.KeyType,
			x:           x,
			y:           y,
			Application: publicKey.Application,
			Fingerprint: fingerprintString,
		}, nil
	}

	return nil, fmt.Errorf("unknown public key type: '%s'", parts[0])
}
