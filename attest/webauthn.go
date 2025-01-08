package attest

import (
	"encoding/hex"
	"fmt"
)

type AuthenticatorData struct {
	// https://www.w3.org/TR/webauthn/#sctn-authenticator-data
	RpIdHash               []byte
	Flags                  byte
	SignCount              uint32
	AttestedCredentialData *AttestedCredentialData
}

type AttestedCredentialData struct {
	// https://www.w3.org/TR/webauthn/#sctn-attested-credential-data
	AAGUID              []byte
	CredentialId        []byte
	CredentialPublicKey map[int]any
}

func parseAuthenticatorData(data []byte) (*AuthenticatorData, error) {
	rpIdHash := data[0:32]
	data = data[32:]

	flags := data[0]
	data = data[1:]
	hasAttestedCredentialData := (flags >> 6) & 0b1
	if hasAttestedCredentialData != 1 {
		return nil, fmt.Errorf("missing attested credential data")
	}

	signCount := uint32(data[0])<<24 + uint32(data[1])<<16 + uint32(data[2])<<8 + uint32(data[3])
	data = data[4:]

	credentialAttestationData, data, err := readAttestedCredentialData(data)
	if err != nil {
		return nil, err
	}

	hasExtensionData := (flags >> 7) & 0b1
	if hasExtensionData == 0 && len(data) > 0 {
		return nil, fmt.Errorf("unexpected trailing authenticator data")
	}

	return &AuthenticatorData{
		RpIdHash:               rpIdHash,
		Flags:                  flags,
		SignCount:              signCount,
		AttestedCredentialData: credentialAttestationData,
	}, nil
}

func readAttestedCredentialData(data []byte) (*AttestedCredentialData, []byte, error) {
	aaguid := data[0:16]
	data = data[16:]

	credentialLength := int(data[0])<<8 + int(data[1])
	data = data[2:]
	credentialId := data[0:credentialLength]
	data = data[credentialLength:]

	credentialPublicKey, data, err := cborReadMap(data)
	if err != nil {
		return nil, nil, err
	}

	return &AttestedCredentialData{
		AAGUID:              aaguid,
		CredentialId:        credentialId,
		CredentialPublicKey: credentialPublicKey,
	}, data, nil
}

func aaguidToString(data []byte) (string, error) {
	d := hex.EncodeToString(data)

	if len(d) != 32 {
		return "", fmt.Errorf("AAGUID should 32 characters")
	}

	return d[0:8] + "-" + d[8:12] + "-" + d[12:16] + "-" + d[16:20] + "-" + d[20:], nil
}
