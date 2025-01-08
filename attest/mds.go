package attest

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// https://fidoalliance.org/metadata/

const mdsDomain = "mds.fidoalliance.org"

// https://valid.r3.roots.globalsign.com/
const rootCA = `-----BEGIN CERTIFICATE-----
MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G
A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp
Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4
MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG
A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8
RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT
gHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm
KPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd
QQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ
XriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw
DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+o
LkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZU
RUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMp
jjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK
6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQX
mcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecs
Mx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpH
WD9f
-----END CERTIFICATE-----`

type jwtHeader struct {
	Alg string   `json:"alg"`
	Typ string   `json:"typ"`
	X5C []string `json:"x5c"`
}

type MetadataBlobPayload struct {
	LegalHeader string              `json:"legalHeader"`
	No          int                 `json:"no"`
	NextUpdate  string              `json:"nextUpdate"`
	Entries     []MetadataBlobEntry `json:"entries"`
}

type MetadataBlobEntry struct {
	// https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dictdef-metadatablobpayloadentry
	AAGUID            string            `json:"aaguid"`
	MetadataStatement MetadataStatement `json:"metadataStatement"`
}

type MetadataStatement struct {
	// https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html
	LegalHeader                 string               `json:"legalHeader"`
	AAGUID                      string               `json:"aaguid"`
	Description                 string               `json:"description"`
	AuthenticatorVersion        uint64               `json:"authenticatorVersion"`
	ProtocolFamily              string               `json:"protocolFamily"`
	Schema                      uint16               `json:"schema"`
	Upv                         []Upv                `json:"upv"`
	AuthenticationAlgorithms    []string             `json:"authenticationAlgorithms"`
	PublicKeyAlgAndEncodings    []string             `json:"publicKeyAlgAndEncodings"`
	AttestationTypes            []string             `json:"attestationTypes"`
	AttestationRootCertificates []string             `json:"attestationRootCertificates"`
	AuthenticatorGetInfo        AuthenticatorGetInfo `json:"authenticatorGetInfo"`
	// ... many more
}

type AuthenticatorGetInfo struct {
	FirmwareVersion int `json:"firmwareVersion"`
}

type Upv struct {
	Major int `json:"major"`
	Minor int `json:"minor"`
}

func parseAndVerifyMDS(mdsData []byte) (*MetadataBlobPayload, error) {
	// https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob
	parts := strings.Split(string(mdsData), ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("expected 3 JWT parts, got %d", len(mdsData))
	}

	headerString := parts[0]
	blobString := parts[1]
	signatureString := parts[2]

	err := verifySignature(headerString, blobString, signatureString)
	if err != nil {
		return nil, err
	}

	blob, err := base64.RawURLEncoding.DecodeString(blobString)
	if err != nil {
		return nil, err
	}

	payload := &MetadataBlobPayload{}
	err = json.Unmarshal(blob, payload)
	if err != nil {
		return nil, err
	}

	const dateFormat = "2006-01-02"
	now := time.Now().UTC()
	nextUpdate, err := time.Parse(dateFormat, payload.NextUpdate)
	if err != nil {
		return nil, err
	}

	if now.After(nextUpdate.Add(24 * time.Hour)) {
		return nil, fmt.Errorf("outdated MDS blob")
	}

	return payload, nil
}

func verifySignature(headerString string, blobString string, signatureString string) error {
	header, err := parseHeader(headerString)
	if err != nil {
		return err
	}

	signature, err := base64.RawURLEncoding.DecodeString(signatureString)
	if err != nil {
		return err
	}

	roots, err := parseRootCerts(rootCA)
	if err != nil {
		return err
	}

	intermediates, err := parseIntermediateCerts(header)
	if err != nil {
		return err
	}

	leafCert, err := parseLeafCert(header)
	if err != nil {
		return err
	}

	chain, err := leafCert.Verify(x509.VerifyOptions{
		DNSName:       mdsDomain,
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return err
	}

	if len(chain) != 1 || len(chain[0]) != len(header.X5C)+1 {
		return fmt.Errorf("unexpected certificate chain length")
	}

	signedPayload := []byte(headerString + "." + blobString)
	digest := sha256.Sum256(signedPayload)

	publicKey := leafCert.PublicKey.(*rsa.PublicKey)
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature)
	if err != nil {
		return err
	}

	return nil
}

func parseHeader(headerString string) (*jwtHeader, error) {
	headerRaw, err := base64.RawURLEncoding.DecodeString(headerString)
	if err != nil {
		return nil, err
	}

	header := &jwtHeader{}
	err = json.Unmarshal(headerRaw, header)
	if err != nil {
		return nil, err
	}

	if len(header.X5C) != 2 {
		return nil, fmt.Errorf("expected 2 x5c certificates, got %d", len(header.X5C))
	}

	if header.Typ != "JWT" {
		return nil, fmt.Errorf("got '%s', expected JWT", header.Typ)
	}

	if header.Alg != "RS256" {
		return nil, fmt.Errorf("got '%s', expected RS256", header.Alg)
	}

	return header, nil
}

func parseRootCerts(rootString string) (*x509.CertPool, error) {
	rootCertBlock, rest := pem.Decode([]byte(rootString))
	if len(rest) != 0 {
		return nil, fmt.Errorf("trailing data %d", len(rest))
	}

	root, err := x509.ParseCertificate(rootCertBlock.Bytes)
	if err != nil {
		return nil, err
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)

	return roots, nil
}

func parseIntermediateCerts(header *jwtHeader) (*x509.CertPool, error) {
	intermediateRaw, err := base64.StdEncoding.DecodeString(header.X5C[1])
	if err != nil {
		return nil, err
	}

	intermediateCert, err := x509.ParseCertificate(intermediateRaw)
	if err != nil {
		return nil, err
	}

	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediateCert)

	return intermediates, nil
}

func parseLeafCert(header *jwtHeader) (*x509.Certificate, error) {
	leafRaw, err := base64.StdEncoding.DecodeString(header.X5C[0])
	if err != nil {
		return nil, err
	}

	leafCert, err := x509.ParseCertificate(leafRaw)
	if err != nil {
		return nil, err
	}

	return leafCert, nil
}

func getMatchingMDSEntry(payload *MetadataBlobPayload, targetAAGUID string) (*MetadataBlobEntry, error) {
	result := make([]MetadataBlobEntry, 0)

	for _, entry := range payload.Entries {
		if entry.AAGUID == targetAAGUID {
			result = append(result, entry)
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("failed to find matching entry for AAGUID %s", targetAAGUID)
	}

	if len(result) != 1 {
		return nil, fmt.Errorf("found multiple matching entries for AAGUID %s", targetAAGUID)
	}

	return &result[0], nil
}
