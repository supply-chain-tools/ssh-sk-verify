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
MIIFWjCCA0KgAwIBAgISEdK7udcjGJ5AXwqdLdDfJWfRMA0GCSqGSIb3DQEBDAUA
MEYxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMRwwGgYD
VQQDExNHbG9iYWxTaWduIFJvb3QgUjQ2MB4XDTE5MDMyMDAwMDAwMFoXDTQ2MDMy
MDAwMDAwMFowRjELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYt
c2ExHDAaBgNVBAMTE0dsb2JhbFNpZ24gUm9vdCBSNDYwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQCsrHQy6LNl5brtQyYdpokNRbopiLKkHWPd08EsCVeJ
OaFV6Wc0dwxu5FUdUiXSE2te4R2pt32JMl8Nnp8semNgQB+msLZ4j5lUlghYruQG
vGIFAha/r6gjA7aUD7xubMLL1aa7DOn2wQL7Id5m3RerdELv8HQvJfTqa1VbkNud
316HCkD7rRlr+/fKYIje2sGP1q7Vf9Q8g+7XFkyDRTNrJ9CG0Bwta/OrffGFqfUo
0q3v84RLHIf8E6M6cqJaESvWJ3En7YEtbWaBkoe0G1h6zD8K+kZPTXhc+CtI4wSE
y132tGqzZfxCnlEmIyDLPRT5ge1lFgBPGmSXZgjPjHvjK8Cd+RTyG/FWaha/LIWF
zXg4mutCagI0GIMXTpRW+LaCtfOW3T3zvn8gdz57GSNrLNRyc0NXfeD412lPFzYE
+cCQYDdF3uYM2HSNrpyibXRdQr4G9dlkbgIQrImwTDsHTUB+JMWKmIJ5jqSngiCN
I/onccnfxkF0oE32kRbcRoxfKWMxWXEM2G/CtjJ9++ZdU6Z+Ffy7dXxd7Pj2Fxzs
x2sZy/N78CsHpdlseVR2bJ0cpm4O6XkMqCNqo98bMDGfsVR7/mrLZqrcZdCinkqa
ByFrgY/bxFn63iLABJzjqls2k+g9vXqhnQt2sQvHnf3PmKgGwvgqo6GDoLclcqUC
4wIDAQABo0IwQDAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNV
HQ4EFgQUA1yrc4GHqMywptWU4jaWSf8FmSwwDQYJKoZIhvcNAQEMBQADggIBAHx4
7PYCLLtbfpIrXTncvtgdokIzTfnvpCo7RGkerNlFo048p9gkUbJUHJNOxO97k4Vg
JuoJSOD1u8fpaNK7ajFxzHmuEajwmf3lH7wvqMxX63bEIaZHU1VNaL8FpO7XJqti
2kM3S+LGteWygxk6x9PbTZ4IevPuzz5i+6zoYMzRx6Fcg0XERczzF2sUyQQCPtIk
pnnpHs6i58FZFZ8d4kuaPp92CC1r2LpXFNqD6v6MVenQTqnMdzGxRBF6XLE+0xRF
FRhiJBPSy03OXIPBNvIQtQ6IbbjhVp+J3pZmOUdkLG5NrmJ7v2B0GbhWrJKsFjLt
rWhV/pi60zTe9Mlhww6G9kuEYO4Ne7UyWHmRVSyBQ7N0H3qqJZ4d16GLuc1CLgSk
ZoNNiTW2bKg2SnkheCLQQrzRQDGQob4Ez8pn7fXwgNNgyYMqIgXQBztSvwyeqiv5
u+YfjyW6hY0XHgL+XVAEV8/+LbzvXMAaq7afJMbfc2hIkCwU9D9SGuTSyxTDYWnP
4vkYxboznxSjBF25cfe1lNj2M8FawTSLfJvdkzrnE6JwYZ+vj+vYxXX4M2bUdGc6
N3ec592kD3ZDZopD8p/7DEJ4Y9HiD2971KE9dJeFt0g5QdYg/NA6s/rob8SKunE3
vouXsXgxT7PntgMTzlSdriVZzH81Xwj3QEUxeCp6
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

	if len(chain) != 1 || len(chain[0]) != 3 {
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

	if len(header.X5C) != 3 {
		return nil, fmt.Errorf("expected 3 x5c certificates, got %d", len(header.X5C))
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
