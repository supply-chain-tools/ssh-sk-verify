package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/supply-chain-tools/ssh-sk-verify/attest"
	"log/slog"
	"os"
	"slices"
)

const usage = `SYNOPSIS
    ssh-sk-verify [OPTIONS]

OPTIONS
        --public-key
            Path to file containing SSH public key.

        --attestation
            Path to SSH attestation file.

        --challenge
            Path to file containing the challenge used when generating the attestation.

        --mds
            Path to FIDO Metadata Service file.

        --json
            Output JSON.

Example
    $ ssh-sk-verify --public-key id_ed25519.pub --attestation attestation.bin --challenge challenge.bin --mds mds.jwt`

type JSONOutput struct {
	MDSLegalHeader               string `json:"mdsLegalHeader"`
	MetadataStatementLegalHeader string `json:"metadataStatementLegalHeader"`
	AuthenticatorDescription     string `json:"authenticatorDescription"`
	AAGUID                       string `json:"aaguid"`
	SSHPublicKeyType             string `json:"sshPublicKeyType"`
	SSHPublicKeyFingerprint      string `json:"sshPublicKeyFingerprint"`
	Application                  string `json:"application"`
}

func main() {
	attestationData, outputJSON, err := processInput()
	if err != nil {
		println("Failed to get input data:", err.Error())
		os.Exit(1)
	}

	if len(attestationData.Challenge) == 0 {
		slog.Debug("input",
			"public key length", len(attestationData.PublicKey),
			"attestation length", len(attestationData.Attestation),
			"challenge length", len(attestationData.Challenge),
			"mds length", len(attestationData.MDS))
	}

	result, err := attest.Verify(attestationData)
	if err != nil {
		println("Failed to verify:", err.Error())
		os.Exit(1)
	}

	if outputJSON {
		output := JSONOutput{
			MDSLegalHeader:               result.MDSLegalHeader,
			MetadataStatementLegalHeader: result.MetadataBlobEntry.MetadataStatement.LegalHeader,
			AAGUID:                       result.MetadataBlobEntry.AAGUID,
			AuthenticatorDescription:     result.MetadataBlobEntry.MetadataStatement.Description,
			SSHPublicKeyType:             result.SSHPublicKey.KeyType,
			SSHPublicKeyFingerprint:      result.SSHPublicKey.Fingerprint,
			Application:                  result.SSHPublicKey.Application,
		}
		o, err := json.Marshal(output)
		if err != nil {
			println("Failed to marshal output:", err.Error())
			os.Exit(1)
		}

		fmt.Println(string(o))
	} else {
		fmt.Printf("MDS Legal Header: %s\n", result.MetadataBlobEntry.MetadataStatement.LegalHeader)
		fmt.Printf("Metadata Statement Legal Header: %s\n\n", result.MetadataBlobEntry.MetadataStatement.LegalHeader)
		fmt.Printf("%s\n", result.MetadataBlobEntry.MetadataStatement.Description)
		fmt.Printf("  aaguid: %s\n", result.MetadataBlobEntry.AAGUID)
		fmt.Printf("  certificate chain:\n")
		for _, cert := range slices.Backward(result.CertificateChain) {
			fmt.Printf("    %s [%s]\n", cert.Subject.CommonName, cert.SerialNumber)
		}

		fmt.Printf("\n%s\n", result.SSHPublicKey.KeyType)
		fmt.Printf("  fingerprint: %s\n", result.SSHPublicKey.Fingerprint)
		fmt.Printf("  application: %s\n", result.SSHPublicKey.Application)
	}
}

func processInput() (*attest.AttestationData, bool, error) {
	flags := flag.NewFlagSet("all", flag.ExitOnError)
	var help, h, debugMode, jsonOutput bool
	var publicKeyPath, attestationPath, challengePath, mdsPath string

	const publicKeyName = "public-key"
	const attestationName = "attestation"
	const challengeName = "challenge"
	const mdsName = "mds"

	flags.BoolVar(&help, "help", false, "")
	flags.BoolVar(&h, "h", false, "")
	flags.BoolVar(&debugMode, "debug", false, "")
	flags.BoolVar(&jsonOutput, "json", false, "")
	flags.StringVar(&publicKeyPath, publicKeyName, "", "")
	flags.StringVar(&attestationPath, attestationName, "", "")
	flags.StringVar(&challengePath, challengeName, "", "")
	flags.StringVar(&mdsPath, mdsName, "", "")

	err := flags.Parse(os.Args[1:])
	if err != nil || help || h {
		fmt.Println(usage)
		os.Exit(1)
	}

	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}

	if debugMode {
		opts.Level = slog.LevelDebug
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, opts))
	slog.SetDefault(logger)

	publicKey, err := readFromFile(publicKeyName, publicKeyPath)
	if err != nil {
		return nil, false, err
	}

	attestation, err := readFromFile(attestationName, attestationPath)
	if err != nil {
		return nil, false, err
	}

	challenge, err := readFromFile(challengeName, challengePath)
	if err != nil {
		return nil, false, err
	}

	mds, err := readFromFile(mdsName, mdsPath)
	if err != nil {
		return nil, false, err
	}

	return &attest.AttestationData{
		PublicKey:   publicKey,
		Attestation: attestation,
		Challenge:   challenge,
		MDS:         mds,
	}, jsonOutput, nil
}

func readFromFile(name string, path string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("--%s <path> is required", name)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return data, nil
}
