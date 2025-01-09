# ssh-sk-attest

**This code is still considered experimental: it should not be relied on for important stuff and breaking changes are to be expected.**

OpenSSH `-sk` keys (security key) are backed by hardware using [WebAuthn](https://www.w3.org/TR/webauthn-2/). When generating `-sk` keys it's possible to also output
attestation information. The FIDO Alliance maintains the Metadata Service (MDS) which includes the Authenticator Attestation GUID (AAGUID) of each authenticator
along with its root certificates. This tool uses the MDS blob as a root of trust to validate the attestation data.

Generate an SSH key with attestation using [generate-key.sh](generate-key.sh). **By default the attestation data should be kept private.**
```bash
./generate-key.sh mykey
```

Download the FIDO Alliance Metadata Service blob ([MDS Legal Terms](https://fidoalliance.org/metadata-legal-terms/))
```sh
curl -L https://mds3.fidoalliance.org/ --output mds.jwt
```

Verify
```bash
ssh-sk-verify --public-key mykey.pub --attestation mykey_attestation.bin --challenge mykey_challenge.bin --mds mds.jwt
```
If successful it will output some metadata including a description of the authenticator, and it's AAGUID.