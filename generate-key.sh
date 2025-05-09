set -e

NAME=$1
if [ -z "$NAME" ]; then
  >&2 echo "name of ssh key must be specified: generate-key <key name>"
  exit 1
fi

CHALLENGE_FILENAME="${NAME}_challenge.bin"
if [ -f "$CHALLENGE_FILENAME" ]; then
    echo "the file '${CHALLENGE_FILENAME}' already exists; aborting..."
    exit 1
fi

if ! command -v openssl 2>&1 >/dev/null
then
    echo "openssl is not available; it's used to create '${CHALLENGE_FILENAME}'"
    echo "alternative: dd if=/dev/random of=${CHALLENGE_FILENAME} bs=1 count=32"
    exit 1
fi

openssl rand 32 > "${CHALLENGE_FILENAME}"

# Other relevant options
# -t ecdsa-sk; use ECDSA with P-256 rather than Ed25519
# -O application; overwrite default "ssh:", must start with "ssh:", rpIdHash is the SHA-256 of this value
# -O no-touch-required; disable requiring touching the security key when using the key (required by default)
# -O verify-required; require e.g. a PIN when using the key (not required by default)
# -O resident; store the key in hardware rather than using non-resident keys (non-resident by default)
# -O user; overwrite the empty default username for resident keys
# -N ""; use empty private key passphrase
ssh-keygen -t ed25519-sk -O challenge="${CHALLENGE_FILENAME}" -O write-attestation="${NAME}_attestation.bin" -f "./${NAME}"
