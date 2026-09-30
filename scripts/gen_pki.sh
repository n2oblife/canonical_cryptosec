#!/bin/bash
set -e

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    echo "Usage: $0"
    echo "Generates the test PKI environment for the Security Hardening Server."
    echo "Creates a Root CA, valid/invalid code signing certificates, and private keys."
    echo "Outputs are automatically placed in the canonical_cryptosec/certs/ directory."
    exit 0
fi

# Dynamically find the project root regardless of where the script is executed
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( dirname "$SCRIPT_DIR" )"
CERTS_DIR="$PROJECT_ROOT/certs"
TRUSTED_DIR="$CERTS_DIR/trusted"
KEYS_DIR="$CERTS_DIR/keys"

mkdir -p "$TRUSTED_DIR" "$KEYS_DIR"

echo "[*] Generating Test PKI (ECDSA prime256v1) in: $CERTS_DIR"

# 1. Generate Root CA
echo " -> Generating Root CA..."
openssl ecparam -name prime256v1 -genkey -noout -out "$KEYS_DIR/rootCA.key"
openssl req -x509 -new -nodes -key "$KEYS_DIR/rootCA.key" -sha256 -days 3650 \
    -out "$CERTS_DIR/rootCA.crt" -subj "/CN=Canonical Test Root CA" 2>/dev/null

# 2. Generate Valid Code Signing Certificate
echo " -> Generating Valid Code Signing Cert..."
openssl ecparam -name prime256v1 -genkey -noout -out "$KEYS_DIR/valid_codesign.key"
openssl req -new -key "$KEYS_DIR/valid_codesign.key" -out "$CERTS_DIR/valid_codesign.csr" \
    -subj "/CN=Valid Code Signer" 2>/dev/null
echo "extendedKeyUsage = codeSigning" > "$CERTS_DIR/codesign.ext"
openssl x509 -req -in "$CERTS_DIR/valid_codesign.csr" -CA "$CERTS_DIR/rootCA.crt" \
    -CAkey "$KEYS_DIR/rootCA.key" -CAcreateserial -out "$TRUSTED_DIR/valid_codesign.crt" \
    -days 365 -sha256 -extfile "$CERTS_DIR/codesign.ext" 2>/dev/null

# 3. Generate Invalid Certificate (Missing codeSigning EKU)
echo " -> Generating Cert with NO codeSigning EKU..."
openssl ecparam -name prime256v1 -genkey -noout -out "$KEYS_DIR/invalid_no_eku.key"
openssl req -new -key "$KEYS_DIR/invalid_no_eku.key" -out "$CERTS_DIR/invalid_no_eku.csr" \
    -subj "/CN=Invalid Missing EKU" 2>/dev/null
openssl x509 -req -in "$CERTS_DIR/invalid_no_eku.csr" -CA "$CERTS_DIR/rootCA.crt" \
    -CAkey "$KEYS_DIR/rootCA.key" -CAcreateserial -out "$TRUSTED_DIR/invalid_no_eku.crt" \
    -days 365 -sha256 2>/dev/null

# 4. Generate Untrusted Code Signing Certificate (Self-Signed)
echo " -> Generating Untrusted (Self-Signed) Code Signing Cert..."
openssl ecparam -name prime256v1 -genkey -noout -out "$KEYS_DIR/untrusted.key"
openssl req -x509 -new -nodes -key "$KEYS_DIR/untrusted.key" -sha256 -days 365 \
    -out "$CERTS_DIR/untrusted.crt" -subj "/CN=Untrusted Self-Signed Signer" \
    -addext "extendedKeyUsage = codeSigning" 2>/dev/null

# Clean up temp files
rm -f "$CERTS_DIR"/*.csr "$CERTS_DIR"/*.ext "$CERTS_DIR"/*.srl

echo "[+] PKI Generation Complete."
echo "[+] Trusted certs to be loaded by the C server are in: $TRUSTED_DIR"