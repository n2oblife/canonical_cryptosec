#!/bin/bash
set -e

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    echo "Usage: $0 <private_key_file> <input_script> <output_script>"
    echo ""
    echo "Signs an input bash script with the specified private key using ECDSA SHA-256."
    echo "The Base64 encoded signature is prepended to the output script as '# SIG: <base64>'."
    echo ""
    echo "Example from project root:"
    echo "  $0 certs/keys/valid_codesign.key tests/dummy.sh tests/signed_dummy.sh"
    exit 0
fi

if [ "$#" -ne 3 ]; then
    echo "Error: Invalid number of arguments."
    echo "Usage: $0 <private_key_file> <input_script> <output_script>"
    echo "Run '$0 -h' for more information."
    exit 1
fi

KEY_FILE="$1"
INPUT_FILE="$2"
OUTPUT_FILE="$3"

if [ ! -f "$KEY_FILE" ]; then
    echo "Error: Private key file '$KEY_FILE' not found."
    exit 1
fi

if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: Input script '$INPUT_FILE' not found."
    exit 1
fi

# 1. Sign the raw input file using OpenSSL (SHA-256 + ECDSA)
# The -w 0 prevents base64 from wrapping lines, ensuring the signature is on one single line
SIGNATURE=$(openssl dgst -sha256 -sign "$KEY_FILE" "$INPUT_FILE" | base64 -w 0)

# 2. Prepend the signature as a bash comment
echo "# SIG: $SIGNATURE" > "$OUTPUT_FILE"

# 3. Append the original script content
cat "$INPUT_FILE" >> "$OUTPUT_FILE"

echo "[+] Successfully signed $INPUT_FILE -> $OUTPUT_FILE"