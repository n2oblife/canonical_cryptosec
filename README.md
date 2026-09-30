# canonical_cryptosec - Cryptographic Bash Script Execution Server

A secure, concurrent C daemon that verifies bash script signatures via X.509 certificates before executing them in an isolated, memory-only sandbox. 

This project was built to satisfy the Canonical Linux Cryptography and Security Engineer assessment requirements, including all stretch goals (concurrent execution, multi-certificate directory scanning, and X.509 Extended Key Usage validation).

## Architecture

* **Language:** C11 (`gnu11`), relying on strict POSIX systems programming.
* **Cryptography & PKI:** 
  * OpenSSL 3.x (`libssl-dev`) using ECDSA over NIST P-256 (`prime256v1`) with SHA-256. 
  * Enforces strict X.509 trust boundaries: dynamically loads multi-certificate directories, verifies cryptographic time bounds, and strictly requires the `codeSigning` Extended Key Usage (EKU) policy.
* **Concurrency:** Pre-fork model. The main daemon accepts connections and forks dedicated child processes to handle validation and execution, allowing simultaneous requests and isolating execution faults.
* **Sandbox Defense-in-Depth:** 
  * Bash scripts are executed entirely in memory via `bash -s` using IPC pipes (zero disk I/O for payloads).
  * The environment is wiped using `clearenv()` and a restricted `PATH` is enforced.
  * System resources are constrained via `setrlimit` to prevent DoS attacks (fork bombs, CPU infinite loops, and memory leaks).
* **Deployment Profiles:** Implements modular C macros driven by the `Makefile` to differentiate between generous Developer limits (for testing) and ultra-strict Production limits (FIPS/Common Criteria alignment).

## Build Instructions

### Prerequisites

* GCC, Make, OpenSSL development headers, socat (if missing), Python 3 and lcov (for the test suite).

```bash
# Ubuntu
sudo apt-get install build-essential libssl-dev python3 python3-venv lcov socat
# Arch Linux
sudo pacman -S base-devel openssl python lcov socat
# Fedora / RHEL
sudo dnf install gcc make openssl-devel python3 lcov socat
```

### Compilation

The `Makefile` supports different profiles for development and production sandbox limits.

To build the default development binary and test on a standard machine:

```bash
make all

```

To build the production binary (enforces strict FIPS/Prod resource limits):

```bash
make prod

```

The compiled binary will be located at `build/bin/crypto_server`.

Here is the expanded section for your `README.md`. It seamlessly bridges starting the server with how to interact with it, highlighting your custom CLI tooling while preserving the underlying manual commands for transparency.

Replace your current **Running the Server** section with the following:

## Running the Server

The server requires a directory containing trusted X.509 certificates and an IPC transport method (either a UNIX Domain Socket or a TCP port). 

You can start the server quickly using the included Makefile targets. These targets will automatically compile the binary and generate the necessary test certificates if they do not already exist.

```bash
# Listen on a UNIX Domain Socket (/tmp/sec_server.sock)
make run-uds

# Listen on a TCP port (8080)
make run-tcp

```

*Note: If you prefer to run the binary manually or pass custom paths, the underlying command format is:*

```bash
./build/bin/crypto_server -c <path_to_certs_dir> [-u <uds_path> | -p <tcp_port>]

```

## Interacting with the Server (Client CLI)

To execute a script, it must be cryptographically signed with a trusted private key, formatted with the correct header, and sent over the IPC socket.

### The Automated Way (Makefile CLI)

The project includes a built-in testing CLI to make payload generation and transmission effortless. Open a second terminal while the server is running and use the following commands:

**1. Generate demo scripts**
You can create any bash file you fancy in the `test_scripts/` folder. Anyway, there are already scripts ready to test.

**2. Send a payload**
The `trigger` target handles signing, Base64 encoding, header prepending, and network transmission in one step.

```bash
# Send the hello world script via UDS (default)
make trigger SCRIPT=hello_world

# Send the Denial of Service script via TCP
make trigger SCRIPT=dos_script PROTO=tcp

```

### The Manual Way (Under the Hood)

If you prefer to manually craft and send the payloads to verify the cryptography and network boundaries without relying on the Makefile automation, you can use standard Linux tools (`openssl`, `base64`, and `socat`).

**1. Generate the raw SHA-256 ECDSA signature:**
```bash
openssl dgst -sha256 -sign certs/keys/valid_codesign.key -out raw.sig test_scripts/hello_world.sh

```

**2. Base64 encode it and prepend the required header:**

```bash
B64_SIG=$(base64 -w 0 raw.sig)
echo "# SIG: $B64_SIG" > payload.txt
cat test_scripts/hello_world.sh >> payload.txt

```

> **Note:** You can bypass manual steps 1 and 2 by using the included bash utility which strictly handles the cryptography and formatting:
> `./scripts/sign_script.sh certs/keys/valid_codesign.key test_scripts/hello_world.sh payload.txt`

**3. Transmit the payload to the server:**
To send the payload, we use `socat`. Unlike standard Netcat (`nc`), `socat` natively and reliably handles the EOF (TCP Half-Close) required to trigger the server's execution phase while keeping the read-stream open to capture the returning `STDOUT`/`STDERR`.

```bash
# For UNIX Domain Sockets
socat - UNIX-CONNECT:/tmp/sec_server.sock < payload.txt

# For TCP Sockets
socat - TCP4:127.0.0.1:8080 < payload.txt

```


## Communication Protocol (IPC)

Clients interact with the server via standard TCP or UDS streams. No proprietary binary framing is required. While compatible with any tool that can write to a socket, we strongly recommend `socat` over `nc` (Netcat), as `socat` reliably handles the EOF/half-close signal natively across all Linux distributions.

### Client Request
1. The client opens a connection to the UDS or TCP socket.
2. The client streams the payload. The first line must be the signature header formatted exactly as:
   `# SIG: <Base64_DER_Encoded_ECDSA_Signature>`
3. The rest of the payload from Line 2 to EOF is the exact bash script to be executed.
4. The client signals the end of transmission using a socket half-close (`shutdown(SHUT_WR)`). This explicitly tells the server to stop reading and begin cryptographic verification, while keeping the client's read-stream open to receive the execution output.


### Server Response & Status Codes

Every request is assigned a unique Request ID for concurrent log tracking.

**On Success:**
The server responds with an `APPROVED` status, executes the script, and streams `STDOUT` and `STDERR` back to the client in real-time, appended with the bash exit code.

```text
[REQ-1727632800-4821] STATUS: APPROVED
--- OUTPUT START ---
<standard output and error from bash>
--- OUTPUT END (EXIT CODE: 0) ---

```

**On Failure:**
The server responds with a `REJECTED` status and a specific reason, then terminates the connection without executing the script.

```text
[REQ-1727632800-4822] STATUS: REJECTED (Reason: Cryptographic signature verification failed)

```

## Test Suite & Code Coverage

The project includes an extensive automated integration test suite written in Python (`pytest`). The suite provisions adversarial certificates, attempts cryptographic downgrade attacks, and tests process boundaries.

To run the test suite and generate a C code coverage report (`lcov`):

```bash
# Set up a python virtual environment and install test dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run the tests and generate the coverage report
make coverage

```

The HTML coverage report will be generated in `build/coverage/report/index.html`.


## Project File Tree

```text
canonical_cryptosec/
├── Makefile                 # Build system, CLI runners, and coverage tools
├── README.md                # Architecture, build, and usage documentation
├── requirements.txt         # Python test dependencies (pytest, cryptography)
├── guidelines.md            # Internal architecture blueprint and test matrix
├── build/                   # Compiled binaries, objects, and coverage HTML (auto-generated)
├── certs/                   # Auto-generated PKI directory (keys and trusted certs)
├── include/                 # C Header definitions
│   ├── crypto.h             
│   ├── executor.h           
│   └── server.h             
├── scripts/                 # Cryptography and environment utilities
│   ├── gen_pki.sh           # OpenSSL script to generate CA and test certs
│   └── sign_script.sh       # Standalone CLI tool to sign custom bash scripts
├── src/                     # Core C Source Code
│   ├── crypto.c             # X509 loader, EKU validation, ECDSA verification
│   ├── executor.c           # Sandbox limits, pipes, and bash execution engine
│   └── main.c               # CLI flags, daemon UDS/TCP socket setup, fork dispatcher
├── test_scripts/            # Sample payloads for manual and automated testing
│   ├── dos.sh               # Infinite loop payload to test CPU/Memory sandbox limits
│   └── hello_world.sh       # Standard execution payload
└── tests/                   # Modular Python integration test suite
    ├── conftest.py          # Pytest fixtures and environment setup
    ├── helpers.py           # Shared socket and network utility functions
    ├── test_crypto.py       # Cryptography, tampering, and downgrade attack tests
    ├── test_execution.py    # IPC socket boundaries and standard execution tests
    ├── test_pki.py          # EKU validation, expiration, and trust store tests
    └── test_sandbox.py      # DoS limits, fork bombs, and kernel signal testing
```