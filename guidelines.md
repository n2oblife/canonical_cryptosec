# Security Hardening Server: Architecture & Implementation Notes

*Notes:
This file was used as the initial notes to help during this task.
Some things ended up varying a bit, but the main ideas are here.*

## 1. Technical Specifications & Protocol

### Cryptography & PKI

* **Standards:** FIPS 140-3 aligned. OpenSSL 3.x (`EVP_DigestVerify`).
* **Algorithm:** ECDSA over NIST P-256 (`prime256v1`) with SHA-256.
* **Certificate Store:** Server loads all valid `.pem`/`.crt` files from a target directory (e.g., `-c ./certs/trusted`) into an `X509_STORE`.
* **Policy Enforcement (EKU):** Certificates must contain the `codeSigning` Extended Key Usage extension (OID `1.3.6.1.5.5.7.3.3` / `NID_code_sign`). Certificates lacking this, or those out of bounds (`X509_cmp_current_time`), are ignored.

### IPC & Wire Protocol

* **Transports:** Dual support for UNIX Domain Sockets (`-u <path>`) and TCP (`-p <port>`).
* **Client Handshake:** Client connects, streams the raw payload, and signals EOF via TCP/UDS half-close (`shutdown(sock_fd, SHUT_WR)`).
* **Payload Format:**
* Line 1: `# SIG: <Base64_DER_Encoded_ECDSA_Signature>`
* Line 2 to EOF: The exact bash script payload (this exact byte sequence is hashed and verified).


* **Server Responses:**
* Success: `[REQ-<timestamp>-<pid>] STATUS: APPROVED` (followed by execution stdout/stderr stream).
* Failure: `[REQ-<timestamp>-<pid>] STATUS: REJECTED (Reason: ...)`



### Execution Engine & Sandboxing

* **Memory-Only Execution:** Zero disk I/O. Payload feeds directly into `/bin/bash -s` via unidirectional UNIX pipes.
* **Environment Hygiene:** Scrubbed via `clearenv()`. Minimal safe path established (`PATH=/usr/bin:/bin`). Memory buffers scrubbed with `OPENSSL_cleanse()`.
* **Resource Limits:** Mitigates DoS (fork bombs, memory exhaustion, infinite loops) using OS-level `setrlimit`:
* `RLIMIT_CPU`: Execution time bounds.
* `RLIMIT_AS`: Maximum memory footprint.
* `RLIMIT_NPROC`: Maximum child processes.



---

## 2. Implementation Phases

**Phase 1: Project Scaffolding & PKI Setup**

* Initialize Git and base directory structure (`src/`, `certs/`, `scripts/`, `tests/`, `include/`).
* Configure strict `Makefile` (`-Wall -Wextra -Werror -pedantic -D_FORTIFY_SOURCE=2 -fPIE`).
* Create `gen_pki.sh` to generate a local CA, a valid Code Signing cert, a cert lacking the EKU, an expired cert, and an untrusted self-signed cert.

**Phase 2: Core Server & Networking**

* Implement `getopt` CLI parsing (`-u`, `-p`, `-c`).
* Set up POSIX socket listeners (AF_UNIX and AF_INET with `SO_REUSEADDR`).
* Implement a pre-fork concurrency model to dispatch dedicated child processes per incoming connection, isolating faults.

**Phase 3: Payload Processing & Cryptography**

* Read incoming socket stream into a bounded heap buffer (preventing overflow).
* Parse and strip Line 1 (Signature). Retain the remainder as the verification payload.
* Implement OpenSSL directory scanning to populate the `X509_STORE`.
* Verify the payload signature against the loaded public keys.

**Phase 4: Secure Sandbox Integration**

* If rejected, send error over IPC, wipe buffers, and exit child process.
* If approved, create `pipe()`, `fork()`, and `dup2()` to map pipes to STDIN/STDOUT/STDERR.
* Execute `/bin/bash -s`. The parent streams the payload into the pipe and concurrently reads the output pipe, forwarding it to the client socket.
* Parent parses `waitpid()` status (`WIFEXITED` / `WIFSIGNALED`) to return a clean exit code or kernel kill reason (e.g., SIGKILL).

**Phase 5: Testing, CI/CD, & Documentation**

* Write the Python `pytest` integration suite targeting socket boundaries and crypto downgrades.
* Implement `lcov`/`gcov` coverage tracking in the `Makefile` (target: 100% C coverage).
* Add automated payload generation/testing CLI targets (`make trigger`).
* Write CI pipeline files (`.github/workflows/ci.yml`, `.gitlab-ci.yml`) and `README.md`.

---

## 3. Project File Tree (initial)

```text
canonical_cryptosec/
├── Makefile                 # Build system, CLI runners, and coverage tools
├── README.md                # Architecture, build, and usage documentation
├── certs/                   # Auto-generated PKI directory
│   ├── keys/                # Private keys
│   └── trusted/             # Valid certs loaded by the server
├── scripts/
│   └── gen_pki.sh           # OpenSSL script to generate CA and test certs
├── src/
│   ├── main.c               # CLI flags, daemon socket setup, fork dispatcher
│   ├── crypto.c             # X509 loader, EKU validation, ECDSA verification
│   └── executor.c           # Sandbox limits, pipes, and bash execution
├── include/
│   ├── server.h             
│   ├── crypto.h             
│   └── executor.h           
└── tests/
    └── test_suite.py        # Automated Pytest suite
```

---

## 4. Quality Assurance & Test Matrix

The following scenarios are automated in `tests/test_suite.py` to prove security boundary enforcement:

| # | Test Scenario | Expected Status | Enforcement Layer |
| --- | --- | --- | --- |
| **T1** | Valid script signed by authorized Code Signing cert | `STATUS: APPROVED` | Cryptography (ECDSA) |
| **T2** | Tampered script (payload modified after signing) | `STATUS: REJECTED` | Cryptography (Hash mismatch) |
| **T3** | Valid signature, but cert lacks `codeSigning` EKU | `STATUS: REJECTED` | PKI Policy (X.509 extensions) |
| **T4** | Valid signature signed by untrusted self-signed cert | `STATUS: REJECTED` | PKI Policy (Not in store) |
| **T5** | Malformed Line 1 (missing `# SIG:` or bad Base64) | `STATUS: REJECTED` | Protocol Parser |
| **T6** | Expired code-signing certificate | `STATUS: REJECTED` | PKI Policy (Time bounds) |
| **T7** | DoS Protection: Infinite loop script | `EXIT CODE: -1` | OS Sandbox (`RLIMIT_CPU`) |
| **T8** | Concurrency: Multiple simultaneous client connections | `STATUS: APPROVED` | Network (Pre-fork isolation) |