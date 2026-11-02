# Chapter 1: The Big Picture

## 1.1 What problem does this solve?

"Only run code that an authorised signer approved." This is the same idea as:
- **Secure Boot / shim / MOK** (only boot signed kernels),
- **Kernel module signing** (`CONFIG_MODULE_SIG`),
- **APT repository signing** (`Release.gpg`, `InRelease`),
- **Snap assertions** (snaps are signed by the store; `snapd` verifies before mounting),
- **IMA/EVM appraisal** (the kernel refuses to exec files whose signature xattr doesn't verify).

Your daemon is a small **remote execution gate** with a **code-signing policy**. Make this link to
real Ubuntu mechanisms in the interview. It shows you understand *why* the exercise exists.

## 1.2 Components (3 modules + tooling)

```
                 ┌──────────────────────────── crypto_server (C11, links libcrypto) ───────────────────────────┐
                 │                                                                                             │
  CLI flags ───▶ │  main.c                     crypto.c                         executor.c                     │
  -u/-p/-c       │  ───────                    ─────────                        ───────────                    │
                 │  getopt, signals            crypto_init(dir)                 execute_script(fd, id, p, n)    │
                 │  create_listener()          ├ readdir → PEM_read_X509        ├ pipe() x2                     │
                 │  accept loop + fork()       ├ is_cert_valid_for_codesigning  ├ fork()                        │
                 │  handle_client()            │   time bounds + EKU            │  child: dup2, setrlimit,      │
                 │   read ≤1MB, parse line 1   └ STACK_OF(X509)                 │         clearenv, execl bash  │
                 │   call verify ────────────▶ crypto_verify_signature()        │  parent: write script, stream │
                 │   call execute ───────────────────────────────────────────▶  │          output, waitpid      │
                 │                             base64 → EVP_DigestVerify*       └ footer w/ exit code / signal  │
                 └─────────────────────────────────────────────────────────────────────────────────────────────┘
  Headers: server.h (limits, status enum, config struct) · crypto.h (opaque ctx API) · executor.h (rlimit profiles)

  Tooling: scripts/gen_pki.sh (test PKI) · scripts/sign_script.sh (client-side signer) · Makefile · tests/*.py · CI yaml
```

**Dependency direction** (good to say to Paul): `main` depends on `crypto` and `executor`;
`crypto` and `executor` don't know about each other or about sockets (well, almost:
`execute_script` takes a raw `client_fd`, a small leak of transport into the executor). `crypto.h`
uses an **opaque type** (`typedef struct crypto_ctx_t crypto_ctx_t;`), so callers can't touch
OpenSSL internals. That's information hiding in C.

## 1.3 Lifecycle of one request

```
Client                          Daemon (PID D)                Handler child (PID H)            Sandbox (PID B: bash -s)
  │  connect()  ───────────────▶ accept() → client_fd
  │                              fork() ───────────────────▶ close(server_fd)
  │                              close(client_fd)            signal(SIGCHLD, SIG_DFL)
  │  send "# SIG: ...\n<script>"                              read() loop until EOF or 1 MiB
  │  shutdown(SHUT_WR) ── EOF ─────────────────────────────▶ split at first '\n'
  │                                                           check "# SIG: " prefix, strip '\r'
  │                                                           crypto_verify_signature()
  │                                                             base64 decode → DER sig
  │                                                             for each trusted cert: EVP_DigestVerify(SHA-256)
  │  ◀── "[REQ-..] STATUS: REJECTED (...)" ── if fail ─────── write, cleanse, exit
  │  ◀── "[REQ-..] STATUS: APPROVED\n--- OUTPUT START ---" ── execute_script()
  │                                                           pipe(in), pipe(out), fork() ───▶ dup2 pipes → 0,1,2
  │                                                                                           setrlimit CPU/AS/NPROC
  │                                                                                           clearenv; PATH=...
  │                                                           write script → pipe_in          execl("/bin/bash","-s")
  │                                                           close(pipe_in) = EOF            reads & runs script
  │  ◀── streamed output ──────────────────────────────────── read(pipe_out) → write(client)  ◀── stdout/stderr
  │                                                           waitpid(B) → WIFEXITED/WIFSIGNALED
  │  ◀── "--- OUTPUT END (EXIT CODE: n) ---" ──────────────── close, cleanse, exit
  │  recv() returns 0 (EOF)                                   D's SIGCHLD handler reaps H
```

Things to say about this diagram:
- **Why the half-close (`SHUT_WR`)?** There's no length prefix in the protocol, so the server needs
  an "end of request" signal. A half-close sends a TCP FIN (or the UDS equivalent) so the server's
  `read()` returns 0. The client's *read* side stays open for the response. This is also why
  `nc` can be awkward and `socat` works.
- **Why two forks?** The first fork isolates each *connection* (a crash or parse bug only kills
  one handler). The second creates the *sandbox* process: rlimits and `exec` replace the process
  image, and the handler must survive to stream the output and collect the exit status.
- **Three process roles**: daemon (long-lived, holds the cert store), handler (one per
  connection, does parsing and crypto), sandbox (runs untrusted-but-signed code).

## 1.4 Trust model: be precise about this

| Question | Answer in *this* code |
|---|---|
| Who is trusted? | Any certificate file in the `-c` directory that is (a) currently within notBefore/notAfter and (b) has the `codeSigning` EKU. |
| Is the chain verified up to `rootCA.crt`? | **No.** `rootCA.crt` is never loaded by the server. There's no `X509_STORE` and no `X509_verify_cert`. Trust = **"the leaf cert is present in a directory"**, effectively *certificate pinning*. |
| Revocation? | None (no CRL, no OCSP). Removing a file and restarting is the revocation mechanism. |
| When are time bounds checked? | **Once, at startup.** A cert that expires while the daemon runs stays trusted. |
| What exactly is signed? | The exact bytes from after the first `\n` to EOF. The signature line is not covered. |
| Replay protection? | None. A signed script can be replayed forever, by anyone who can reach the socket. |
| Who can reach the socket? | UDS: anyone with write permission on the socket file (umask-dependent). TCP: **everyone on the network** (`INADDR_ANY`, plaintext). |
| Who does the script run as? | Whoever launched the daemon. There's no privilege drop. |

**The honest one-liner:** "Authenticity of the script is strong: ECDSA-P256 over SHA-256 with
pinned keys. Authorisation of the *caller*, freshness, confidentiality of the output, and
isolation of execution are weak or absent."

## 1.5 Security controls inventory (map each to a threat)

| Threat | Control | Where | Effectiveness |
|---|---|---|---|
| Run unsigned/modified script | ECDSA verify over exact bytes | [crypto.c:177-204](../src/crypto.c#L177-L204) | Strong |
| Signer not authorised for code signing | EKU `codeSigning` filter | [crypto.c:38-55](../src/crypto.c#L38-L55) | OK (load-time only) |
| Expired / not-yet-valid signer | Time check | [crypto.c:28-36](../src/crypto.c#L28-L36) | Startup only |
| Hash downgrade (SHA-1) | Verifier pins `EVP_sha256()` | [crypto.c:188](../src/crypto.c#L188) | Strong (the verifier, not the attacker, chooses the hash) |
| Huge payload memory DoS | 1 MiB cap | [main.c:124-127](../src/main.c#L124-L127) | OK, but the client gets no error message |
| CPU infinite loop | `RLIMIT_CPU` → SIGKILL | [executor.c:93-94](../src/executor.c#L93-L94) | CPU time only, **not wall-clock** |
| Memory bomb | `RLIMIT_AS` | [executor.c:97-98](../src/executor.c#L97-L98) | Allocations fail (bash exits 2); not a kill |
| Fork bomb | `RLIMIT_NPROC` | [executor.c:101-102](../src/executor.c#L101-L102) | Per-**UID** counter, not per sandbox; ignored for root |
| Env injection (`LD_PRELOAD`, `BASH_ENV`…) | `clearenv()` + fixed PATH | [executor.c:105-106](../src/executor.c#L105-L106) | Good |
| Script on disk tampered/left behind | `bash -s` via pipe | [executor.c:111](../src/executor.c#L111) | Good intent; introduces a deadlock (ch. 6) |
| Secrets left in memory | `OPENSSL_cleanse` | [main.c:189](../src/main.c#L189), [crypto.c:207](../src/crypto.c#L207) | Mostly cosmetic (signatures aren't secret) |
| Exploit hardening of the daemon itself | FORTIFY, stack protector, PIE, RELRO/now | [Makefile:57-69](../Makefile#L57-L69) | Good baseline |

## Questions you must be able to answer
1. Draw the process tree during a request. Which process holds the listening socket? Which holds `client_fd`?
2. Why does the client need `shutdown(SHUT_WR)` and not `close()`?
3. What exactly does "trusted" mean in this server? What would change with `X509_verify_cert`?
4. Which bytes are signed? Why must the signer and the verifier agree *byte-for-byte* (think CRLF)?
5. Name three threats the design does **not** address.
