# Chapter 2: `src/main.c` line by line

File: [src/main.c](../src/main.c) (271 lines). Headers first: [include/server.h](../include/server.h).

---

## 2.0 `server.h`: shared vocabulary

```c
#define MAX_PAYLOAD_SIZE      (1024 * 1024)   // 1 MiB cap on the whole request
#define MAX_LINE_LENGTH       4096            // ⚠ never used anywhere
#define EXECUTION_TIMEOUT_SEC 10              // ⚠ never used anywhere (no wall-clock timeout exists!)
```
- The parentheses around `(1024 * 1024)` are macro hygiene: without them, `x / MAX_PAYLOAD_SIZE`
  would expand to `x / 1024 * 1024`.
- **Two dead constants.** `EXECUTION_TIMEOUT_SEC` suggests a wall-clock timeout that doesn't
  exist. A careful reviewer will spot this, and it ties into finding F3 (chapter 6).

```c
typedef enum { STATUS_OK = 0, STATUS_ERR_NETWORK, STATUS_ERR_BAD_PAYLOAD,
               STATUS_ERR_CRYPTO_FAIL, STATUS_ERR_EXEC_FAIL, STATUS_ERR_INTERNAL } server_status_t;
```
- A unified error vocabulary is good design. In practice only `OK`, `CRYPTO_FAIL` and `INTERNAL` are
  used, and `main.c` **ignores** the return value of `execute_script`.
- `start_server()` is declared at [server.h:30](../include/server.h#L30) but **never defined**. It
  compiles because nothing calls it. That's a leftover from the initial design.

`server_config_t` stores `const char*` pointers straight into `argv`. That works because `argv`
lives for the whole process.

---

## 2.1 Includes (L1-18)
- `<signal.h>`, `<sys/wait.h>`: signal handling and child reaping.
- `<sys/socket.h>`, `<sys/un.h>` (`sockaddr_un`), `<netinet/in.h>` (`sockaddr_in`, `INADDR_ANY`), `<arpa/inet.h>` (`htons`).
- `<openssl/crypto.h>`: only for `OPENSSL_cleanse`.

## 2.2 Global shutdown flag (L21)
```c
volatile sig_atomic_t keep_running = 1;
```
- `sig_atomic_t`: the only integer type that the C standard guarantees can be read and written
  atomically with respect to signal handlers.
- `volatile`: stops the compiler from caching it in a register across the loop, since the handler
  changes it "behind the compiler's back".
- It should be `static` (internal linkage). It's a minor point.

## 2.3 Signal handlers (L26-37)
```c
static void sigchld_handler(int s) {
    (void)s;                               // silence -Wunused-parameter (needed with -Werror)
    int saved_errno = errno;               // handlers must preserve errno: the interrupted code may be about to read it
    while (waitpid(-1, NULL, WNOHANG) > 0);// reap ALL finished children; signals coalesce, so one SIGCHLD may mean N exits
    errno = saved_errno;
}
```
**Key concepts:**
- **Zombie**: a child that exited but whose parent hasn't collected the status with `wait`. It
  holds a PID slot. Without reaping, a fork-per-connection server leaks zombies until PID
  exhaustion.
- **Why the `while` loop**: standard signals don't queue. If 3 children die at once you may get
  one SIGCHLD.
- **`WNOHANG`**: never block inside a handler.
- `waitpid` is **async-signal-safe** (see `man 7 signal-safety`). `printf` is not.

```c
static void sigterm_handler(int s) { (void)s; keep_running = 0; }
```
Async-signal-safe: it only sets a `sig_atomic_t` flag.

## 2.4 `setup_signals()` (L39-60)
```c
struct sigaction sa_chld;                 // ⚠ not zero-initialised; use = {0} or memset
sa_chld.sa_handler = sigchld_handler;
sigemptyset(&sa_chld.sa_mask);            // don't block extra signals while the handler runs
sa_chld.sa_flags = SA_RESTART;            // syscalls interrupted by SIGCHLD (accept) auto-restart
```
- `sigaction` is preferred over `signal()`: `signal()` semantics vary between historical System V
  and BSD behaviour, and `sigaction` lets you choose flags explicitly.
- **`SA_RESTART` for SIGCHLD but NOT for SIGTERM/SIGINT** (L52-54). This is the clever part: a
  child exiting must not break `accept()`, but a termination request *must*. Without
  `SA_RESTART`, `accept()` returns `-1/EINTR`, the loop re-checks `keep_running`, and exits.
- **Race condition** (good to mention yourself): if SIGTERM arrives *after* `while (keep_running)`
  is evaluated but *before* `accept()` blocks, the flag is set but `accept()` sleeps until the next
  client. Proper fixes: `signalfd` + `poll`, the **self-pipe trick**, or `ppoll`/`pselect` with
  signals blocked except during the wait.
- `signal(SIGPIPE, SIG_IGN)` (L59): if the client disconnects and we `write()` to the socket, the
  kernel would send SIGPIPE, whose default action kills the process. Ignoring it turns that into
  `write()` returning `-1/EPIPE`, which `write_all` handles. An alternative is
  `send(..., MSG_NOSIGNAL)`.
- `static void setup_signals()` with empty parens is an *old-style* declaration in C (it means
  "unspecified arguments"). Use `(void)`. `-Wstrict-prototypes` would catch it.

## 2.5 `create_listener()` (L65-104)

### UNIX domain socket branch
```c
sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
struct sockaddr_un addr; memset(&addr, 0, sizeof(addr));
addr.sun_family = AF_UNIX;
strncpy(addr.sun_path, config->uds_path, sizeof(addr.sun_path) - 1);   // ⚠ silent truncation at 107 chars
unlink(config->uds_path);                                              // remove stale socket from previous run
bind(...); 
```
- `sun_path` is **108 bytes** on Linux. `strncpy` with `-1` guarantees NUL termination (memset
  zeroed it), but **truncation is silent**. I reproduced this: a long path made the server bind to
  a *different, truncated* path and fail with a confusing "Address already in use". Fix: check
  `strlen(path) >= sizeof(addr.sun_path)` and refuse.
- `unlink()` before `bind()`: `bind` fails with `EADDRINUSE` if the file exists. ⚠ It unlinks
  *whatever* path the operator passes. Run as root with `-u /etc/something`, it deletes it. A
  hardened version checks `S_ISSOCK` with `lstat` first.
- **Permissions**: the socket file gets `0777 & ~umask` (I saw `srwxr-xr-x`). To *connect* to a
  UDS you need write permission on it, so here only the owner can connect. That's an accident of
  umask, not a decision. Production: `fchmod`/`chmod 0660` + a dedicated group, and/or check
  the peer with `getsockopt(SO_PEERCRED)` (gives pid/uid/gid of the client). **This is a great
  thing to mention**: UDS gives you kernel-authenticated caller identity for free.
- The socket file isn't removed on shutdown.

### TCP branch
```c
sockfd = socket(AF_INET, SOCK_STREAM, 0);
int opt = 1; setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
addr.sin_addr.s_addr = INADDR_ANY;                       // ⚠ listens on ALL interfaces
addr.sin_port = htons((uint16_t)atoi(config->tcp_port)); // ⚠ atoi: no validation ("abc" → 0 → random port)
```
- `SO_REUSEADDR`: lets you rebind immediately while old connections sit in `TIME_WAIT` after a
  restart.
- `htons`: host-to-network byte order (big-endian) for the 16-bit port.
- IPv4 only (`AF_INET`). Use `AF_INET6` with `IPV6_V6ONLY=0` for dual-stack, or `getaddrinfo`.
- **Plaintext, unauthenticated, all interfaces.** The script is signed, so it can't be modified.
  But anyone can replay a signed script, and the output (which may contain secrets) travels in
  clear text. Default to `127.0.0.1`, or wrap in TLS (mTLS gives caller authentication too).
- `strtol` with range checks would be the robust parsing.

### Both
```c
if (listen(sockfd, 10) < 0) return -1;   // backlog: completed connections waiting for accept()
```
If neither `-u` nor `-p` was given, `sockfd == -1` and `listen(-1)` fails. `main()` already
prevents that case. If both are given, UDS wins silently.

## 2.6 `handle_client()`: runs in the per-connection child (L109-193)

```c
char req_id[64];
snprintf(req_id, sizeof(req_id), "REQ-%ld-%d", (long)time(NULL), getpid());
```
Correlation ID = epoch seconds + PID of the handler. It's unique enough, because PIDs aren't reused
within the same second in practice. It's used in the response and is meant for logs (though the
logs don't actually include it; see chapter 6).

```c
unsigned char *buffer = malloc(MAX_PAYLOAD_SIZE + 1);   // heap: 1 MiB on the stack is risky (8 MiB default stack, but still)
```
`+1` reserves room for a NUL terminator so string functions are safe.

```c
while ((n = read(client_fd, buffer + total_read, MAX_PAYLOAD_SIZE - total_read)) > 0) {
    total_read += (size_t)n;
    if (total_read == MAX_PAYLOAD_SIZE) break;
}
```
- It reads until EOF (`n == 0`), error (`n < 0`), or the cap. The length argument shrinks each
  iteration, so it **can't overflow**. This is correct bounded reading.
- ⚠ **No timeout.** A client that connects and never sends EOF pins this child forever
  (slowloris). I opened 30 idle connections and got 31 children. Fix: `SO_RCVTIMEO`, `alarm()`,
  or `poll()` with a deadline.
- ⚠ **Hitting the cap is not reported.** The code proceeds with a truncated buffer. The signature
  then fails, *or* the client gets `EPIPE`/`ECONNRESET` because the server closes with unread data.
  Reproduced: the client saw `BrokenPipeError`, not a REJECTED message. It's better to detect
  "more data after cap" and reply `REJECTED (payload too large)`.
- `EINTR` isn't retried here. It's OK in practice because the handler resets SIGCHLD to default and
  no other handler is installed in the child… except the inherited SIGTERM handler (no
  `SA_RESTART`)! So a SIGTERM sent to a handler makes `read` fail → `exit(EXIT_FAILURE)`. That's
  acceptable behaviour.

```c
buffer[total_read] = '\0';
char *newline = strchr((char*)buffer, '\n');
```
- `strchr` stops at the **first NUL byte**. A NUL before the first newline → "no newline" →
  rejected. That's safe. The *payload* part is handled by length (`payload_len`), so binary
  content after line 1 is fine.
- Missing newline → REJECTED (Malformed input). `goto cleanup` is the idiomatic C pattern for a
  single exit path, the C version of RAII/`finally`.

```c
size_t line1_len = (size_t)(newline - (char*)buffer);
char *line1 = malloc(line1_len + 1);  memcpy(...); line1[line1_len] = '\0';
unsigned char *payload = (unsigned char*)(newline + 1);
size_t payload_len = total_read - line1_len - 1;
```
- The pointer difference gives the line length. Copying line 1 lets us modify it (strip `\r`)
  without touching the signed payload.
- **The payload is exactly the bytes after the first `\n`.** This must match what
  `sign_script.sh` signed: `openssl dgst -sign file` over the original file. Since
  `echo "# SIG: …" > out; cat file >> out`, the bytes after the first newline *are* the original
  file. ✔
- `payload_len` can't underflow: `newline` is inside `[buffer, buffer+total_read)`.
- Memory audit of `line1`: the prefix-failure path frees it before `goto`, the success path frees
  it at L185, and the `!line1` path has nothing to free. No leak. ✔

```c
const char *prefix = "# SIG: ";
if (strncmp(line1, prefix, strlen(prefix)) != 0) { ...REJECTED...; free(line1); goto cleanup; }
char *base64_sig = line1 + strlen(prefix);
```
Why is the signature a **bash comment**? It's backwards-compatible: the signed file is still a
valid bash script, and it's the same convention as shebang lines or `# -*- coding -*-`.

```c
size_t sig_len = strlen(base64_sig);
if (sig_len > 0 && base64_sig[sig_len - 1] == '\r') base64_sig[sig_len - 1] = '\0';
```
CRLF tolerance **for line 1 only**. If the *body* had CRLF endings while the signer signed LF, the
hash differs → rejected. That's correct: never normalise signed bytes.

```c
if (crypto_verify_signature(crypto_ctx, payload, payload_len, base64_sig) == STATUS_OK)
    execute_script(client_fd, req_id, (const char*)payload, payload_len);   // return value ignored
else ... "REJECTED (Reason: Cryptographic signature verification failed)"
```
- A single generic rejection reason for every crypto failure (bad base64, bad DER, wrong key,
  tampering). **Good security practice**: don't give an oracle that tells the attacker *which*
  check failed. Details go to the server log only.
- **Verify-then-execute on the same buffer** means no TOCTOU: the bytes verified are exactly the
  bytes executed, and they never sit on disk where they could be swapped. Say this explicitly. It's
  a classic code-signing pitfall (verify a file, then exec the path).

```c
cleanup:
    OPENSSL_cleanse(buffer, MAX_PAYLOAD_SIZE + 1);   // compiler-proof memset (won't be optimised away)
    free(buffer); close(client_fd);
    exit(EXIT_SUCCESS);                              // ⚠ should be _exit() in a forked child
```
- **Why `OPENSSL_cleanse` and not `memset`?** The compiler can delete a `memset` on memory that's
  freed right after ("dead store elimination"). `OPENSSL_cleanse` / `explicit_bzero` /
  `memset_s` are guaranteed to run. FIPS 140-3 calls this **zeroisation** (of CSPs: keys, seeds).
  Note the honest nuance: neither a public script nor a signature is a secret; this is
  defence-in-depth.
- **`exit` vs `_exit` after `fork`**: `exit()` runs `atexit` handlers and **flushes stdio
  buffers inherited from the parent**. I reproduced this: with stdout redirected to a file, the
  daemon's startup banner was duplicated once per connection (4 connections → 5 copies). In a
  forked child that doesn't `exec`, use `_exit()`, or `fflush` everything before `fork()`.

## 2.7 `main()` (L198-271)

```c
server_config_t config = {0};                         // all pointers NULL
while ((opt = getopt(argc, argv, "u:p:c:h")) != -1)   // "x:" = option takes an argument (optarg)
```
- `getopt` is POSIX. `-h` and unknown flags fall through to the usage message + `EXIT_FAILURE`.
  (Arguably `-h` should exit 0, but the test expects non-zero.)
- Validation: needs a transport (`-u` **or** `-p`) **and** `-c`.

Startup order, **and why it matters**:
1. `setup_signals()`
2. `crypto_init()`: **load and validate certs once, before accepting traffic**. Fail fast: no
   valid cert → exit. Children inherit the parsed store via `fork()` (copy-on-write), so there's
   no per-request disk I/O and no per-request parsing.
3. `create_listener()`
4. The accept loop.

```c
while (keep_running) {
    int client_fd = accept(server_fd, NULL, NULL);
    if (client_fd < 0) { if (errno == EINTR) continue; perror(...); continue; }
    pid_t pid = fork();
    if (pid == 0) {                         // CHILD
        close(server_fd);                   // least privilege: handler can't accept other clients
        signal(SIGCHLD, SIG_DFL);           // ★ critical, see below
        handle_client(client_fd, ctx);      // never returns (exit inside)
    } else if (pid > 0) {
        close(client_fd);                   // ★ parent MUST close its copy, otherwise EOF never reaches the client & fds leak
    } else { perror; close(client_fd); }
}
crypto_cleanup(ctx); close(server_fd); return 0;   // comment says "unreachable"; it IS reachable via SIGTERM (stale comment)
```

**★ Why `signal(SIGCHLD, SIG_DFL)` in the handler child?** Signal dispositions are **inherited
across `fork()`**. Without the reset, the handler child would run `sigchld_handler` when bash
exits. That handler's `waitpid(-1, …, WNOHANG)` would **steal** bash's exit status, and
`executor.c`'s `waitpid(pid, &status, 0)` would get `ECHILD` with garbage `status`. This is a
subtle, real bug that you fixed. Be ready to explain it; it shows systems depth.

**★ Why the parent closes `client_fd`**: after `fork`, both processes reference the same open
socket. The connection only fully closes when *all* references close. If the parent kept it, the
client would never see EOF after the handler finishes, and the daemon would leak one fd per
request until `EMFILE`.

**Concurrency model, named properly:** this is **fork-per-connection** (Apache "prefork" is
different: a *pool* of pre-forked workers). The repo calls it "pre-fork", so be precise if asked.
Pros: strong fault isolation, simple, matches the need to fork bash anyway. Cons: no limit on
concurrent children (DoS), fork cost per request (cheap thanks to copy-on-write), and no shared
state between requests (no rate limiting).

⚠ **`fork()` after OpenSSL init**: it's fine here because children only *use* the already-parsed
certs. With a random generator (signing, TLS) you'd care about RNG state duplication (OpenSSL 3
reseeds on fork detection).

## Questions you must be able to answer
1. Why `sig_atomic_t` and `volatile`? What can a signal handler safely call?
2. Why `SA_RESTART` on SIGCHLD but not on SIGTERM? What's the race, and how would you remove it?
3. What breaks if you delete `signal(SIGCHLD, SIG_DFL)`? If you delete `close(client_fd)` in the parent?
4. Why is the read loop safe against overflow? What two DoS problems remain in it?
5. Why `OPENSSL_cleanse` instead of `memset`? Why `_exit` instead of `exit` in a forked child?
6. How would you authenticate the *caller* on a UNIX socket? (`SO_PEERCRED`)
7. Why is verifying a buffer and executing the *same buffer* better than verifying a file and executing its path?
