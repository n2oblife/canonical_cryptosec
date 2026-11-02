# Chapter 6: Weaknesses, verified on your machine

Every item marked **✅ reproduced** was actually run against your binary (built from `HEAD`,
OpenSSL 3.6.5) on 2026-10-31. Repro commands use the helper from chapter 7
(`study/labs/send.py`). For each: **what**, **evidence**, **fix**, **how to say it**.

> Interview strategy: bring up 3-4 of these *yourself* ("if I had another day, I'd fix…").
> For the rest, if an interviewer finds one, acknowledge it calmly, explain the root cause, give
> the fix. Never defend a bug. *"Good catch, here's why it happens and how I'd fix it"* is a
> senior answer.

---

## 6.0 Repo hygiene: fix BEFORE the interviews (5 minutes)

Both interviewers may open the repo. Two things undermine you:
1. **[README.md:55-57](../README.md#L55-L57)** contains leftover chat-assistant text: *"Here is the
   expanded section for your `README.md`… Replace your current **Running the Server** section
   with the following:"*. Delete those lines.
2. **[imrpovment.md](../imrpovment.md)** (typo in the name) is written as coaching *to you* ("How
   to defend it", "Submit the `tar.gz` with total confidence"). A reviewer will read it as
   rehearsed answers. Either delete it, or rewrite it as a neutral **"Known limitations & future
   work"** section in the README (much better: it shows self-awareness). This chapter gives you
   the material for that rewrite.
3. Optional small fixes that are cheap and visible: the `make prod` bug (F10), `make debug` link
   (F11), the broken test (F12), and the README `SCRIPT=dos_script` → `dos`.

Decide whether to fix these in the repo or to present them as known issues. Fixing the
README/imrpovment items is strongly recommended. For the code bugs, either choice is fine as
long as you can talk about them.

---

## Severity table

| ID | Finding | Area | Severity | Status |
|---|---|---|---|---|
| F1 | No chain validation: trust = presence in directory | Crypto/PKI | **High** (design) | ✅ |
| F2 | "FIPS 140-3 aligned" but FIPS provider never loaded | Crypto/compliance | **High** (claim) | code review |
| F3 | No wall-clock timeout (`EXECUTION_TIMEOUT_SEC` unused) | Sandbox | **High** | ✅ |
| F4 | Pipe deadlock for large scripts with large early output | Executor | **High** | ✅ |
| F5 | Background processes outlive the request / hold the pipe | Sandbox | High | ✅ |
| F6 | No privilege drop; RLIMIT_NPROC is per-UID and ignored for root | Sandbox | High | ✅ |
| F7 | `client_fd` leaks into bash (no CLOEXEC) | Executor | Medium | ✅ |
| F8 | Script's stdin is its own source code | Executor | Medium | ✅ |
| F9 | `exit()` in forked children duplicates log lines | main | Low | ✅ |
| F10 | `make prod` builds dev limits | Build | **High** (for a deliverable) | ✅ |
| F11 | `make debug` fails to link | Build | Medium | ✅ |
| F12 | Time-validity test is a no-op | Tests | **High** (false assurance) | ✅ |
| F13 | Unbounded forks + no read timeout (slowloris) | main | High | ✅ |
| F14 | Oversized payload: no REJECTED, client gets EPIPE | Protocol | Low | ✅ |
| F15 | Replay; TCP on all interfaces, plaintext; no caller authN | Protocol | High (design) | ✅ replay |
| F16 | Validity checked only at startup; no revocation; no key-type policy | PKI | Medium | code review |
| F17 | UDS path silently truncated at 107 chars | main | Low | ✅ |
| F18 | Memory-limit footer says SIGKILL; reality is exit 2 | Executor | Low | ✅ |
| F19 | SIGTERM vs `accept()` race | main | Low | theory |
| F20 | Misc: unchecked returns (`setrlimit`, `waitpid`, `sk_*`, `EVP_DecodeFinal`), dead `start_server`, `MAX_LINE_LENGTH` | Code quality | Low | code review |

---

### F1: No certificate chain validation ✅
**What.** `crypto_init` keeps any cert in `-c` dir that's time-valid and has the codeSigning EKU.
`rootCA.crt` is never read. No `X509_STORE` and no `X509_verify_cert`, even though
`guidelines.md` and the README describe that model.
**Evidence.** I copied `certs/untrusted.crt` (self-signed) into a trust dir. The server logged
`Loaded Valid Cert: /CN=Untrusted Self-Signed Signer` and a script signed by `untrusted.key` was
**APPROVED**. The "untrusted" test passes only because of *where the file is*.
**Fix.** Load the CA(s) as trust anchors, keep signer certs separately, and validate the
signer at load (and ideally at verify time):
```c
X509_STORE *store = X509_STORE_new();
X509_STORE_load_file(store, "/etc/crypto_server/ca.pem");          // trust anchors
X509_STORE_set_purpose(store, X509_PURPOSE_CODE_SIGN);             // OpenSSL ≥ 3.2 (checks EKU)
X509_STORE_set_flags(store, X509_V_FLAG_X509_STRICT /* | X509_V_FLAG_CRL_CHECK */);
X509_STORE_CTX *sctx = X509_STORE_CTX_new();
X509_STORE_CTX_init(sctx, store, signer_cert, untrusted_intermediates);
if (X509_verify_cert(sctx) != 1) reject(X509_verify_cert_error_string(X509_STORE_CTX_get_error(sctx)));
```
Better protocol: the client sends its **certificate (chain) along with the signature**
(CMS/PKCS#7 detached signature, `openssl cms -sign -binary -nodetach`). The server only stores
CA anchors. Then new signers can be added without touching the server. That's how real code
signing works (Authenticode, Sigstore, kernel module signing with PKCS#7).
**Say.** "I implemented leaf pinning, like an `authorized_keys` model. It's simple and
auditable, but it isn't PKI. The docs overstate it. The fix is `X509_verify_cert` against CA
anchors with a code-signing purpose, and ideally CMS signatures carrying the chain."

### F2: FIPS mode not enabled
**What.** The code uses FIPS-*approved algorithms* (P-256, SHA-256) through the default provider.
It never loads the `fips` provider or sets `fips=yes`, and it doesn't restrict key types.
**Fix.** See [chapter 3 §3.7](03-crypto-c.md). On Ubuntu Pro: `pro enable fips-updates`; at
runtime check `/proc/sys/crypto/fips_enabled`; in code, explicit libctx + `fips` provider +
`EVP_default_properties_enable_fips`, and fail closed if loading fails.
**Say.** "The right wording is *FIPS-compatible algorithm choice*. Compliance needs a CMVP-validated
module operating in approved mode. Using OpenSSL 3's FIPS provider on Ubuntu Pro FIPS gives you
that without code changes, *provided* I use EVP and approved algorithms, which I do."

### F3: No wall-clock timeout ✅
**What.** `RLIMIT_CPU` counts CPU time. Sleeping or blocking scripts run forever.
`EXECUTION_TIMEOUT_SEC` is defined but unused.
**Evidence.** `sleep 20` script: the client was still waiting when my 4 s timeout fired.
**Fix.** In the handler: `poll()` on `pipe_out[0]` with a deadline; on expiry
`kill(-pgid, SIGKILL)` (child calls `setsid()` first) and report `TIMEOUT`. Or use
`timerfd`/`alarm`, or `systemd-run -p RuntimeMaxSec=`.

### F4: Pipe deadlock ✅
**What.** The parent writes the whole script *then* reads output. Bash reads its stdin
incrementally (pipes aren't seekable). If the script > 64 KiB **and** its early commands print
> 64 KiB, both processes block forever. The code comment claiming bash buffers the whole script
is wrong.
**Evidence.** 225 KB script whose first line prints 200 KB → hung; `ps` showed handler and
`bash -s` both sleeping. Not killed by RLIMIT_CPU (no CPU used).
**Fix.** `memfd_create("script", MFD_CLOEXEC|MFD_ALLOW_SEALING)` → write → `fcntl(F_ADD_SEALS,
F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE|F_SEAL_SEAL)` → child: stdin=`/dev/null`,
`execl("/bin/bash","bash","--noprofile","--norc","/proc/self/fd/N",NULL)` (drop CLOEXEC on N
for the child, or `dup2` it to a known fd). Alternative: `poll()`-driven I/O loop.

### F5: Background processes escape ✅
**What.** Background jobs inherit `pipe_out[1]`, so the handler waits until they exit. Daemonised
ones (`setsid nohup … &` with redirected fds) escape entirely and run after the "request" ended,
reparented to init/subreaper, with no limit except inherited rlimits.
**Evidence.** `sleep 6 & echo main-done` → response took 6 s.
**Fix.** Put the sandbox in its own process group or session (`setsid()`), kill the whole group
on completion or timeout. Robust version: a **cgroup per request** and `cgroup.kill`, or
`PR_SET_CHILD_SUBREAPER` on the handler so orphans come back to it.

### F6: No privilege separation ✅
**What.** Scripts run as the daemon's user (`id` → `noobife`), `NoNewPrivs: 0`, `Seccomp: 0`.
If started as root (likely for a "system" daemon), signed scripts run as root, and
`RLIMIT_NPROC` doesn't apply to root. `RLIMIT_NPROC` is a per-real-UID *system-wide* count, which
is why the dev limit had to be 2048.
**Fix.** Dedicated unprivileged user (systemd `DynamicUser=yes`), `setgroups/setgid/setuid` in
the child, `PR_SET_NO_NEW_PRIVS`, cgroup `pids.max` instead of NPROC. Plus namespaces, seccomp
and AppArmor (chapter 4 §4.5).
**Say.** "Signature verification answers *should this code run*. It says nothing about *with
what authority*. Least privilege is the next layer."

### F7: File descriptor leak into the sandbox ✅
**What.** No `O_CLOEXEC`/`SOCK_CLOEXEC`; bash inherits **fd 4 = the client socket**.
**Evidence.** `ls -l /proc/$$/fd` inside the script showed `4 -> socket:[…]`.
**Impact.** The script can read further client data, write raw bytes that bypass the
OUTPUT START/END framing (forging a fake footer), and keep the connection alive.
**Fix.** `accept4(..., SOCK_CLOEXEC)`, `pipe2(..., O_CLOEXEC)`, `socket(... | SOCK_CLOEXEC)`, and/or
`close_range(3, ~0U, 0)` right before `execl`.

### F8: stdin is the script ✅
**What.** Commands reading stdin consume the remaining script source.
**Evidence.** `read x` swallowed the next line of the script.
**Fix.** Same as F4 (memfd + `/dev/null` stdin).

### F9: `exit()` vs `_exit()` in forked children ✅
**What.** Children inherit unflushed stdio buffers. `exit()` flushes them again.
**Evidence.** With stdout redirected to a file and 4 requests, the startup banner appeared **5×**.
**Fix.** `fflush(NULL)` before `fork()`, use `_exit()` in children, and use `setvbuf`/line
buffering or syslog/journald for logs.

### F10: `make prod` isn't prod ✅
**Evidence.** `make -n prod` prints "Building with DEVELOPMENT sandbox limits", and no
`-DENV_PRODUCTION` appears. `make -n PROFILE=prod` does show it. See chapter 5 for the cause
(parse-time `ifeq` vs target-specific variable).

### F11: `make debug` doesn't link ✅
`undefined reference to '__gcov_merge_add'`: `--coverage` is missing from `DEBUG_LDFLAGS`. So
ASan/UBSan were likely never run. Fix the flag, then run the test suite under ASan in CI.

### F12: The time-validity test can't fail ✅
**Evidence.** It passes in 0.07 s. The AST shows the test body has 7 statements (docstring +
imports). The real code lives in a dedented, never-called module-level function. Combined with
`LCOV_EXCL_LINE` on the expiry branches, the expiry logic has **zero effective coverage** while
the report says 100%.
**Fix.** Re-indent; generate an **ECDSA** cert (to match policy); assert the stderr messages.
Make it fail first by temporarily breaking the C check.

### F13: Connection exhaustion / slowloris ✅
**What.** No cap on concurrent children, no read timeout, `listen` backlog 10.
**Evidence.** 30 idle connections → 31 daemon children, all blocked in `read()`.
**Fix.** Track active children (counter decremented in the SIGCHLD handler), reject over a cap
*before* forking; `SO_RCVTIMEO`/poll deadline on reads; systemd `TasksMax=`; or socket activation
with `Accept=yes` + `MaxConnections=`.

### F14: Oversized payload ✅
Client sending 1.6 MB got `BrokenPipeError`, not a REJECTED line. Fix: after the cap, do one more
`read` of 1 byte. If it returns data → reply `REJECTED (Payload too large)`, then
`shutdown(SHUT_WR)` and drain/close.

### F15: Protocol-level trust gaps ✅ (replay)
- **Replay**: the same signed payload is APPROVED every time (verified). The signature binds
  *content*, not *time or intent*. Fix: include a nonce/timestamp/target-host in the signed data
  (signed header fields), plus a server-side replay cache / expiry window.
- **TCP**: `INADDR_ANY`, plaintext. Output can leak, and anyone can trigger approved scripts. Fix:
  bind loopback by default; TLS 1.3 with mutual auth for remote use.
- **UDS**: no `SO_PEERCRED` check; access depends on umask. Fix: explicit mode/group +
  peer-credential policy.
- **No framing/versioning**: half-close as the message delimiter; no protocol version. Fix: a
  versioned header (`CSX/1 len=… keyid=…`) or length-prefixed frames.

### F16: PKI lifecycle
Time validity is checked only at load (a cert expiring at runtime stays trusted until restart).
No CRL/OCSP. No key-algorithm policy (an RSA-1024 codeSigning cert would be loaded). No
`keyUsage`/`basicConstraints` check. Fix: validate at verify time with `X509_verify_cert`
(which uses the current time), `X509_V_FLAG_CRL_CHECK` + CRL files, and an explicit check on
`EVP_PKEY_get_base_id`/group name/bits. Support reload on `SIGHUP`.

### F17: UDS path truncation ✅
With a 130-char path, `strncpy` truncated silently and `bind` failed with a misleading
"Address already in use". Fix: length check → clear error.

### F18: Misleading memory-limit reporting ✅
The memory bomb ended with `xmalloc: cannot allocate…` and **EXIT CODE: 2**. The footer's SIGKILL
text blames "CPU timeout or Memory exhaustion". Only CPU produces SIGKILL here. Use
`strsignal()` and document that RLIMIT_AS yields allocation failures.

### F19: SIGTERM/accept race
A signal arriving between the `while (keep_running)` check and `accept()` entering the kernel
is missed until the next connection. Fix: `signalfd` + `poll`, self-pipe trick, or `ppoll` with a
blocked mask. Also on shutdown: unlink the UDS path and signal or wait for in-flight children.

### F20: Code-quality nits
Unchecked: `setrlimit`, `waitpid`, `sk_X509_new_null`, `sk_X509_push`, `EVP_DecodeFinal`,
`snprintf` truncation of `filepath`. Dead: `start_server()` declaration, `MAX_LINE_LENGTH`,
`EXECUTION_TIMEOUT_SEC`, the "Unreachable" comment, and the `else` branch after
`WIFSIGNALED`. Style: `setup_signals()` should be `(void)`; `keep_running` should be `static`;
`execl(..., NULL)` should be `(char *)NULL`; uninitialised `struct sigaction` fields.

---

## How to talk about all this (template)
> "There are three classes of issues. **Trust model**: it's pinning, not PKI; no FIPS mode; no
> caller auth or replay protection. **Isolation**: rlimits alone aren't a sandbox. I'd add a
> wall-clock timeout with process-group kill, privilege drop, cgroups, namespaces, seccomp,
> AppArmor, or simply delegate to systemd. **Engineering**: a pipe deadlock I'd fix with memfd,
> fd leaks fixed with CLOEXEC, and some build and test bugs. The most embarrassing is a test
> that couldn't fail, which taught me to always watch a new test go red first."
