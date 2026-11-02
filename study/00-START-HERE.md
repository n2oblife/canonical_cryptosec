# Interview Journey: `canonical_cryptosec`

> A guided path through **your own project**: the architecture first, then every line of code, then
> the weaknesses an interviewer will find, then hands-on labs and mock interviews.
> This folder is excluded from git (`.git/info/exclude`), so it never ships with the repo.

---

## 0. The two interviews and what each person will probe

| | **Paul Goins**: Software architecture & engineering (60 min) | **Henry Coggill**: Technical skills (60 min) |
|---|---|---|
| Who | Senior Reliability Engineer (Managed Solutions / BootStack). Ex-Intel architect who led a team of 8. Python first; strong on TDD, code review, clean architecture, CI/CD, Debian packaging, ops on OpenStack/K8s, Juju charms. | Security certifications & hardening at Canonical. Forks of *"What makes a hardened Linux system / container image"* (OpenSSF-style papers) and a C repo called **`fipstestsnap`**. |
| What he will look for | Design trade-offs, failure modes, testability, observability, how it runs in production (systemd, packaging, timeouts, back-pressure), how you'd evolve it, code-review instincts, how you work in a team | Applied crypto (ECDSA, hashes, X.509, PKI trust), OpenSSL 3 APIs, **FIPS 140-3** (providers, approved mode, self-tests), Common Criteria, **DISA-STIG / CIS**, Linux hardening (sandboxing, AppArmor, seccomp, capabilities), secure C |
| Chapter to study | [08-interview-paul.md](08-interview-paul.md) | [09-interview-henry.md](09-interview-henry.md) |

Both of them **will read your repo**. Chapter 6 lists what they can find there. Fix the cosmetic
items (section 6.0) **before** the interviews.

---

## 1. Route map

| # | Chapter | Goal | Time |
|---|---|---|---|
| 1 | [01-big-picture.md](01-big-picture.md) | Explain the system in 2 minutes on a whiteboard: request lifecycle, process tree, trust model | 45 min |
| 2 | [02-main-c.md](02-main-c.md) | Every line of `main.c`: CLI, signals, sockets, fork-per-connection, protocol parsing | 1.5 h |
| 3 | [03-crypto-c.md](03-crypto-c.md) | Every line of `crypto.c`, plus the crypto theory behind it: ECDSA, SHA-256, DER, Base64, X.509, EKU, OpenSSL 3 | 2 h |
| 4 | [04-executor-c.md](04-executor-c.md) | Every line of `executor.c`: pipes, `dup2`, rlimits, `clearenv`, `waitpid` decoding | 1.5 h |
| 5 | [05-build-tests-ci.md](05-build-tests-ci.md) | Makefile hardening flags, the PKI and signing scripts, the pytest suite, CI | 1 h |
| 6 | [06-weaknesses-verified.md](06-weaknesses-verified.md) | **The most important chapter.** 20+ issues, each *reproduced on your machine*, with a fix and a way to talk about it | 2 h |
| 7 | [07-labs.md](07-labs.md) | Hands-on: break it, trace it (`strace`, `gdb`, `openssl asn1parse`), fix it | 3 h+ |
| 8 | [08-interview-paul.md](08-interview-paul.md) | Architecture interview: likely questions and model answers | 1 h |
| 9 | [09-interview-henry.md](09-interview-henry.md) | Security interview: FIPS, CC, STIG/CIS, OpenSSL, Linux hardening, Q&A | 2 h |
| 10 | [10-cheatsheet.md](10-cheatsheet.md) | One page to re-read 30 minutes before each call | 15 min |

### Suggested 4-day plan
- **Day 1:** chapters 1, 2, 3. Do labs 1 to 4 in chapter 7 as you read.
- **Day 2:** chapters 4 and 5, then chapter 6 *carefully*. Reproduce at least 5 findings yourself.
- **Day 3:** chapter 9 (Henry), plus labs on FIPS and OpenSSL. Out loud: explain FIPS 140-3 in 3 minutes.
- **Day 4:** chapter 8 (Paul). Do a mock "redesign v2" whiteboard. Re-read chapter 10.

### How to study each code chapter
1. Open the source file side by side with the chapter (all links are clickable).
2. For each block, **before reading my explanation, say out loud what it does and why**. Then check.
3. Each chapter ends with **"Questions you must be able to answer"**. If you can't answer one in
   30 seconds, re-read that section.

---

## 2. The 30-second pitch (memorise this)

> "It's a small C11 daemon that runs **signed bash scripts**. A client connects over a UNIX socket or
> TCP and sends `# SIG: <base64 DER ECDSA signature>` followed by the script. The server loaded a
> directory of X.509 certificates at startup and kept only the ones that are time-valid and carry
> the **codeSigning EKU**. It verifies the ECDSA-P256/SHA-256 signature over the exact script bytes
> with OpenSSL 3's EVP API. If one of the trusted keys verifies it, the server forks bash with `-s`,
> feeds the script through a pipe so nothing touches disk, and applies `setrlimit` CPU, memory and
> process limits plus a scrubbed environment. It streams stdout/stderr back and reports the exit
> status or the killing signal. Concurrency is fork-per-connection. It's tested end to end by a
> pytest suite that includes adversarial cases: tampering, signature swapping, RSA confusion,
> SHA-1 downgrade, missing EKU, fork/CPU/memory bombs."

Then **immediately** follow with self-critique (interviewers love this):

> "Building it, I also learned where it's weak. Trust is 'presence in a directory', not chain
> validation, and FIPS mode isn't actually enabled. The sandbox is rlimits only: no wall-clock
> timeout, no privilege drop, no namespaces or seccomp. And the stdin pipe can deadlock with large
> scripts. Here's how I'd fix each one…" → chapter 6.

Owning the weaknesses before they find them is the single most effective thing you can do in
both interviews.
