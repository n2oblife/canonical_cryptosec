# Chapter 10: One-page cheatsheet (re-read 30 min before each call)

## The system in 5 lines
1. C11 daemon; UDS or TCP; fork-per-connection; certs loaded once at startup (time-valid + codeSigning EKU).
2. Protocol: `# SIG: <b64 DER ECDSA>\n<script>` + half-close; reply `[REQ-ts-pid] STATUS: APPROVED|REJECTED`.
3. Verify: base64 → DER → `EVP_DigestVerify{Init(SHA-256),Update,Final} == 1` against each pinned cert.
4. Execute: pipes + fork + `dup2` → `setrlimit(CPU, AS, NPROC)` → `clearenv` + `PATH` → `execl /bin/bash -s`; stream output; `waitpid` → exit code or signal.
5. Tests: pytest black-box over UDS; tampering, swap, RSA confusion, SHA-1 downgrade, no-EKU, DoS limits.

## Lines worth quoting
- `main.c:52-54`: no `SA_RESTART` on SIGTERM so `accept()` returns EINTR.
- `main.c:256`: reset SIGCHLD in the handler child, so the inherited reaper doesn't steal bash's status.
- `main.c:261`: parent closes `client_fd` (EOF + fd leak).
- `crypto.c:29/33`: `X509_cmp_current_time` fail-closed (0 = error).
- `crypto.c:188-190`: verifier pins SHA-256; return checked `== 1`.
- `executor.c:77-88`: closing unused pipe ends = EOF semantics.

## My top 6 known issues (say them first)
| # | Issue | One-line fix |
|---|---|---|
| F1 | Pinning, not chain validation (self-signed in dir = trusted) | `X509_STORE` + `X509_verify_cert` + codesign purpose; CMS signatures with chain |
| F2 | FIPS algorithms but no FIPS provider | libctx + `OSSL_PROVIDER_load("fips")` + `fips=yes`; Ubuntu Pro `fips-updates` |
| F3/F5/F13 | No wall-clock/read timeouts; bg jobs escape; unbounded forks | poll deadlines; `setsid` + `kill(-pgid)`; cgroup per job; concurrency cap |
| F4/F8 | Pipe deadlock for >64 KiB scripts; script reads itself | sealed **memfd**, `bash /proc/self/fd/N`, stdin `/dev/null` |
| F6/F7 | No priv drop/ns/seccomp; client socket leaks into bash | `DynamicUser`, `NO_NEW_PRIVS`, `close_range`/CLOEXEC, AppArmor |
| F10-12 | `make prod` = dev; `make debug` link error; no-op expiry test | lazy make var; `--coverage` in LDFLAGS; re-indent + red-first |

## Precise vocabulary
- FIPS *validated* (module has a CMVP cert) vs *approved* (algorithm) vs *approved mode* vs "using a validated module".
- CMVP / CAVP (ACVP) / ESV / CST lab / Security Policy / SSP = CSP + PSP / pre-operational integrity test / CAST / PCT / service indicator / Level 1.
- 140-2 certs → historical since Sept 2026; 140-3 = ISO 19790.
- CC: TOE, ST, PP (OSPP), SFR (`FCS_`…), SAR, EAL, evaluated configuration; Ubuntu Pro `cc-eal`.
- STIG CAT I/II/III; CIS L1/L2; USG = OpenSCAP + ComplianceAsCode content; XCCDF + OVAL (object/state/test/definition); tailoring.
- OpenSSL 3: providers (default, fips, base, legacy), fetch + properties, EVP only; `get0` borrowed vs `get1` owned.

## Bridges to Canonical's world
- Code signing ↔ Secure Boot/shim, module signing, APT `InRelease`, snap assertions, IMA appraisal.
- Sandbox ↔ systemd hardening, AppArmor profiles, snap strict confinement, cgroups, user namespaces (restricted on 24.04).
- Audit automation ↔ USG audit/fix, OVAL checks, Ansible remediation, rule tests in LXD/containers.

## Phrases that work
- "Good catch. Here's the root cause and the fix."
- "That was a deliberate trade-off because…, and the cost is…"
- "I'd measure before optimising that."
- "Signature verification answers *whether* code should run, not *with what authority*."
- "A test that can't fail is false assurance, so now I watch every test go red first."
