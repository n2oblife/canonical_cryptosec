# Chapter 9: Technical skills interview (Henry Coggill, Security Certifications & Hardening)

## 9.1 Read the interviewer
- Works on **security certifications and hardening** at Canonical. That's the team you'd join, so
  he's probably your future peer or lead.
- Public GitHub hints: forks of *"What makes a hardened Linux system?"* and *"What makes a hardened
  container image?"* (community security working-group papers), and **`fipstestsnap`**, a C
  project evidently about testing FIPS behaviour in a snap. That suggests a practical interest in
  how **packaged/confined software actually picks up the FIPS crypto module**.
- Expect: deep follow-ups on your crypto code; FIPS 140-3 process and OpenSSL 3 FIPS provider;
  CC; STIG/CIS automation (USG, OVAL, Ansible); Linux hardening; secure C. He'll probe for
  **precision of language** (e.g. "FIPS validated" vs "FIPS compliant" vs "FIPS approved").

---

## 9.2 FIPS 140-3: what you must be able to explain in 3 minutes

**What it is.** A US/Canadian government standard for **cryptographic modules** (FIPS 140-3,
effective 2019, built on **ISO/IEC 19790:2012** with test requirements in **ISO/IEC 24759**).
Run by the **CMVP** (NIST + Canada's CCCS). Testing is done by accredited **CST labs**.
- **Algorithms** are validated separately by **CAVP** (certificates per algorithm/implementation,
  tested via **ACVP**, the automated protocol). The module is validated by **CMVP**, which
  requires CAVP certs for the approved algorithms it offers.
- **Entropy sources** have their own validation, **ESV** (per SP 800-90B). DRBGs follow **SP 800-90A**.
- **FIPS 140-2 → 140-3**: new 140-2 submissions stopped in 2021, and remaining **140-2
  certificates moved to the historical list in September 2026**. So, as of now, 140-3 is what
  counts for new procurements. (Worth knowing given today's date.)

**Vocabulary (use it precisely):**
- *Approved algorithm*: in the approved list (SP 800-140C): AES, SHA-2/SHA-3, HMAC, ECDSA/RSA/EdDSA
  (FIPS 186-5), ECDH/DH (SP 800-56A), RSA KEM (SP 800-56B), KDFs (SP 800-108, HKDF via SP 800-56C),
  DRBG (SP 800-90A), and now ML-KEM/ML-DSA/SLH-DSA (FIPS 203/204/205). **Not approved**: MD5, DES,
  ChaCha20-Poly1305, and X25519 key agreement (it isn't in SP 800-56A). A common real-world
  gotcha: TLS in FIPS mode falls back to AES-GCM and P-256/P-384 ECDHE, so clients that only
  offer ChaCha20/X25519 fail to connect.
- *Validated module*: has a CMVP certificate for a specific version, build, and **operational
  environment** (OS + CPU tested).
- *Approved mode*: the module only offers approved services. Using a validated module outside
  approved mode ≠ FIPS.
- **Security Policy**: the public document per certificate stating the module boundary, services,
  roles, SSPs, self-tests, and the rules the *user* must follow (e.g. "AES-GCM IVs must be
  generated internally"). Applications must follow it.
- **SSP** (sensitive security parameters) = **CSPs** (secret: keys, seeds) + **PSPs** (public
  keys, whose integrity matters). They must be protected and **zeroised**.
- **Security levels 1-4**: software modules are typically **Level 1** (no physical security
  requirements). Levels 3-4 are HSMs.
- **Self-tests**: **pre-operational** (software **integrity test**: e.g. HMAC-SHA-256 over the
  module binary, compared with the value computed at install time), plus **conditional
  self-tests**: **CASTs** (known-answer tests per algorithm before first use), **PCT** (pairwise
  consistency test on every asymmetric key generation), continuous RNG/entropy health tests. On
  failure → **error state**: no crypto output.
- **Service indicator** (new in 140-3): the module must tell the caller whether the service it
  just performed was approved.
- **Key strength**: ≥ 112-bit security (SP 800-131A): RSA ≥ 2048, ECC ≥ P-224 (P-256 in
  practice). SHA-1 not allowed for signature generation.

**How it maps to OpenSSL 3:**
- The FIPS **provider** (`fips.so`) *is* the module boundary. libcrypto is outside it and just
  dispatches. That's why OpenSSL 3 could validate a provider without validating the whole library.
- `openssl fipsinstall` runs the self-tests and writes `fipsmodule.cnf` with the integrity MAC.
- Applications must fetch algorithms with `fips=yes` (globally via `default_properties =
  fips=yes` in `openssl.cnf`, or `EVP_default_properties_enable_fips()`), and must use the EVP API.
  **Low-level APIs (`SHA256()`, `AES_encrypt`, `ECDSA_do_sign`) bypass providers**: deprecated,
  and not FIPS.
- Things that fail in FIPS mode and surprise people: `MD5()` usage in apps (e.g. legacy
  checksums), PKCS#12 files using RC2/3DES, X25519, RSA < 2048 keygen, short HMAC keys, PBKDF2
  with tiny salts or iterations.

**How it maps to Ubuntu (Ubuntu Pro):**
- Canonical certifies a set of packages per LTS (typically the **Linux kernel crypto API**,
  **OpenSSL**, **libgcrypt**, **GnuTLS/Nettle**, sometimes strongSwan, depending on the release).
- `sudo pro enable fips` → **strictly the validated binaries** (no security patches unless
  re-validated). `sudo pro enable fips-updates` → validated modules **plus security fixes**
  (the patched builds aren't themselves re-certified; the trade-off is *compliance purity vs
  security*). Most customers choose `fips-updates`; regulated customers with strict auditors may
  need `fips`. **This tension is a great discussion point.**
- Enabling sets the kernel command line `fips=1`, installs FIPS kernel + libs, and reboots. Check
  with `cat /proc/sys/crypto/fips_enabled` → `1`. OpenSSL, libgcrypt and GnuTLS read this flag
  and enter FIPS mode automatically (libgcrypt also has `/etc/gcrypt/fips_enabled`; GnuTLS
  `GNUTLS_FORCE_FIPS_MODE`).
- Containers: **the host kernel is shared**, but userspace libs come from the image. A container
  is only "FIPS" if its image ships the validated libraries (Ubuntu Pro FIPS container images).
  **Snaps** bundle their own libraries via base snaps; a snap using its own OpenSSL isn't using
  the host's validated module. This is exactly the kind of problem a "fipstestsnap" would probe.
  Ask him about it (§9.9).

**Applied to your project** (be ready):
> "My server only does signature *verification* with public keys, so its SSPs are PSPs (the
> trusted public keys) and it holds no CSPs. To run in approved mode I'd load the FIPS provider
> in an explicit libctx, fail closed if the self-tests fail, enforce approved key types at cert
> load, and use only EVP with `fips=yes` fetches. Then the module's Security Policy governs. I
> wouldn't call my binary 'FIPS validated'. It would be an application *using* a FIPS 140-3
> validated module in approved mode."

---

## 9.3 Common Criteria (ISO/IEC 15408)
- Evaluates a **TOE** (Target of Evaluation) against a **Security Target** (ST), the vendor's
  claims, often conforming to a **Protection Profile** (PP). For OSes: NIAP's **PP for General
  Purpose Operating Systems** (OSPP), with extended packages (e.g. SSH, TLS).
- **SFRs** (security functional requirements, by class: `FCS_` crypto, `FIA_` identification and
  auth, `FAU_` audit, `FDP_` user data protection, `FPT_` TSF protection, `FTP_` trusted path)
  and **SARs** (assurance: development, guidance docs, life-cycle, tests, vulnerability
  assessment).
- **EAL1-7** (assurance depth) vs NIAP's modern "exact conformance to a PP" approach. The CCRA
  mutually recognises up to EAL2 or cPPs.
- Evaluated by licensed labs; **evaluated configuration** matters: the cert covers a specific
  configuration, documented in guidance. Ubuntu Pro has a `cc-eal` service that provides the
  CC-evaluated configuration tooling and materials.
- **CC FCS_ requirements usually point at FIPS-validated crypto** for the US scheme. That's why
  the same team does both.

## 9.4 DISA-STIG, CIS, and Compliance-as-Code
| | CIS Benchmarks | DISA STIG |
|---|---|---|
| Owner | Center for Internet Security (consensus, community) | US DoD Defense Information Systems Agency |
| Audience | Industry, any org | DoD and contractors (mandatory there) |
| Structure | Profiles: **Level 1** (low impact, baseline) / **Level 2** (defence in depth, may break things); Server vs Workstation | Rules with **CAT I/II/III** severity; IDs like `UBTU-22-xxxxxx` (STIG ID), `V-xxxxxx` (vuln ID), `SV-…` (rule ID); requires e.g. FIPS mode, auditd rules, DoD banners, smart-card auth |
| Formats | PDF + SCAP/XCCDF content | XCCDF benchmark + OVAL (SCAP), STIG Viewer checklists (`.ckl`/`.cklb`) |

**Canonical's tool: Ubuntu Security Guide (USG)**, via Ubuntu Pro (`pro enable usg`, `apt install usg`):
```bash
sudo usg audit cis_level1_server          # → XCCDF results + HTML report under /var/lib/usg
sudo usg audit disa_stig
sudo usg generate-tailoring cis_level1_server tailor.xml   # customise: disable/adjust rules
sudo usg audit --tailoring-file tailor.xml
sudo usg fix cis_level1_server            # apply remediation (test first!)
sudo usg generate-fix cis_level1_server --output fix.sh    # review before running
```
It's built on **OpenSCAP** (the evaluation engine) and content derived from **ComplianceAsCode**
(the SCAP Security Guide project), where each **rule** is a directory containing: `rule.yml`
(title, description, rationale, severity, references to CIS/STIG/NIST 800-53 IDs), an **OVAL
check**, **bash remediation**, **Ansible remediation**, and **tests** (pass/fail scenarios run in
containers). Profiles select rules and set variables (e.g. `var_password_pam_minlen=15`).

**SCAP family**: XCCDF (checklist structure and results), **OVAL** (machine-checkable state
tests), CPE (platform naming), CVE/CVSS, ARF (result format).

**OVAL anatomy** (be able to sketch one):
```
definition (class="compliance")  ── criteria (AND/OR) ── criterion → test
test   = object + state + check/existence semantics
object = WHAT to collect       (e.g. textfilecontent54_object: path=/etc/ssh/sshd_config, pattern=^\s*PermitRootLogin\s+(\S+))
state  = WHAT it should be      (e.g. subexpression = "no")
```
Other useful tests: `dpkginfo_test` (package version), `sysctl_test`, `file_test` (permissions,
owner), `partition_test` (mount options), `systemdunitproperty_test`. Canonical also publishes
**OVAL data for Ubuntu CVEs/USNs** (usable with `oscap oval eval`), which is the vulnerability
class of OVAL.

**Worked example: an end-to-end rule** (great to talk through):
*"SSH root login must be disabled"* (CIS 5.2.x / STIG).
- Check (OVAL): the effective `PermitRootLogin` is `no`. **Subtlety**: on Ubuntu 22.04+,
  `sshd_config` has `Include /etc/ssh/sshd_config.d/*.conf` **at the top**, and in OpenSSH the
  **first** value obtained wins. So a drop-in can silently override the main file. A naive regex
  on `sshd_config` gives a false pass. Robust checks consider the drop-ins, or evaluate the
  effective config with `sshd -T`.
- Remediation (bash): write `/etc/ssh/sshd_config.d/00-hardening.conf` (sorted first), validate
  with `sshd -t`, then reload. Idempotent.
- Remediation (Ansible): `lineinfile`/`template` + handler `systemd: name=ssh state=reloaded`,
  `validate: 'sshd -t -f %s'`. Supports `--check --diff`.
- Tests: scenario with root login enabled in a drop-in → must FAIL; after remediation → PASS;
  second remediation run → no change.

**Other classic hardening rules you should be able to discuss** (and what can break):
- Separate partitions with `nodev,nosuid,noexec` on `/tmp`, `/var/tmp`, `/dev/shm` (`noexec`
  /tmp breaks some installers).
- Disable unused filesystems/modules (`install cramfs /bin/false`, usb-storage).
- `auditd` rules (privileged commands, identity files, time changes, `execve` logging), immutable mode `-e 2`.
- AppArmor enabled and all profiles in enforce mode.
- Sysctl: `kernel.randomize_va_space=2`, `kernel.kptr_restrict`, `kernel.dmesg_restrict=1`,
  `kernel.yama.ptrace_scope`, `net.ipv4.ip_forward=0`, `accept_redirects=0`,
  `rp_filter=1`, `tcp_syncookies=1`, `fs.suid_dumpable=0`.
- PAM: `pam_pwquality` (length, complexity), `pam_faillock` (lockout), password hashing
  (yescrypt / SHA-512), password ageing (`login.defs`).
- File permissions on `/etc/shadow`, `/etc/passwd`, cron dirs; no world-writable files; no
  unowned files.
- AIDE file integrity; time sync (chrony); logging (rsyslog/journald persistent); login banners.
- STIG-specific: FIPS mode enabled; smart-card/PKI auth (`pam_pkcs11`/`sssd`); session lock.

**Automation design principles** (what makes good audit/remediation tooling):
idempotent; check and fix separated; dry-run/diff; tailoring with documented exceptions;
version content against benchmark versions; test every rule in CI on every supported release;
don't break the system (staged rollout); produce auditor-friendly evidence (ARF/HTML).

## 9.5 Linux crypto libraries, briefly
| Library | Used by | FIPS notes |
|---|---|---|
| **OpenSSL** (libcrypto/libssl) | Most of the system: OpenSSH (libcrypto), Python `ssl`/`hashlib`, nginx, curl (OpenSSL flavour) | OpenSSL 3 FIPS provider; EVP API; providers and properties |
| **libgcrypt** | GnuPG, systemd-journald (FSS), cryptsetup (optionally) | FIPS mode via `/proc/sys/crypto/fips_enabled` or `/etc/gcrypt/fips_enabled`; S-expressions API; `gcry_md_*`, `gcry_pk_verify` |
| **GnuTLS** (+ **Nettle** for primitives) | apt's https transport, many GNOME apps, wget (some builds), libcurl3-gnutls | FIPS mode auto-detected; `gnutls_fips140_mode_enabled()`; priority strings |
| **Kernel crypto API** | dm-crypt/LUKS, IPsec (XFRM), fs-verity, kTLS, `getrandom`/DRBG | `fips=1` boot param → kernel self-tests and approved-only; `/proc/crypto` lists algorithms with `selftest: passed`; userspace access via **AF_ALG** |
| NSS | Firefox, some RHEL tools | Has its own FIPS mode (less relevant on Ubuntu) |

The job description says "extend these libraries with features for FIPS/CC". In practice that
means: patching self-tests, service indicators, disabling non-approved algorithms in FIPS mode,
integrity checking (`.hmac` files), backporting fixes into validated source trees with minimal
diffs, and keeping Debian packaging (`debian/patches`, quilt) clean.

## 9.6 Linux security mechanisms (hardening vocabulary)
- **DAC** (uid/gid, modes) vs **MAC** (LSMs: **AppArmor** on Ubuntu, SELinux on RHEL, Smack,
  TOMOYO; **Landlock**: unprivileged; **Yama**: ptrace restrictions; **Lockdown**: kernel
  integrity/confidentiality modes under Secure Boot).
- **Capabilities** (`CAP_NET_BIND_SERVICE`, `CAP_SYS_ADMIN` = "the new root"), bounding set,
  ambient caps, `no_new_privs`.
- **seccomp-bpf** syscall filtering. **Namespaces** (mnt, pid, net, user, ipc, uts, cgroup, time).
  **cgroups v2** (resource control). Ubuntu 23.10+/24.04 **restrict unprivileged user namespaces
  via AppArmor** (`kernel.apparmor_restrict_unprivileged_userns`), which matters for sandboxes
  like bwrap.
- **Boot chain**: UEFI Secure Boot → shim (Microsoft-signed) → GRUB → signed kernel → **module
  signature enforcement**; **TPM**-backed FDE (offered by the Ubuntu installer, initially as experimental from 23.10). **IMA/EVM**
  for runtime file integrity measurement and appraisal.
- **Supply chain**: signed APT repos (InRelease), reproducible builds, SBOM (SPDX/CycloneDX),
  SLSA provenance, image signing (cosign/sigstore). "Hardened container image" paper themes:
  minimal/distroless (Ubuntu **chiselled** images), non-root user, read-only rootfs, no shell or
  package manager, pinned digests, CVE scanning, signed images with provenance, FIPS libs if
  required.
- **Livepatch** (kernel patching without reboot), **ESM** (extended security maintenance), USNs.

## 9.7 Secure C checklist (he may ask you to review code live)
- Bounds: lengths everywhere; `snprintf` return value checked for truncation; avoid `strcpy`,
  `strcat`, `sprintf`, `gets`; beware `strncpy` (no NUL guarantee, pads with zeros).
- Integers: overflow in size computations (`n * size` → use `reallocarray`/checks),
  signed/unsigned comparisons, narrowing casts (your `-Wconversion` casts), `ssize_t` vs `size_t`.
- Memory: use-after-free, double free, leaks on error paths (goto cleanup), uninitialised reads.
- Format strings: never `printf(user)`.
- Concurrency/signals: async-signal-safety, TOCTOU on files (`open` then `fstat`, use `O_NOFOLLOW`,
  `openat`), races.
- Crypto-specific: check return codes as `== 1`; constant-time comparison of MACs
  (`CRYPTO_memcmp`, never `memcmp`); zeroise secrets with `OPENSSL_cleanse`/`explicit_bzero`;
  never roll your own crypto; use the library's RNG (`RAND_bytes`, `getrandom`); don't let input
  choose algorithms.
- Process: fds with CLOEXEC; `_exit` after fork; drop privileges in the right order
  (`setgroups` → `setgid` → `setuid`, check each); sanitise env; absolute paths for `exec`.
- Tooling: `-Wall -Wextra -Werror`, sanitizers, valgrind, `-fanalyzer`, cppcheck, CodeQL,
  fuzzing (libFuzzer/AFL++, OSS-Fuzz).

## 9.8 Crypto fundamentals: rapid Q&A (answer each in 2-3 sentences)
1. **Hash vs MAC vs signature?** Integrity only / integrity + authenticity with a shared key /
   authenticity + non-repudiation with a key pair.
2. **Why hash-then-sign?** Efficiency (fixed-size input), and the security proofs are for
   fixed-size representatives.
3. **ECDSA nonce reuse?** Two signatures with the same `k` → solve for `k`, then the private key.
   Use a good DRBG or RFC 6979 deterministic nonces.
4. **RSA PKCS#1 v1.5 vs PSS?** PSS is randomised with a security proof. v1.5 signatures are
   still OK in practice if verified strictly (Bleichenbacher '06 forgery came from lax parsing);
   v1.5 *encryption* is vulnerable to padding-oracle attacks (Bleichenbacher '98, ROBOT).
5. **AES-GCM nonce reuse?** Catastrophic: it leaks the XOR of plaintexts and the GHASH key → forgeries.
   96-bit nonces; in FIPS mode the IV must be generated per SP 800-38D rules.
6. **Why constant-time?** Timing side channels leak secrets (MAC compare, RSA/ECC scalar mult).
7. **What's an HMAC and why not `H(key||msg)`?** Length-extension attacks on Merkle-Damgård
   hashes (SHA-256). HMAC's nested construction prevents them.
8. **KDFs?** HKDF (extract-and-expand, for high-entropy input), PBKDF2 (passwords; FIPS-approved),
   scrypt/Argon2 (memory-hard; not FIPS-approved).
9. **Forward secrecy?** Ephemeral (EC)DH per session, so a later key compromise doesn't decrypt
   past sessions. TLS 1.3 mandates it.
10. **TLS 1.3 handshake in one breath?** ClientHello (key share) → ServerHello (key share) →
    encrypted {EncryptedExtensions, Certificate, CertificateVerify, Finished} → client Finished.
    1-RTT, only AEAD ciphers, ephemeral key exchange only, RSA key transport removed.
11. **Where does Linux randomness come from?** Kernel CSPRNG (ChaCha20 output since 4.8, BLAKE2s entropy mixing since 5.17),
    seeded from interrupt timings, RDRAND/RDSEED, jitter. Use `getrandom()`. In FIPS mode the
    kernel uses an SP 800-90A DRBG with an SP 800-90B entropy source (jitterentropy).
12. **Post-quantum?** ML-KEM for key exchange (hybrid X25519MLKEM768 already deployed in
    browsers/OpenSSL 3.5); ML-DSA/SLH-DSA for signatures; "harvest now, decrypt later" threatens
    confidentiality today; signatures are less urgent but long-lived roots of trust (firmware,
    code signing) must migrate early.

## 9.9 Questions to ask Henry
- "With `fips` vs `fips-updates`, how do customers usually decide, and how does the team handle
  CVEs in validated modules between re-validations?"
- "How do you approach FIPS for snaps and containers, where the userspace crypto comes from the
  package rather than the host? Is that what `fipstestsnap` explores?"
- "How is USG content developed and tested: upstream in ComplianceAsCode, or Canonical-specific?
  How do you test rules across releases?"
- "What does the post-quantum migration look like for the FIPS roadmap (ML-KEM/ML-DSA in the
  validated modules)?"
- "What would success look like for this role in the first 6 months?"

## 9.10 Mock drill: "Review your own `crypto.c` as if I were the auditor"
Out loud, in under 5 minutes, cover: (1) the trust model is pinning, not chain validation (F1);
(2) FIPS provider not loaded (F2); (3) correct `== 1` checks and verifier-pinned hash;
(4) time checks only at startup, no revocation, no key-type policy (F16); (5) cleanse is
hygiene since there are no CSPs; (6) generic client error vs detailed server log;
(7) error queue and minor unchecked returns. Then the fix plan.
