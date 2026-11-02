# Chapter 3: `src/crypto.c` line by line, plus the crypto behind it

File: [src/crypto.c](../src/crypto.c) (226 lines). API: [include/crypto.h](../include/crypto.h).

This is the chapter Henry will care most about. Learn the **theory** sections as well as the code.

---

## 3.0 Theory you must own

### Hash: SHA-256
- It maps any input to 256 bits. Its properties are **preimage resistance**, **second-preimage
  resistance** and **collision resistance** (~2^128 work, by the birthday bound).
- Signatures sign a **hash** of the message (hash-then-sign), not the message itself.
- SHA-1 is broken for collisions (SHAttered 2017, chosen-prefix 2020). NIST SP 800-131A
  **disallows SHA-1 for signature generation**. Verifying old SHA-1 signatures is "legacy use".

### Signature: ECDSA over P-256 (aka `prime256v1`, `secp256r1`)
- Key pair: private scalar `d`, public point `Q = d·G` on the curve.
- **Sign(m)**: `e = H(m)`. Pick a fresh secret nonce `k`. Compute `r = (k·G).x mod n` and
  `s = k⁻¹(e + r·d) mod n`. The signature is `(r, s)`.
- **Verify**: compute `u1 = e·s⁻¹`, `u2 = r·s⁻¹`, `R = u1·G + u2·Q` and check `R.x mod n == r`.
- **The nonce `k` must never repeat or be biased.** Reuse leaks the private key (the Sony PS3
  hack). Biased nonces leak it via lattice attacks. Mitigations: a good DRBG (SP 800-90A), or
  deterministic `k` (RFC 6979). OpenSSL uses its DRBG, mixed with the private key and message.
- **Malleability**: `(r, n−s)` is also valid. That doesn't matter here (we don't use signatures as
  IDs), but it matters in blockchains.
- Security level of P-256 is ~128 bits, matching SHA-256 (good *algorithm strength pairing*).
  **FIPS 186-5** approves ECDSA (P-256/384/521) and **EdDSA** (Ed25519/Ed448).
- **Post-quantum note** (Henry may ask): Shor's algorithm breaks ECDSA/RSA. NIST published FIPS
  203 (**ML-KEM**), 204 (**ML-DSA**) and 205 (**SLH-DSA**) in Aug 2024. OpenSSL 3.5 ships
  ML-KEM, ML-DSA and SLH-DSA. For code signing, **ML-DSA** or **SLH-DSA** (stateless hash-based,
  very conservative) or LMS/XMSS (stateful, SP 800-208) are the candidates.

### Encoding: DER and Base64
- `openssl dgst -sign` with an EC key outputs an **ASN.1 DER** `ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }`,
  typically 70-72 bytes (variable, because INTEGERs drop leading zeros or add a `0x00` when the
  high bit is set). Contrast: the **raw/P1363** format is fixed-width `r||s` (64 bytes), used by
  JWS/WebCrypto.
- **Base64** turns binary into ASCII (4 chars per 3 bytes, about 96 chars here) so it fits on a
  text line.

### X.509 certificate (RFC 5280), what matters here
```
Certificate
 ├ tbsCertificate
 │  ├ version, serialNumber, signature algorithm
 │  ├ issuer (DN), subject (DN)
 │  ├ validity: notBefore, notAfter          ← checked
 │  ├ subjectPublicKeyInfo (EC P-256 key)     ← used to verify
 │  └ extensions
 │     ├ basicConstraints (CA:TRUE/FALSE)
 │     ├ keyUsage (digitalSignature, keyCertSign…)   ← NOT checked here
 │     ├ extendedKeyUsage (codeSigning = 1.3.6.1.5.5.7.3.3)  ← checked
 │     ├ subjectKeyIdentifier / authorityKeyIdentifier
 │     └ CRL distribution points / AIA (OCSP)
 ├ signatureAlgorithm
 └ signatureValue (issuer's signature over tbsCertificate)
```
- **keyUsage vs extendedKeyUsage**: KU is low-level ("this key may make digital signatures").
  EKU is the application purpose ("…for code signing"). A strict verifier checks both.
- **Chain validation** (RFC 5280 §6): build a path leaf → intermediate(s) → trust anchor. Then
  check each signature, validity periods, basicConstraints/pathLen on CAs, name constraints,
  policies, revocation (CRL/OCSP), and the purpose. In OpenSSL that's `X509_STORE` +
  `X509_STORE_CTX` + `X509_verify_cert()`, with `X509_PURPOSE_CODE_SIGN` (OpenSSL ≥ 3.2) or a
  custom purpose check.

### OpenSSL 3 architecture
- **libcrypto** (algorithms, X.509, ASN.1) vs **libssl** (TLS). This server only links `-lcrypto`.
- **Providers** (new in 3.0): `default`, **`fips`**, `legacy` (MD4, DES…), `base`. Algorithms are
  *fetched* from providers using property queries such as `"fips=yes"`.
- **EVP** = the high-level, algorithm-agnostic "envelope" API. *Always* use EVP. The low-level
  `ECDSA_do_verify`/`SHA256()` are deprecated in 3.0, and they bypass providers, which means they
  bypass FIPS.
- `EVP_sha256()` does an *implicit fetch*. `EVP_MD_fetch(libctx, "SHA2-256", "fips=yes")` is the
  explicit form.
- Reference counting: `get0` functions = borrowed pointer (don't free). `get1` = new reference
  (you must free).

---

## 3.1 The opaque context (L16-19)
```c
struct crypto_ctx_t { STACK_OF(X509) *valid_certs; };
```
- `STACK_OF(X509)` is OpenSSL's type-safe dynamic array macro family (`sk_X509_new_null`,
  `sk_X509_push`, `sk_X509_num`, `sk_X509_value`, `sk_X509_pop_free`).
- Callers only see `typedef struct crypto_ctx_t crypto_ctx_t;`, so the representation can change
  (e.g. to an `X509_STORE`) without touching `main.c`. **Point this out to Paul.**
- ⚠ Pedantic C: identifiers ending in `_t` are reserved by POSIX. Common practice, minor.

## 3.2 `is_cert_valid_for_codesigning()` (L25-56)
```c
if (X509_cmp_current_time(X509_get0_notBefore(cert)) >= 0) { "not yet valid"; return 0; }
if (X509_cmp_current_time(X509_get0_notAfter(cert))  <= 0) { "expired";       return 0; }
```
- `X509_cmp_current_time(t)` returns **-1 if t < now**, **1 if t > now**, and **0 on error**.
  - notBefore must be < now → returns -1. Anything `>= 0` (future **or error**) → reject. ✔ Fail-closed.
  - notAfter must be > now → returns 1. Anything `<= 0` (past **or error**) → reject. ✔ Fail-closed.
  - **Mention that you handle the 0 = error case closed.** It's a classic bug where people write
    `< 0` or `> 0` only.
- These two branches are marked `// LCOV_EXCL_LINE` **and the test that should exercise them is
  broken** (chapter 6, F12). So time-validity checking currently has *no* passing test that
  proves it.

```c
EXTENDED_KEY_USAGE *eku = X509_get_ext_d2i(cert, NID_ext_key_usage, NULL, NULL);
```
- `d2i` = "DER to internal": it decodes the extension into a C structure (a `STACK_OF(ASN1_OBJECT)`).
- The last two args: `crit` (out: was it critical? / -1 if absent / -2 if duplicated) and `idx`.
  Passing `NULL` for `crit` means **a duplicated EKU extension also returns NULL** → rejected.
  That's fail-closed, good.
- No EKU → reject. *Policy choice*: per RFC 5280, a cert with no EKU is technically "any
  purpose", but a strict code-signing policy requires it explicitly. Say this. It shows you know
  the RFC default and *chose* to be stricter.

```c
for (int i = 0; i < sk_ASN1_OBJECT_num(eku); i++)
    if (OBJ_obj2nid(sk_ASN1_OBJECT_value(eku, i)) == NID_code_sign) { has_codesign = 1; break; }
EXTENDED_KEY_USAGE_free(eku);   // d2i allocated it → we own it → free on every path
```
- NID = OpenSSL's internal numeric ID for an OID. `NID_code_sign` ↔ `1.3.6.1.5.5.7.3.3`.
- `anyExtendedKeyUsage` (2.5.29.37.0) isn't accepted. That's strict, and good.
- **Not checked**: `keyUsage` contains `digitalSignature`, `basicConstraints CA:FALSE`, key
  algorithm/curve (an RSA-1024 cert with codeSigning would be accepted!), issuer chain.

## 3.3 `decode_base64()` (L62-94)
```c
size_t len = strlen(b64_str);
*out_buf = malloc(len);                         // decoded size ≤ 3/4·len, so len is always enough ✔
EVP_ENCODE_CTX *b64_ctx = EVP_ENCODE_CTX_new();
EVP_DecodeInit(b64_ctx);
if (EVP_DecodeUpdate(b64_ctx, *out_buf, &outl, (const unsigned char*)b64_str, (int)len) < 0) {...fail}
EVP_DecodeFinal(b64_ctx, *out_buf + outl, &tmpl);   // ⚠ return value ignored (-1 on bad padding)
*out_len = (size_t)outl + (size_t)tmpl;
```
- It uses OpenSSL's streaming base64 decoder. `(int)len` is a narrowing cast; it's safe because
  the line is < 1 MiB. Under `-Wconversion` you need the explicit cast.
- Edge case: an empty signature → `malloc(0)` may return `NULL` → "decode failed" → rejected.
  Either way it's rejected.
- Ignoring `EVP_DecodeFinal`'s result is harmless: a malformed tail means bad DER, so verification
  fails anyway. It's still a review comment ("check every return value"). Simpler alternatives:
  `EVP_DecodeBlock` (but it doesn't strip padding from the length) or a `BIO_f_base64` chain.

## 3.4 `crypto_init()` (L99-155)
```c
DIR *dir = opendir(cert_dir);               // fail → perror → NULL → main exits ✔
crypto_ctx_t *ctx = malloc(sizeof(crypto_ctx_t));
ctx->valid_certs = sk_X509_new_null();      // ⚠ unchecked NULL
while ((entry = readdir(dir)) != NULL) {
    if (entry->d_type != DT_REG && entry->d_type != DT_LNK) continue;
```
- ⚠ `d_type` may be **`DT_UNKNOWN`** on some filesystems (some XFS configs, network FS). Then
  every file is skipped → "no valid certs". Robust code calls `fstatat()` when `DT_UNKNOWN`.
- `DT_LNK` is accepted and `fopen` follows symlinks. A symlink in the trust dir can point
  anywhere. That's acceptable only if the directory itself is root-owned and not
  writable by others. **The security of the whole system reduces to the integrity of this
  directory.** Say that.
- `.` and `..` are `DT_DIR` → skipped. Non-cert files (README, keys) → `PEM_read_X509` returns
  NULL → skipped silently. ⚠ The OpenSSL error queue isn't cleared (`ERR_clear_error`), so it
  accumulates.

```c
snprintf(filepath, sizeof(filepath), "%s/%s", cert_dir, entry->d_name);  // ⚠ truncation not checked (use PATH_MAX & check return)
FILE *fp = fopen(filepath, "r");
X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);   // reads ONLY the first cert in the file (bundles ignored)
fclose(fp);
```
- `PEM_read_X509(fp, x, password_cb, u)`: decodes the `-----BEGIN CERTIFICATE-----` base64 → DER → `X509*`.
- TOCTOU between `readdir` and `fopen` is irrelevant if the directory is trusted.

```c
if (is_cert_valid_for_codesigning(cert)) {
    sk_X509_push(ctx->valid_certs, cert);   // ownership transferred to the stack (⚠ push failure unchecked → leak)
    X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0) → log → OPENSSL_free
} else X509_free(cert);
...
if (sk_X509_num(ctx->valid_certs) == 0) { error; crypto_cleanup(ctx); return NULL; }   // fail-closed ✔
```
- **Fail-closed at startup**: a server with zero trusted keys refuses to start, rather than
  running and rejecting everything (or worse, accepting everything).
- `X509_NAME_oneline` is a legacy format. `X509_NAME_print_ex` with `XN_FLAG_RFC2253` is the
  modern one.

> **What's missing (the biggest crypto finding):** `rootCA.crt` (generated by `gen_pki.sh`) is
> never loaded. No `X509_STORE`, no `X509_verify_cert`. The "untrusted self-signed" test passes
> only because `untrusted.crt` lives in `certs/`, **not** in `certs/trusted/`. Copy it into
> `trusted/` and it becomes fully trusted. The design is effectively **leaf pinning** (like SSH
> `authorized_keys`), which is legitimate, *but the README and guidelines describe an
> `X509_STORE`/CA model*. Own that discrepancy. See chapter 6, F1, for the code to do real path
> validation.

## 3.5 `crypto_verify_signature()` (L160-211)
```c
if (!ctx || !payload || !base64_sig) return STATUS_ERR_INTERNAL;   // defensive
if (!decode_base64(...)) return STATUS_ERR_CRYPTO_FAIL;
```
⚠ Edge: an **empty script** (payload_len 0): is `payload` non-NULL? Yes, it points just past the
newline. The test `test_empty_payload_handling` covers signing an empty file. ✔

```c
for (int i = 0; i < num_certs; i++) {
    X509 *cert = sk_X509_value(ctx->valid_certs, i);
    EVP_PKEY *pubkey = X509_get0_pubkey(cert);     // get0 = borrowed, don't free ✔
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pubkey) == 1)
      if (EVP_DigestVerifyUpdate(mdctx, payload, payload_len) == 1)
        if (EVP_DigestVerifyFinal(mdctx, raw_sig, raw_sig_len) == 1) verified = 1;
    EVP_MD_CTX_free(mdctx);
    if (verified) { log subject; break; }
}
```
Line by line:
- `EVP_DigestVerifyInit(ctx, &pctx_out, md, engine, pkey)`: sets up "hash with SHA-256, then
  verify with this key". Passing `NULL` for `pctx` means we don't tweak parameters (for RSA you'd
  set PSS padding there).
- `Update`: streams the message into the hash. You could call it in chunks.
- `Final`: finishes the hash, parses the DER signature, and does the ECDSA math.
- **Return value discipline**: `EVP_DigestVerifyFinal` returns **1 = valid, 0 = invalid, <0 =
  error**. The code checks `== 1`, which is correct. The famous bug (CVE-2008-5077 class) is
  `if (EVP_VerifyFinal(...))`, which treats -1 as success. **Mention this. Henry will like it.**
- The `if (X == 1)` nesting is idiomatic OpenSSL: any non-1 skips to free.
- **Why the SHA-1 downgrade test is rejected**: the *verifier* decides the hash (`EVP_sha256()`),
  not the attacker. An ECDSA signature over SHA-1(m) doesn't verify as a signature over
  SHA-256(m). Contrast with JWT `alg` header confusion, where the attacker chooses. Principle:
  **never let the message choose the algorithm**.
- **Why RSA signatures are rejected**: every trusted key is EC. An RSA PKCS#1 blob isn't valid
  ECDSA DER, so Final returns 0 (or <0 with an error queued). There's no crash.
- **Trial verification over all keys**: O(n) and fine for a handful of signers. At scale, put a
  *key identifier* in the header (e.g. `# SIG-KEYID: <SKI hex>`) and look it up. That's also
  better for audit logs (you know *who* signed before verifying).
- ⚠ The error queue isn't cleared after failed attempts (`ERR_clear_error`). Each handler is a
  short-lived process, so it doesn't matter in practice.
- `EVP_MD_CTX_new` failing → `continue` (silently skips the key). In theory, fail-closed is
  still preserved because `verified` stays 0.

```c
OPENSSL_cleanse(raw_sig, raw_sig_len);  free(raw_sig);
return verified ? STATUS_OK : STATUS_ERR_CRYPTO_FAIL;
```
Signatures aren't secret, so the cleanse is hygiene, not a requirement. Say that honestly if
asked: "FIPS zeroisation is about CSPs, meaning private keys, seeds, and shared secrets. Here
there are none; the server only holds **public** keys. That's actually a nice property: **the
server has no secrets to steal**. Compromise of the server doesn't let an attacker sign scripts."

## 3.6 `crypto_cleanup()` (L216-226)
```c
sk_X509_pop_free(ctx->valid_certs, X509_free);   // frees each element then the stack
OPENSSL_cleanse(ctx, sizeof(crypto_ctx_t)); free(ctx);
```
`sk_X509_pop_free` is the standard idiom. A plain `sk_X509_free` would leak every cert.

---

## 3.7 "Make it actually FIPS" (Henry will almost certainly go here)

Choosing FIPS-approved *algorithms* ≠ being FIPS compliant. Compliance means **using a validated
module, in its approved mode, only for approved services, within its security policy**.
What the code would need:

```c
#include <openssl/provider.h>
OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
if (!OSSL_LIB_CTX_load_config(libctx, "/etc/ssl/openssl.cnf")) die();   // config includes fipsmodule.cnf
OSSL_PROVIDER *fips = OSSL_PROVIDER_load(libctx, "fips");               // runs POST: integrity check + KATs
OSSL_PROVIDER *base = OSSL_PROVIDER_load(libctx, "base");               // encoders/decoders (PEM/DER) only
if (!fips) die("FIPS provider failed self-test");                       // fail closed
EVP_default_properties_enable_fips(libctx, 1);                          // all fetches get "fips=yes"
EVP_MD *sha256 = EVP_MD_fetch(libctx, "SHA2-256", NULL);
EVP_DigestVerifyInit_ex(mdctx, NULL, "SHA2-256", libctx, NULL, pubkey, NULL);
// and load certs with PEM_read_X509 variants taking libctx (X509_new_ex)
```
- `openssl fipsinstall -out fipsmodule.cnf -module fips.so` computes the module's integrity
  **HMAC** and records the self-test status.
- On **Ubuntu Pro**, `sudo pro enable fips-updates` (or `fips`) installs the certified packages
  (kernel, OpenSSL, libgcrypt, GnuTLS, strongSwan…), sets `fips=1` on the kernel command line
  and reboots. Then `cat /proc/sys/crypto/fips_enabled` → `1`, and OpenSSL picks the FIPS
  provider through the system config.
- Also: check that cert keys are approved (P-256/384/521, RSA ≥ 2048) and reject others at load.
  FIPS 140-3 also wants a **service indicator** (tell the caller whether an approved service was
  used). OpenSSL 3 exposes "indicator" parameters for that.

## Questions you must be able to answer
1. Walk through ECDSA verification. What happens if the signer reuses `k`?
2. DER vs raw `r||s`? Why is the DER signature variable-length?
3. What does `EVP_DigestVerifyFinal` return, and why is `if (ret)` a vulnerability?
4. Why can't an attacker downgrade to SHA-1 here?
5. KU vs EKU? What does RFC 5280 say about a cert without EKU, and what does your code do?
6. What does `X509_verify_cert` check that your code doesn't?
7. Why doesn't the server need any secret? Why is that good?
8. What exactly would you change to run in FIPS approved mode with OpenSSL 3?
9. `get0` vs `get1` in OpenSSL naming?
