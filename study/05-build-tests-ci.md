# Chapter 5: Build, PKI scripts, tests, CI

## 5.1 Makefile ([Makefile](../Makefile))

### Variables & profiles (L5-50)
- `CC ?= gcc`: `?=` assigns only if not already set (env/CLI override). `:=` is *simple
  expansion* (evaluated once, now). `=` is *recursive* (evaluated at each use).
- `ifeq ($(PROFILE), prod)` is evaluated **when the Makefile is parsed**.

**Bug (F10, verified):**
```make
prod: PROFILE := prod        # target-specific variable, applied only while building 'prod' recipes
prod: clean_objs release
```
`PROFILE_FLAGS` was already computed at parse time with `PROFILE=dev`, so `make prod` prints
"Building with DEVELOPMENT sandbox limits" and compiles **without** `-DENV_PRODUCTION`. Only
`make PROFILE=prod` works. Fix: make it lazy, e.g.
`PROFILE_FLAGS = $(if $(filter prod,$(PROFILE)),-DENV_PRODUCTION,)` with `=` instead of `:=`, and
build `BASE_CFLAGS` with `=` too. Or just have `prod:` call `$(MAKE) PROFILE=prod release`.

### Hardening flags (L52-69): know each one cold
| Flag | What it does | Attack it mitigates |
|---|---|---|
| `-D_FORTIFY_SOURCE=2` | glibc replaces `memcpy`, `strcpy`, `sprintf`… with checked versions when the compiler knows the buffer size; aborts on overflow. **Needs `-O1`+** (`=3` uses `__builtin_dynamic_object_size`; Ubuntu 24.04+ defaults to 3) | Buffer overflows in libc calls |
| `-fstack-protector-strong` | Canary between locals and the return address in functions with arrays/address-taken locals; checked before return | Stack smashing → RIP overwrite |
| `-fPIE` + `-pie` | Position-independent executable, so the binary itself is randomised by ASLR | ROP needing fixed code addresses |
| `-Wl,-z,relro,-z,now` | **Full RELRO**: resolve all symbols at load time, then make the GOT read-only | GOT overwrite |
| `-Wformat -Wformat-security` | Warn on non-literal format strings | Format string attacks (`printf(user)`) |
| `-Wall -Wextra -Werror -pedantic -Wconversion -Wshadow` | Strict warnings as errors; `-Wconversion` catches silent narrowing (hence all the `(size_t)` casts) | Integer truncation bugs |

**Missing compared with Ubuntu's own defaults / OpenSSF compiler-hardening guide**:
`-fstack-clash-protection` (Ubuntu default), `-fcf-protection` (Intel CET shadow stack/IBT,
Ubuntu default on amd64), `-Wl,-z,noexecstack`, `-Wl,--as-needed`, `-D_FORTIFY_SOURCE=3`,
`-Wformat=2`, `-Wstrict-prototypes`, `-Wl,-z,nodlopen`, `-fno-delete-null-pointer-checks`,
`-ftrivial-auto-var-init=zero`. Note: Ubuntu's gcc *already* enables many of these by default
(`gcc -Q --help=common | grep protector`, or `dpkg-buildflags --get CFLAGS`). Check the binary
with `checksec --file=build/bin/crypto_server` or `readelf -d … | grep BIND_NOW`.

### Debug / coverage
- `DEBUG_CFLAGS` adds ASan + UBSan (`-fsanitize=address,undefined`), `-U_FORTIFY_SOURCE`
  (FORTIFY and ASan conflict) and `--coverage`.
- **Bug (F11, verified): `make debug` fails to link** (`undefined reference to __gcov_merge_add`)
  because `--coverage` is in CFLAGS but not in `DEBUG_LDFLAGS`. ASan has therefore probably never
  run on this code.
- **Bug: `clean_objs` deletes `$(VENV)/*`**, and `prod`, `debug` and `coverage` all depend on
  `clean_objs`. So `make coverage` wipes your Python virtualenv before running pytest.
- `coverage` uses gcov (instrumentation writes `.gcda` files when the process *exits normally*).
  Children killed by SIGKILL or ending in `_exit` don't flush coverage. Your `exit()` calls in
  children are what make coverage work, which is ironic given F9. With `_exit` you'd call
  `__gcov_dump()` under `#ifdef`.
- `LCOV_EXCL_LINE` markers exclude defensive branches. This is honest only when the branch is
  genuinely untestable. **The expiry/not-yet-valid branches are testable and are excluded**,
  combined with the broken test F12. Expect a question from Paul like "how do you get 100%
  coverage?". Say: "partly by exclusion, and I'd now rather use fault injection: `LD_PRELOAD`
  shims or `--wrap=malloc` to fail `malloc`/`fork`/`pipe`, and unit tests for `crypto.c`".

### Other Makefile notes
- Header dependencies are hand-written and incomplete (`crypto.o` depends on `server.h` via
  `crypto.h`, which isn't listed). Use `-MMD -MP` and `-include $(OBJS:.o=.d)`.
- `.PHONY` lists `prod` twice. `help` mentions `clean_cov` but the target is `clean_coverage`.
- README says `make trigger SCRIPT=dos_script`, but the file is `dos.sh` → `SCRIPT=dos`.
- `test: release pki` regenerates **all keys on every test run**. Fine for tests, but it means
  test results never depend on stale certs (good).

## 5.2 `scripts/gen_pki.sh` ([file](../scripts/gen_pki.sh))
```bash
set -e                                                    # stop at first failing command (also consider -u -o pipefail)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"   # resolve script location regardless of cwd
openssl ecparam -name prime256v1 -genkey -noout -out rootCA.key    # P-256 private key (SEC1 "EC PRIVATE KEY" PEM)
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 3650 -subj "/CN=…"  # self-signed root
openssl req -new -key valid_codesign.key -out x.csr -subj "/CN=Valid Code Signer"  # CSR = PKCS#10
echo "extendedKeyUsage = codeSigning" > codesign.ext
openssl x509 -req -in x.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -extfile codesign.ext -days 365 -sha256  # CA signs leaf
```
- 4 identities: Root CA, valid code signer (CA-issued + EKU), signer **without** EKU (CA-issued),
  and an untrusted self-signed signer **with** EKU (`-addext`).
- Placement is what drives "trust": `trusted/` gets `valid_codesign.crt` and `invalid_no_eku.crt`
  (filtered by EKU at load). `rootCA.crt` and `untrusted.crt` sit in `certs/` and are never read.
- `-nodes` = "no DES": don't encrypt the private key. Keys are written with the default umask
  (likely 0644, **world-readable private keys**). For real keys: `umask 077`, or better, an
  HSM/PKCS#11 or a signing service. ⚠ The leaf certs lack `keyUsage=digitalSignature` and
  `basicConstraints=CA:FALSE`. The Root lacks an explicit `keyUsage=keyCertSign`. A proper
  `openssl.cnf` profile sets those.
- Inspect what you generated: `openssl x509 -in certs/trusted/valid_codesign.crt -noout -text`.

## 5.3 `scripts/sign_script.sh` ([file](../scripts/sign_script.sh))
```bash
SIGNATURE=$(openssl dgst -sha256 -sign "$KEY_FILE" "$INPUT_FILE" | base64 -w 0)   # DER ECDSA sig → one-line base64
echo "# SIG: $SIGNATURE" > "$OUTPUT_FILE"
cat "$INPUT_FILE" >> "$OUTPUT_FILE"
```
- `openssl dgst -sha256 -sign`: hash the file with SHA-256, then sign with the private key. The
  output is DER. Modern equivalent: `openssl pkeyutl -sign -rawin -digest sha256` (OpenSSL 3).
- `-w 0` is GNU coreutils only (macOS `base64` differs).
- **Without `pipefail`**, if `openssl` fails, the pipeline status is `base64`'s (success) → empty
  signature written. `set -o pipefail` fixes it.
- Invariant: bytes after line 1 == original file bytes. The server relies on it.
- Verify independently (a great live demo):
  ```bash
  tail -n +2 payload.txt > body.sh
  head -1 payload.txt | sed 's/^# SIG: //' | base64 -d > sig.der
  openssl x509 -in certs/trusted/valid_codesign.crt -pubkey -noout > pub.pem
  openssl dgst -sha256 -verify pub.pem -signature sig.der body.sh      # "Verified OK"
  openssl asn1parse -inform DER -in sig.der                            # SEQUENCE { INTEGER r, INTEGER s }
  ```

## 5.4 Test suite ([tests/](../tests/))

**Architecture**: black-box integration tests. A session-scoped fixture starts the real binary
on a UDS in a temp dir ([conftest.py](../tests/conftest.py)). Helpers sign with the real shell
script and talk over real sockets ([helpers.py](../tests/helpers.py)). They test the system *as
deployed*, which is good for security boundaries.

| File | Covers |
|---|---|
| [test_execution.py](../tests/test_execution.py) | happy path; stderr + exit 42; empty script; 100 KB output (pipe-buffer); bash syntax error (exit 2); background process |
| [test_crypto.py](../tests/test_crypto.py) | tampering; missing prefix; invalid base64; valid base64 but garbage DER; CRLF on line 1; **signature swapping** |
| [test_pki.py](../tests/test_pki.py) | no-EKU signer; untrusted signer; rogue ECDSA key; **RSA algorithm confusion**; **SHA-1 downgrade**; time validity (**broken**); missing/empty cert dir |
| [test_sandbox.py](../tests/test_sandbox.py) | >1 MiB payload; 5 concurrent clients; env scrubbing; CPU bomb; memory bomb; half-open client; CLI args; TCP + missing newline |

**Weaknesses a TDD person (Paul!) will see:**
1. **F12: `test_startup_cert_time_validations` tests nothing.** Indentation error: the test body
   only does imports. `generate_time_shifted_cert` and every assertion are dedented into a
   module-level helper that's never called (and it would call itself recursively). It passes in
   0.07 s. A test that can't fail is worse than no test. Lesson: **see every test fail first**
   (red → green).
2. `send_to_server` **swallows exceptions** and returns `"ERROR: …"`. So any negative assertion
   (`"APPROVED" not in response`) passes vacuously on connection failure. E.g.
   `test_dos_protection_payload_size` actually passes because of `BrokenPipeError`.
3. Weak assertions: memory test asserts only `"EXIT CODE: 0" not in`; untrusted/RSA/SHA-1 tests
   don't check the reason.
4. `time.sleep(0.5)` for server readiness → flaky on slow CI. Instead, poll until the socket
   file exists or `connect` succeeds, with a timeout. Server output goes to `DEVNULL` (no logs
   on failure). Capture to a file and attach it on failure.
5. The fixed TCP port `8888` can collide. Use port 0 and read it back, or a free-port helper.
6. One session-wide server: tests aren't fully isolated (a hung handler can affect others).
7. No **unit tests** for C (`decode_base64`, parser). The parser could be extracted as a pure
   function `parse_request(buf, len, &sig, &payload)` and **fuzzed** with libFuzzer/AFL++.
   Fuzzing parsers is exactly what a security team values.
8. `datetime.UTC` needs Python ≥ 3.11. GitLab CI uses `ubuntu:22.04` (Python 3.10). It only
   "works" because the code is never executed.
9. `requirements.txt` isn't pinned (reproducibility).
10. No test for: wall-clock hang, large script deadlock, background `sleep infinity`, fd leakage,
    privilege, replay. These are exactly the findings in chapter 6.

## 5.5 CI ([.github/workflows/ci.yml](../.github/workflows/ci.yml), [.gitlab-ci.yml](../.gitlab-ci.yml))
- Both: install deps → `make all` → `make pki` → `make test`. GitLab splits build and test stages
  and passes the binary as an artifact, but the `test` stage rebuilds anyway (`test: release pki`).
- Missing (good "what would you add" answers): matrix over Ubuntu 22.04/24.04 and gcc/clang;
  `make debug` + run tests under ASan/UBSan; `make coverage` with a threshold;
  **static analysis** (`cppcheck`, `clang-tidy`, `scan-build`, `gcc -fanalyzer`, CodeQL);
  `shellcheck` on scripts; a valgrind run; a fuzzing smoke run; `checksec` assertion on the
  binary; pin actions by SHA (`actions/checkout@v3` is outdated, and pinning by SHA is a
  supply-chain best practice); upload test logs as artifacts.

## Questions you must be able to answer
1. Explain each hardening flag and the attack it blocks. What's missing compared with Ubuntu defaults?
2. Why does `make prod` not produce a prod build? How do you fix it?
3. Why does FORTIFY need optimisation? Why disable it under ASan?
4. How does gcov get data out of a forked child? What breaks it?
5. Why is `test_startup_cert_time_validations` passing? What process would have caught it?
6. Why does `send_to_server` returning `"ERROR"` make some tests meaningless?
7. What would you add to CI first, and why?
