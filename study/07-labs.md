# Chapter 7: Hands-on labs

Doing beats reading. Each lab takes 10-30 minutes. All commands run from the repo root. `build/`,
`certs/` and `payload.txt` are git-ignored, so you can't dirty the repo.

**Setup (once):**
```bash
make all && make pki
chmod +x study/labs/send.py
# Terminal 1:
./build/bin/crypto_server -c certs/trusted -u /tmp/sec_server.sock
# Terminal 2: run the labs
```
`send.py FILE --sign KEY` signs and sends in one go, and reports timeouts and errors honestly.
Install `strace` (`sudo pacman -S strace`) for labs 5-6.

---

## Part A: Crypto & PKI

### Lab 1: Read your certificates like an auditor
```bash
openssl x509 -in certs/trusted/valid_codesign.crt -noout -text | less
openssl x509 -in certs/trusted/invalid_no_eku.crt -noout -ext extendedKeyUsage   # nothing
openssl x509 -in certs/trusted/valid_codesign.crt -noout -issuer -subject -dates -ext extendedKeyUsage,keyUsage,basicConstraints
openssl verify -CAfile certs/rootCA.crt -purpose codesign certs/trusted/valid_codesign.crt   # real chain + purpose check
openssl verify -CAfile certs/rootCA.crt certs/untrusted.crt                               # fails: not issued by CA
```
**Find**: the public key algorithm and curve, the signature algorithm, and which extensions are
missing (keyUsage, basicConstraints). Compare `openssl verify` (a real chain check) with what your
server does (F1).

### Lab 2: Take a signature apart
```bash
bash scripts/sign_script.sh certs/keys/valid_codesign.key test_scripts/hello_world.sh payload.txt
head -1 payload.txt | sed 's/^# SIG: //' | base64 -d > /tmp/sig.der
openssl asn1parse -inform DER -in /tmp/sig.der        # SEQUENCE { INTEGER r, INTEGER s }
wc -c /tmp/sig.der                                    # 70-72 bytes; sign again: length & bytes change (random k)
tail -n +2 payload.txt > /tmp/body.sh
openssl x509 -in certs/trusted/valid_codesign.crt -pubkey -noout > /tmp/pub.pem
openssl dgst -sha256 -verify /tmp/pub.pem -signature /tmp/sig.der /tmp/body.sh     # Verified OK
echo >> /tmp/body.sh; openssl dgst -sha256 -verify /tmp/pub.pem -signature /tmp/sig.der /tmp/body.sh  # Verification failure
```
**Explain**: why two signatures of the same file differ; why one extra newline breaks it.

### Lab 3: Prove F1 (pinning, not PKI)
```bash
mkdir -p /tmp/tr && cp certs/trusted/*.crt certs/untrusted.crt /tmp/tr/
./build/bin/crypto_server -c /tmp/tr -u /tmp/lab3.sock      # see "Loaded Valid Cert: /CN=Untrusted…"
study/labs/send.py test_scripts/hello_world.sh --uds /tmp/lab3.sock --sign certs/keys/untrusted.key   # APPROVED
```
**Stretch**: implement `X509_verify_cert` in `crypto_init` (code in chapter 6, F1) on a branch, and make
this lab return REJECTED.

### Lab 4: Attacks the suite already covers (run them by hand)
```bash
printf 'echo hi\n' > /tmp/a.sh
study/labs/send.py /tmp/a.sh --sign certs/keys/invalid_no_eku.key   # REJECTED (key not loaded)
openssl genrsa -out /tmp/rsa.key 2048 && study/labs/send.py /tmp/a.sh --sign /tmp/rsa.key   # REJECTED
# SHA-1 downgrade:
openssl dgst -sha1 -sign certs/keys/valid_codesign.key /tmp/a.sh | base64 -w0 | sed 's/^/# SIG: /' > /tmp/p1; echo >> /tmp/p1; cat /tmp/a.sh >> /tmp/p1
study/labs/send.py /tmp/p1                                            # REJECTED
```
Watch the server terminal for the log lines of each case.

### Lab 5: FIPS on your machine (concepts)
```bash
openssl list -providers                       # which providers are active?
openssl list -providers -provider fips 2>&1   # is a FIPS module installed? (probably not on Arch)
openssl list -signature-algorithms | head
cat /proc/sys/crypto/fips_enabled 2>/dev/null # kernel FIPS mode
openssl md5 /etc/hostname                     # works now; in FIPS mode MD5 is refused
```
On an **Ubuntu 22.04/24.04 VM** with a free personal Ubuntu Pro token (up to 5 machines):
`sudo pro attach <token>; sudo pro enable fips-updates; sudo reboot`. Then repeat the commands,
try `openssl md5`, and run your server. This is *the* hands-on experience Henry's team lives in.
Even 30 minutes of it gives you real things to say.

---

## Part B: Linux systems behaviour

### Lab 6: Watch the process tree and syscalls
```bash
# Terminal 1: run the server under strace, following forks
strace -f -e trace=accept,fork,clone,clone3,pipe,pipe2,dup2,setrlimit,prlimit64,execve,wait4,read,write -s 60 \
  ./build/bin/crypto_server -c certs/trusted -u /tmp/sec_server.sock
# Terminal 2:
study/labs/send.py test_scripts/hello_world.sh --sign certs/keys/valid_codesign.key
```
**Map** each syscall to a line in `main.c`/`executor.c`. Find: the two `clone` calls, the
`dup2(…, 0/1/2)`, the three `prlimit64` calls, `execve("/bin/bash", ["bash","-s"], [PATH=…])`
(note the 1-element env!), and `wait4`. Also see bash doing `read(0, …, 1)`: **one byte at a
time**, the root cause of F4/F8.

### Lab 7: Reproduce the sandbox findings (F3, F5, F7, F8, F18, F6)
```bash
K=certs/keys/valid_codesign.key
printf 'ls -l /proc/$$/fd\n'                         > /tmp/f7.sh; study/labs/send.py /tmp/f7.sh --sign $K   # fd 4 = socket
printf 'sleep 30\n'                                  > /tmp/f3.sh; study/labs/send.py /tmp/f3.sh --sign $K --timeout 5
printf 'sleep 6 &\necho main-done\n'                 > /tmp/f5.sh; study/labs/send.py /tmp/f5.sh --sign $K   # ~6 s
printf 'read x\necho "eaten: never printed"\necho after\n' > /tmp/f8.sh; study/labs/send.py /tmp/f8.sh --sign $K
printf 's=A\nwhile true; do s="$s$s"; done\n'        > /tmp/f18.sh; study/labs/send.py /tmp/f18.sh --sign $K  # exit 2
printf 'id; grep -E "NoNewPrivs|Seccomp:|CapEff" /proc/self/status; ulimit -a\n' > /tmp/f6.sh; study/labs/send.py /tmp/f6.sh --sign $K
```
After F3 times out, run `ps -ef --forest | grep -A3 crypto_server` and see the orphaned work still
running. Clean up with `pkill -f 'sleep 30'`.

### Lab 8: The pipe deadlock (F4)
```bash
python3 -c "
print(\"head -c 200000 /dev/zero | tr '\\\\0' x; echo\")
for i in range(5000): print('# padding', i, '.'*30)
print('echo finished')" > /tmp/f4.sh
wc -c /tmp/f4.sh                                     # > 64 KiB
study/labs/send.py /tmp/f4.sh --sign certs/keys/valid_codesign.key --timeout 6   # TIMEOUT
ps -o pid,stat,wchan:20,cmd --ppid $(pgrep -o crypto_server)   # handler…
cat /proc/$(pgrep -n -x bash)/wchan; echo                       # …both blocked in pipe_write / pipe_wait
pkill -n -x bash
```
**Explain it on paper**, then implement the memfd fix on a branch and rerun.

### Lab 9: Slowloris (F13)
```bash
python3 -c "
import socket,time
s=[socket.socket(socket.AF_UNIX) for _ in range(50)]
[x.connect('/tmp/sec_server.sock') for x in s]; time.sleep(20)" &
sleep 1; pgrep -P $(pgrep -o crypto_server) | wc -l     # ~50 children doing nothing
```

### Lab 10: Build pipeline
```bash
make -n prod | head -3                 # F10: says DEVELOPMENT
make -n PROFILE=prod | grep -c ENV_PRODUCTION
make debug 2>&1 | tail -2              # F11: link error
readelf -d build/bin/crypto_server | grep -E 'BIND_NOW|FLAGS'   # RELRO/now
readelf -h build/bin/crypto_server | grep Type                  # DYN = PIE
readelf -s build/bin/crypto_server | grep -E '__stack_chk_fail|_chk@'   # canary + FORTIFY in use
```

### Lab 11: Debug with gdb (child processes)
```bash
gdb --args ./build/bin/crypto_server -c certs/trusted -u /tmp/sec_server.sock
(gdb) set follow-fork-mode child
(gdb) set detach-on-fork off
(gdb) break crypto_verify_signature
(gdb) run
# send a request from another terminal, then:
(gdb) p payload_len
(gdb) p (char*)payload
(gdb) finish        # see the return value
```
For better symbols, build with `make CFLAGS="-std=gnu11 -Iinclude -O0 -g"` (after F11, use
`make debug`).

---

## Part C: Fix it (the best interview prep is a branch with fixes)
Pick 2-3 and do them for real on a branch (`git switch -c hardening`). You'll then speak from
experience:
1. **memfd executor** (F4, F8) with `/dev/null` stdin and sealed memfd.
2. **CLOEXEC everywhere + `close_range`** (F7). Add a test asserting `ls /proc/$$/fd` shows only 0, 1, 2 (and 255, bash's own).
3. **Wall-clock timeout + process-group kill** (F3, F5) using `poll()`. Add tests with `sleep 30` and `sleep 30 &`.
4. **`X509_verify_cert` + CA anchor** (F1). Fix the test that must now fail when the self-signed cert is in the dir.
5. **Fix F10/F11/F12** (30 min total), and watch F12's test go red when you comment out the expiry check.
6. **A systemd unit** with hardening + `systemd-analyze security` score (great for both interviewers):
   ```ini
   [Service]
   ExecStart=/usr/local/bin/crypto_server -c /etc/crypto_server/trusted -u /run/crypto_server/sock
   DynamicUser=yes
   RuntimeDirectory=crypto_server
   NoNewPrivileges=yes
   ProtectSystem=strict
   ProtectHome=yes
   PrivateTmp=yes
   PrivateDevices=yes
   PrivateNetwork=yes          # if UDS only
   RestrictAddressFamilies=AF_UNIX
   CapabilityBoundingSet=
   SystemCallFilter=@system-service
   MemoryMax=512M
   TasksMax=256
   ```
