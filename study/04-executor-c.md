# Chapter 4: `src/executor.c` line by line

File: [src/executor.c](../src/executor.c) (181 lines). Header: [include/executor.h](../include/executor.h).

---

## 4.0 `executor.h`: the limit profiles
```c
#ifdef ENV_PRODUCTION
  LIMIT_NPROC 64, LIMIT_MEM_BYTES 128 MiB, LIMIT_CPU_SEC 5
#else
  LIMIT_NPROC 2048, LIMIT_MEM_BYTES 256 MiB, LIMIT_CPU_SEC 10
#endif
```
- Compile-time policy, selected by `-DENV_PRODUCTION`. ⚠ **`make prod` does not set it** (verified
  with `make -n prod`; only `make PROFILE=prod` works; see chapter 5). So the "production
  binary" you'd hand over actually has dev limits.
- The argument *for* compile-time limits (in `imrpovment.md`): the policy can't be loosened by
  editing a config file. The counter-argument: operators can't tune it without a rebuild, and
  for certification you'd document a *configuration* in the Security Target anyway. A middle
  ground: a config file that may only **tighten** compiled-in maxima.
- Why `NPROC 2048` in dev? `RLIMIT_NPROC` counts **all processes of the real UID**, not just the
  sandbox's children (see F6). On a desktop, your user already runs hundreds of processes, so a
  low limit makes even `bash` fail to fork. This is the tell-tale sign of the per-UID semantics.
  Explain it if asked "why so high?".

## 4.1 `write_all()` (L19-41)
```c
while (nleft > 0) {
    nwritten = write(fd, ptr, nleft);
    if (nwritten <= 0) {
        if (nwritten < 0 && errno == EINTR) nwritten = 0;   // interrupted before writing anything → retry
        else return -1;                                      // EPIPE (client gone), etc.
    }
    nleft -= (size_t)nwritten; ptr += nwritten;
}
```
- `write()` on sockets and pipes may write **fewer bytes than asked** (a *short write*), e.g. when
  the socket buffer is nearly full or a signal interrupts it. Looping until done is mandatory
  for correctness. Many beginners forget this.
- `write() == 0` with `count > 0` is treated as an error, which is safe.
- `const void *buf` → `const char *ptr` so we can do pointer arithmetic byte by byte (arithmetic
  on `void*` is a GNU extension).
- In `main.c`, rejections use a single `write()` rather than `write_all`. That's inconsistent, but
  the messages are tiny.

## 4.2 `execute_script()`: setup (L46-71)
```c
int pipe_in[2];   // parent → child (bash's stdin):  [0] read end, [1] write end
int pipe_out[2];  // child → parent (bash's stdout+stderr)
if (pipe(pipe_in) < 0 || pipe(pipe_out) < 0) ...   // ⚠ if 2nd fails, the 1st leaks (irrelevant: process exits soon)
```
- A pipe is a one-way kernel buffer, **64 KiB by default on Linux** (`F_GETPIPE_SZ`). Writers
  block when it's full; readers block when it's empty. `read()` returns 0 (EOF) only when **all**
  write ends are closed. Remember this: it explains findings F4 and F5.
- ⚠ Not `pipe2(…, O_CLOEXEC)`. Those fds, and `client_fd`, are inherited by bash (F7).

```c
snprintf(header, sizeof(header), "[%s] STATUS: APPROVED\n--- OUTPUT START ---\n", req_id);
write_all(client_fd, header, (size_t)hlen);
pid = fork();
```
APPROVED is sent *before* `fork`. If `fork` fails, the client got APPROVED and then nothing.
That's minor, but the order should be fork, then announce.

## 4.3 The child: building the sandbox (L73-116)

**Order of operations matters.** Walk it like this:

```c
close(pipe_in[1]);   // child never writes to its own stdin: if it kept this, bash would never see EOF
close(pipe_out[0]);  // child never reads its own output
```
**Why closing unused ends is essential**: EOF on a pipe only happens when *every* copy of the write
end is closed. After `fork`, both processes hold all four fds. Forgetting `close(pipe_in[1])` in
the child = bash waits forever for more script.

```c
dup2(pipe_in[0],  STDIN_FILENO);    // fd 0 := pipe read end
dup2(pipe_out[1], STDOUT_FILENO);   // fd 1 := pipe write end
dup2(pipe_out[1], STDERR_FILENO);   // fd 2 := same pipe → stdout & stderr interleaved in one stream
close(pipe_in[0]); close(pipe_out[1]);   // originals no longer needed
```
- `dup2(old, new)` makes `new` refer to the same open file description as `old` (closing `new`
  first). This is *the* standard way to redirect a child's stdio. It's how a shell does `>` and `|`.
- stderr is merged into stdout: simple, but the client can't tell them apart. An alternative is a
  third pipe plus `poll()`.
- `exit(127)` on failure: 127 is the shell convention for "command not found / couldn't exec".

```c
struct rlimit rlim_cpu = {LIMIT_CPU_SEC, LIMIT_CPU_SEC};      setrlimit(RLIMIT_CPU, &rlim_cpu);
struct rlimit rlim_mem = {LIMIT_MEM_BYTES, LIMIT_MEM_BYTES};  setrlimit(RLIMIT_AS,  &rlim_mem);
struct rlimit rlim_nproc = {LIMIT_NPROC, LIMIT_NPROC};        setrlimit(RLIMIT_NPROC,&rlim_nproc);
```
`struct rlimit { rlim_t rlim_cur /*soft*/, rlim_max /*hard*/; }`. Soft = enforced value; hard =
ceiling. An unprivileged process can lower the hard limit but never raise it, so setting
**soft == hard** stops the script from raising its own soft limit. ✔ (Good point.) Limits are
inherited across `fork` and preserved across `execve`.

| Limit | Semantics (man 2 getrlimit) | What actually happens here |
|---|---|---|
| `RLIMIT_CPU` | **CPU seconds** consumed. Soft → SIGXCPU; hard → **SIGKILL**. With soft == hard the kernel checks hard first → SIGKILL. | `while true` gets killed ✔. **`sleep 9999` or a blocking `read` never consume CPU → never killed** (F3, reproduced). |
| `RLIMIT_AS` | Max **virtual address space**. `mmap`/`brk` fail with ENOMEM beyond it. **No signal.** | Reproduced: `bash: xmalloc: cannot allocate…`, **exit code 2**, not SIGKILL. The footer text "SIGKILL – … or Memory exhaustion" is therefore misleading. Also: AS counts *reserved* virtual memory, so it's coarse; multithreaded or JIT programs reserve far more than they use. cgroup `memory.max` limits real usage. |
| `RLIMIT_NPROC` | Max processes for the process's **real UID** (across the whole system!). Checked at `fork`. **Not enforced for root / CAP_SYS_RESOURCE / CAP_SYS_ADMIN.** | Not a per-sandbox limit. With 64 in prod, if the daemon's user already has 64 processes, even benign scripts can't fork. As root it does nothing. cgroup `pids.max` is the right tool. |

⚠ Return values of `setrlimit` are ignored. A failing limit should abort the child (fail-closed):
`if (setrlimit(...) != 0) _exit(126);`.

Missing limits worth naming: `RLIMIT_FSIZE` (max file size the script can write; stops disk
filling), `RLIMIT_NOFILE` (fd exhaustion), `RLIMIT_CORE = 0` (no core dumps that may contain
secrets).

```c
clearenv();                              // glibc/_GNU_SOURCE; equivalent to environ = NULL
setenv("PATH", "/usr/bin:/bin", 1);      // absolute, root-owned dirs only; no "." or relative entries
```
Why it matters, with concrete attacks:
- `LD_PRELOAD` / `LD_LIBRARY_PATH`: inject a shared library into every program the script runs.
- **`BASH_ENV`**: bash *sources this file* at startup for non-interactive shells. That's arbitrary
  code before your verified script runs. (`ENV` for sh.)
- `IFS`, `PS4`, `SHELLOPTS`, exported functions (`BASH_FUNC_x%%`, the Shellshock vector in 2014).
- `PATH=.:…`: hijack `ls` with a local file.
- Proxy variables, `HOME`, `TMPDIR`… route output or files elsewhere.

Note that the env comes from the **daemon's** environment (whoever started it), not from the
client. So this protects against a poisoned *service* environment, and it gives determinism.
That's good practice either way (systemd also starts services with a minimal env).

Even better: `execle`/`execve` with an explicit `envp[] = {"PATH=/usr/bin:/bin", NULL}`, which is
atomic with no global state. Consider `bash --noprofile --norc -p` too (though non-interactive
`-s` doesn't read rc files anyway, except `BASH_ENV`, which is cleared).

```c
execl("/bin/bash", "bash", "-s", NULL);   // absolute path: no PATH lookup; argv[0]="bash"; -s = read commands from stdin
perror("execl failed"); exit(127);        // only reached if exec failed (⚠ _exit would be more correct)
```
- `execl` replaces the process image. The rlimits, fds 0/1/2 and **any other fds without
  `FD_CLOEXEC`** survive.
- ⚠ The `NULL` sentinel should be `(char *)NULL` for variadic-argument portability (pedantic).
- **The comment at L108-110 and L124-126 claims bash "reads the entire script into memory before
  executing". That's false.** When stdin isn't seekable (a pipe), bash reads it **incrementally,
  even byte by byte**, so that commands inside the script can share stdin. Consequences,
  reproduced:
  - **Deadlock (F4)**: a script > 64 KiB whose early commands print > 64 KiB. The parent blocks
    writing the script; bash blocks writing output nobody reads. It hangs forever, and a CPU
    rlimit won't help because both are sleeping.
  - **The script's stdin is the script itself (F8)**: `read x` or `cat` inside the script
    consumes its own remaining source code.
  - Fix: **`memfd_create()`**. Write the verified bytes into an anonymous in-memory file, seal it
    (`F_SEAL_WRITE|F_SEAL_SHRINK|F_SEAL_GROW`) so it can't change after verification, then run
    `bash /proc/self/fd/N` (or `fexecve` for binaries) with `stdin=/dev/null`. Still zero disk
    I/O, no deadlock, no self-reading, and verify-then-exec stays atomic. **This is a strong
    "senior" answer.**

## 4.4 The parent: controller (L117-181)
```c
close(pipe_in[0]); close(pipe_out[1]);     // ★ MUST close pipe_out[1], or read() below never returns 0
write_all(pipe_in[1], payload, payload_len);   // ⚠ blocks if bash isn't reading (F4)
close(pipe_in[1]);                          // EOF for bash
while ((bytes_read = read(pipe_out[0], buf, sizeof(buf))) > 0)
    if (write_all(client_fd, buf, (size_t)bytes_read) < 0) break;   // client gone → stop streaming
close(pipe_out[0]);
```
- This is a sequential "write all, then read all" design. A correct concurrent design uses
  **`poll()`** on both `pipe_in[1]` (POLLOUT) and `pipe_out[0]` (POLLIN), or a separate writer
  thread/process. Or it removes the input pipe entirely (memfd).
- Streaming in 4 KiB chunks gives real-time output with constant memory. ✔
- ⚠ **EOF only arrives when every holder of `pipe_out[1]` closes it.** Background processes the
  script started (`sleep 6 &`, `nohup …&`) inherit stdout. Reproduced: `sleep 6 &` delays the
  response by 6 s. With `sleep infinity &` the handler never finishes (F5).
- If the client disconnects, the loop breaks, but **bash is not killed**. It keeps running, then
  dies of SIGPIPE when it next writes. Better: `kill(pid, SIGKILL)` (or kill the process group)
  on client disconnect.

```c
int status; waitpid(pid, &status, 0);      // ⚠ return value unchecked (would be ECHILD without the SIG_DFL fix in main.c)
if (WIFEXITED(status))        → "EXIT CODE: WEXITSTATUS(status)"     // normal exit(n), n = 0..255
else if (WIFSIGNALED(status)) → sig = WTERMSIG(status); SIGKILL / SIGSEGV / other → "EXIT CODE: -1 [reason]"
else                          → "TERMINATED UNKNOWN"   // only possible with WUNTRACED/WCONTINUED, so effectively dead code
```
- `status` is an encoded int. Always decode it with the `W*` macros.
- Shell convention: a signal-killed child is reported by shells as `128 + signo` (e.g. 137 for
  SIGKILL). The server uses `-1 [reason]` instead, kept for the tests.
- `SIGSEGV` from *bash*? Rare, but `SIGXCPU`, `SIGPIPE` and `SIGABRT` are more likely. A generic
  `strsignal(sig)` would be better than a hand-written table.
- It always returns `STATUS_OK`, even on fork failure in the middle. Fine, since `main` ignores it.

## 4.5 What a *real* sandbox would add (Henry: hardening; Paul: production)

Layer from cheap to strong:
1. **Drop privileges**: run the daemon under a dedicated user (`DynamicUser=yes` in systemd), or
   in the child do `setgroups(0,NULL); setgid(g); setuid(u);` (in that order!) and check the
   results.
2. **`prctl(PR_SET_NO_NEW_PRIVS, 1)`**: setuid binaries (`sudo`, `passwd`) can no longer gain
   privileges. It's a prerequisite for unprivileged seccomp.
3. **Process group / session + wall-clock timeout**: `setsid()` in the child, then the parent
   uses `poll` with a deadline → `kill(-pgid, SIGKILL)` on timeout. That kills background jobs too.
4. **Close all other fds**: `close_range(3, ~0U, 0)` (Linux 5.9+) before exec, or `O_CLOEXEC` everywhere.
5. **cgroups v2** (best done by systemd: `systemd-run --scope -p MemoryMax=128M -p TasksMax=64 -p CPUQuota=50% -p RuntimeMaxSec=10`).
   This gives real memory accounting, a per-sandbox pids limit, and `cgroup.kill` to kill
   everything atomically.
6. **Namespaces** (`unshare`/`clone` flags): `CLONE_NEWNET` (no network), `NEWPID`, `NEWNS` +
   read-only bind mounts / `pivot_root`, `NEWUSER` (unprivileged), `NEWIPC`, `NEWUTS`. Tools:
   `bwrap` (bubblewrap), `nsjail`, `systemd-nspawn`.
7. **seccomp-bpf**: a syscall allowlist (via libseccomp).
8. **LSM**: an **AppArmor** profile for `crypto_server` and the bash child (Ubuntu's default LSM),
   or **Landlock** (unprivileged filesystem sandboxing, Linux 5.13+).
9. **systemd unit hardening** of the daemon itself: `NoNewPrivileges=`, `ProtectSystem=strict`,
   `ProtectHome=`, `PrivateTmp=`, `PrivateDevices=`, `RestrictAddressFamilies=AF_UNIX`,
   `CapabilityBoundingSet=`, `SystemCallFilter=@system-service`, `MemoryDenyWriteExecute=`. Check
   the result with `systemd-analyze security crypto_server.service`.

## Questions you must be able to answer
1. Why must each side close the pipe ends it doesn't use? Give the exact hang each mistake causes.
2. What does `dup2` do? How does a shell implement `cmd > file 2>&1` with it?
3. Soft vs hard rlimit; why set them equal?
4. Why doesn't `RLIMIT_CPU` stop `sleep 1000`? Why doesn't `RLIMIT_AS` produce SIGKILL? Why is `RLIMIT_NPROC` not a per-sandbox limit?
5. Explain the pipe deadlock. Draw the two blocked processes.
6. Why does `sleep 6 &` delay the response by 6 seconds?
7. Name four environment variables that could compromise a bash run.
8. Design the memfd-based executor.
9. List the layers of a production sandbox in the order you'd add them, and justify the order.
