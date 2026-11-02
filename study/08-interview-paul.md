# Chapter 8: Software architecture & engineering interview (Paul Goins)

## 8.1 Read the interviewer
- **Senior Reliability Engineer**, Canonical Managed Solutions (ex-BootStack) since 2019: runs
  customer OpenStack/Kubernetes clouds, triages outages, writes **Juju charms** (Python).
- Before that: **architect/lead of an 8-person team at Intel** (a Python microservices test
  framework, plugin architecture, moved the team from code freezes to **continuous delivery**,
  primary code reviewer, refocused the project on **performance, scalability and security**).
- Self-description: *"enthusiastic about software craftsmanship (TDD, code reviews, clean
  architecture) and encouraging better engineering practices"*.
- He's **not** on the security team. He's a cross-functional "engineering bar" interviewer.
  Expect him to care about: **testability, failure modes, operability, clarity of design,
  trade-offs, and how you collaborate.** He'll think like an operator: *"What happens at 3 am
  when this breaks at a customer site?"*

What wins with him: clear reasoning about trade-offs, honest self-critique, test discipline,
operational thinking (timeouts, back-pressure, logs, metrics, packaging, upgrades), and
respectful code-review style.

## 8.2 Likely question areas and model answers

### A. "Walk me through the architecture."
Use the 30-second pitch ([00-START-HERE](00-START-HERE.md)), then draw the 3-process diagram
([01](01-big-picture.md)). Emphasise **separation of concerns** (transport / crypto policy /
execution), the **opaque crypto context**, and **fail-fast startup**. End with "here's what I'd
change", which leads to C.

### B. "Why fork-per-connection? Why not threads, epoll, or a worker pool?"
> "Executing bash requires `fork`+`exec` anyway, and the process is the natural unit for rlimits
> and isolation. A crash or memory corruption in one request's parsing can't affect others or
> the daemon, and no shared mutable state means no locking. The cost: unbounded children and
> per-connection fork overhead. The workload is low-rate and the execution is heavy, so fork cost
> is noise. **What's missing is admission control.** I'd cap concurrent children, add read
> deadlines, and reject early. If throughput ever mattered, an event loop (epoll) for I/O plus a
> bounded pool of execution workers would be next, but I'd measure first."

Threads would be a bad fit: `fork` in a multithreaded process is dangerous (only the calling
thread survives; locks held by other threads stay locked), and per-request rlimits are
per-process.

### C. "What would v2 look like?" (whiteboard; prepare this)
```
                 systemd (socket activation, hardening, restart, journald)
                         │  /run/crypto-exec.sock (0660, group crypto-exec), SO_PEERCRED policy
              ┌──────────▼───────────┐
              │ crypto-execd (daemon)│  config: /etc/crypto-exec/config.toml (limits may only tighten)
              │  - admission control │  metrics: requests_total{result}, verify_fail_total, exec_seconds, active
              │  - framing/proto v2  │  logs: structured (journald), req_id, signer, sha256(script), result
              └───┬──────────────┬───┘
                  │ pure functions, unit-tested + fuzzed
     ┌────────────▼───┐   ┌──────▼──────────────────────────────────┐
     │ verifier       │   │ executor                                  │
     │ CMS sig + chain│   │ memfd (sealed) → bash /proc/self/fd/N     │
     │ X509_verify_cert│  │ stdin=/dev/null; poll() I/O; deadline     │
     │ fips provider   │  │ setsid + cgroup per job (pids/mem/cpu),   │
     │ replay window   │  │ userns/netns, seccomp, AppArmor, drop uid │
     └────────────────┘   └───────────────────────────────────────────┘
```
Key decisions to explain: **protocol v2** (versioned, length-prefixed, includes key ID +
timestamp/nonce covered by the signature); **policy separated from mechanism**; **delegate
isolation to systemd/cgroups** rather than re-implementing it; **observability built in**.

### D. Testing / TDD (his favourite)
- "How did you test it?" → black-box integration tests via real sockets, adversarial cases.
  Then **volunteer the gaps**: no C unit tests; swallowed exceptions make negative tests
  vacuous; the no-op time test (F12); sleep-based readiness; fixed ports. Say what you learned:
  *"I now watch every new test fail first; a test that can't fail is false assurance, which is
  worse than a missing test in a security context."*
- "How would you restructure for testability?" → extract `parse_request()` as a pure function
  (buffer in, struct out, no I/O). Inject the clock into cert validation (`X509_cmp_time(t,
  &now)`) so expiry is testable without forging certs. Make the executor take an fd, not a
  socket, and return a result struct. Then unit tests (e.g. with `cmocka` or `Unity`), and a
  **libFuzzer** harness on the parser and base64/DER paths.
- Test pyramid: many fast unit tests, fewer integration tests, a few end-to-end tests (systemd
  unit in a VM/LXD container).
- Coverage: "100% line coverage was partly achieved via exclusions. I'd rather report honest
  branch coverage and use fault injection (`-Wl,--wrap=malloc`, `LD_PRELOAD`) for the
  error paths."

### E. Reliability / operations (his day job)
| Concern | Current | Improvement |
|---|---|---|
| Hangs | No timeouts (F3, F13) | Read deadline, execution deadline, process-group/cgroup kill |
| Overload | Unbounded fork | Concurrency cap, `TasksMax`, early reject with a clear status |
| Logs | stdout, duplicated (F9), not tagged with req_id in server logs | journald/syslog `LOG_AUTHPRIV`, structured key=value, req_id everywhere, hash of executed script for audit |
| Metrics | none | Counters for approved/rejected by reason, histograms of exec time; Prometheus endpoint or statsd |
| Lifecycle | foreground, SIGTERM stops accept, children orphaned, socket file left | systemd `Type=simple`, `ExecReload` → SIGHUP reloads certs, graceful drain with timeout, `RuntimeDirectory=` |
| Config | compile-time (and `make prod` broken, F10) | config file + validation at startup; secure defaults compiled in |
| Deploy | `make` | **Debian package** (`debian/` dir, `dh`, systemd unit via `dh_installsystemd`), or a **snap** (strict confinement), or a **Juju charm** that installs, configures certs, and exposes actions. Mention the charm: it's his world |
| Upgrades | n/a | Certificate rotation without downtime (load new + old, then remove old) |

### F. Code review scenario
He may show code (maybe yours) and ask what you'd comment. Practise on your own files with the
chapter 6 list. Style of a good review comment: **specific, explains why, suggests a fix,
separates blocking from nit.** Example:
> *Blocking:* `execute_script` writes the whole payload before reading output. bash reads stdin
> incrementally, so a >64 KiB script with heavy early output deadlocks (repro attached). Suggest
> memfd or a poll loop. *Nit:* `setup_signals()` → `setup_signals(void)`.

### G. Error handling philosophy in C
- Check every return value; fail closed; one cleanup path (`goto cleanup`); free in reverse order
  of acquisition; differentiate *client errors* (reply REJECTED) from *internal errors*
  (log, 500-equivalent); never leak internal detail to the client (single generic crypto
  failure reason, which you did).
- The unified `server_status_t` was a good start but wasn't propagated, e.g. `execute_script`'s
  result is ignored.

### H. Language and tooling choices
- **Why C?** The role is about C crypto libraries; direct access to POSIX + OpenSSL; small
  attack surface binary. The downside is memory safety, mitigated by hardening flags, sanitizers,
  fuzzing, and small code size. *Would you use Rust?* "For a new daemon, quite possibly: `openssl`
  crate or `rustls` + `nix`. But for FIPS on Ubuntu the validated module is OpenSSL's FIPS
  provider, so I'd still call into libcrypto."
- **Why Python for tests?** Fast to write adversarial clients; the `cryptography` lib for
  forging certs; pytest fixtures for lifecycle. Typed with annotations.

### I. A system-design question tied to the job (good chance of something like this)
*"Design a way to audit 10,000 Ubuntu machines against CIS/STIG and remediate."*
1. **Content**: rules as data (ComplianceAsCode-style): for each rule an ID, description,
   **check** (OVAL / script), **remediation** (bash + Ansible), applicability (release,
   package present), severity, profile membership (CIS L1/L2 server, DISA-STIG), and tailoring.
2. **Agent side**: `usg audit <profile>` (OpenSCAP engine) on each host via a timer or
   orchestration; produces XCCDF results (ARF XML) + HTML. Read-only by default; `usg fix` or
   generated scripts/Ansible for remediation, **with dry-run, change review, and staged
   rollout** (canaries → 10% → all) since hardening can break workloads (e.g. disabling
   `ip_forward` on a router, `noexec` on `/tmp` breaking installers).
3. **Collection**: push results to a central store (object storage + DB); idempotent uploads;
   host identity; signed results if integrity matters.
4. **Reporting**: compliance % per profile, per rule, drift over time; exceptions/waivers with
   expiry and justification (auditors need this).
5. **Ops**: rate-limit scans, avoid thundering herd (jitter), handle offline hosts, version the
   content (results must say which benchmark version they were checked against).
6. **Testing the content**: each rule tested in LXD/VMs: a pass fixture, a fail fixture, and
   "remediation makes the check pass and is idempotent". This is CI for compliance content.

### J. Behavioural-technical (expect 1-2)
Prepare a 2-minute **STAR** story for each:
- A design you changed after review feedback (the SIGCHLD/`waitpid` bug is a good technical one:
  the symptom, the root cause in fork-inherited signal dispositions, the fix).
- A time you disagreed in code review / with a teammate.
- Something you'd do differently on this project (F12 test + "red first" lesson; or FIPS
  wording).
- How you work remote and asynchronously: written design docs, small PRs, clear commit messages.
  (Your commit history: `improvments`, `project done and tested`… Be ready to say you'd write
  more descriptive commits in a team; he may notice.)

## 8.3 Questions to ask Paul
- "How does the Managed Solutions team interact with the Security Hardening team? Do FIPS or
  hardened deployments create operational pain you see first-hand?"
- "What does good engineering practice look like at Canonical: review norms, testing
  expectations for C vs Python code?"
- "From an operator's perspective, what makes a hardening tool easy or hard to run at customer
  scale?"
- "What do you wish engineers on product teams understood better about running software in
  production?"

## 8.4 Rapid-fire self-test
1. Name three single points of failure or hang in the current design.
2. Explain copy-on-write and why `fork` per connection is cheap.
3. How would you make certificate reload possible without restart? (SIGHUP → set flag → main loop rebuilds ctx → new children use the new ctx; old children keep theirs.)
4. How do you prevent a log-injection attack via client data? (Don't log raw script; escape or quote; length-limit; structured logging.)
5. What metrics would you alert on? (Rejected rate spike = possible attack or expired cert; exec timeouts; active children near cap; daemon restarts.)
6. How would you package and roll it out to a fleet? (deb/snap + systemd unit; charm for config; canary rollout; health check = can verify a known signed no-op script.)
