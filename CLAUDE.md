# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run tests
nimble test

# Run example tool
nimble example

# Compile manually (requires --path:./src to find landlock.nim)
nim c -r --path:./src tests/test_landlock.nim
nim c -r --path:./src src/landlock_example.nim /tmp/landlock_demo
```

Requires Nim >= 2.0.0. Linux only (amd64, arm64, riscv64).

## Architecture

Single-file library: `src/landlock.nim`. Everything else is consumer code.

**Layers:**

1. **Raw syscall layer** — direct `syscall()` wrappers for `landlock_create_ruleset`, `landlock_add_rule`, `landlock_restrict_self`, and `prctl(PR_SET_NO_NEW_PRIVS)`. No libc landlock bindings; uses hardcoded syscall numbers.

2. **ABI versioning** — `getAbiVersion()` queries the kernel at runtime. `getBestEffortFsMask/NetMask/ScopeMask(abi)` return only the flags supported by the running kernel, masking out newer flags for backward compatibility.

3. **High-level proc** — `restrictTo(allowedPaths, allowedPorts, scopes, flags)` orchestrates: create ruleset → add FS rules (each path opened with `O_PATH`) → add network port rules → set no-new-privs → restrict self. Returns `Sandboxed` capability on success.

4. **DSL macro** — `sandbox:` block transforms `allow path, {flags}`, `allowNet port, {flags}`, `scope {flags}` statements at compile time into a `restrictTo()` call.

5. **Capability type** — `Sandboxed` is an empty object type used as a proof-of-restriction token for type-safe APIs.

**Key types:** `FsAccess`, `NetAccess`, `Scope` enums map to Landlock ABI flags via compile-time array maps. `LandlockError` is the exception type.

**Test strategy:** Tests compile and run small Nim snippets in child processes (via `runTestHelper`) to get true process isolation for sandbox enforcement checks. ABI version guards (`if getAbiVersion() < N: skip()`) handle older kernels.
