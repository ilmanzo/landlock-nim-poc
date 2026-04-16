# Landlock Playground (Nim Wrapper)

Idiomatic Nim wrapper for Linux Landlock LSM. High-level, safe, portable sandboxing.

## Features

- **Declarative DSL:** `sandbox:` macro for readable policy definition
- **Multi-Domain:** Filesystem (v1+), TCP Network (v4+), IPC Scoping (v6+)
- **Capability Type:** `Sandboxed` proof enforces security-critical logic only runs when restricted
- **Path Safety:** Validates absolute paths, canonicalizes symlinks, rejects relative paths
- **Type-Safe Flags:** Enum-based flags instead of raw integers
- **Builder Pattern:** Fluent API for complex policies with validation
- **Introspection:** Query if sandboxed, retrieve capability proof
- **ABI Versioning:** Auto-masks unsupported flags for kernel compatibility
- **Safe Defaults:** Auto-sets `PR_SET_NO_NEW_PRIVS`

## Usage

### Declarative Sandbox (Recommended)

```nim
import landlock

try:
  # Must capture or discard - enforces awareness
  discard sandbox:
    allow "/tmp/work", {ReadFile, WriteFile, MakeReg}
    allowNet 443, {ConnectTcp}
    scope {Signal}
  
  # Sandboxed. Allowed operations work.
  writeFile("/tmp/work/file.txt", "OK")
  
  # Denied operations fail.
  writeFile("/etc/passwd", "DENIED")  # Kernel blocks this
except LandlockError as e:
  echo "Sandbox failed: ", e.msg
```

### Builder Pattern (For Complex Policies)

```nim
import landlock

var policy = newSandboxPolicy()
policy.allowPath("/tmp", {ReadFile, WriteFile, MakeReg})
      .allowPath("/home/user/data", {ReadFile, ReadDir})
      .allowPort(443, {ConnectTcp})
      .addScope(Signal)

# Validate before applying
let errors = policy.validate()
if errors.len > 0:
  for err in errors:
    echo "Error: ", err
  quit(1)

# Apply and capture capability
let sb = policy.apply()
```

### Helper Procedures

```nim
# Read-only access to paths
discard restrictToRead(@["/tmp", "/home/user/data"])

# Single directory with custom permissions
discard restrictToDir("/tmp/work", {ReadFile, WriteFile, MakeReg, MakeDir})

# Network-only (no filesystem access)
discard restrictToNetworkOnly(@[(443'u64, {ConnectTcp}), (8080'u64, {BindTcp})])
```

### Capability Type Enforcement

```nim
# Functions can require proof of sandboxing
proc dangerousOp(proof: Sandboxed, data: string) =
  # Only callable when sandboxed
  processData(data)

let sb = restrictToRead(@["/tmp"])
dangerousOp(sb, "safe")  # OK - we have proof

# dangerousOp(???, "unsafe")  # Compile error - no proof
```

### Introspection

```nim
# Check if already sandboxed
if isSandboxed():
  echo "Already restricted"

# Retrieve capability after sandboxing
discard restrictToRead(@["/tmp"])
let cap = getSandboxedCapability()
if cap.isSome:
  dangerousOp(cap.get, "data")
```

## Requirements

- **Nim:** >= 2.0.0
- **OS:** Linux only (amd64, arm64, riscv64)
- **Kernel:** Landlock support (5.13+ recommended, check with `getAbiVersion()`)

## Building and Running

Uses [Nimble](https://github.com/nim-lang/nimble).

### Run Tests
Comprehensive test suite (22 tests covering all features):
```bash
nimble test
```

### Run Example
Demo tool showing filesystem, network, and signaling operations:
```bash
nimble example
```

### Manual Compilation
```bash
# Requires --path:./src to find landlock module
nim c -r --path:./src src/landlock_example.nim /tmp/demo
```

## Important Notes

- **Paths must be absolute:** Relative paths rejected at runtime
- **Return values enforced:** Must capture `Sandboxed` result or explicitly `discard`
- **Validation recommended:** Use `policy.validate()` before applying complex policies
- **Thread-local state:** Introspection tracks per-thread sandboxing
- **Wrapper version:** Check `LandlockWrapperVersion` constant (currently "0.1.0")

## Documentation

- **Inline docs:** All exported APIs have comprehensive documentation
- **Blog Post:** See `landlock_blog_post.md` for practical guide
- **Presentation:** `docs/presentation.md` (viewable with Marp)
- **Official Landlock:** [landlock.io](https://landlock.io) for kernel API docs

## License
MIT
