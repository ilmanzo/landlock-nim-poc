# Landlock Playground (Nim Wrapper)

An idiomatic Nim wrapper for the Linux Landlock LSM (Linux Security Module), providing high-level, safe, and portable sandboxing for Nim applications.

## Features

- **Declarative DSL:** Use the `sandbox:` macro for readable, high-level policy definition.
- **Multi-Domain Support:** Covers Filesystems (v1+), TCP Networking (v4+), and IPC Scoping (v6+).
- **Static Safety:** Use the `Sandboxed` capability type to ensure security-critical logic only runs when restricted.
- **ABI Versioning:** Proactively handles kernel versioning by masking unsupported flags, ensuring forward and backward compatibility.
- **Safe Defaults:** Automatically sets `PR_SET_NO_NEW_PRIVS` before applying restrictions.

## Usage

### Declarative Sandbox

```nim
import landlock

try:
  sandbox:
    allow "/tmp/work", {ReadFile, WriteFile, MakeReg}
    allowNet 443, {ConnectTcp}
    scope {Signal}
  
  # Sandbox is now active
  echo "Running in a restricted environment."
except LandlockError as e:
  echo "Failed to initialize sandbox: ", e.msg
```

## Building and Running

This project uses [Nimble](https://github.com/nim-lang/nimble) for task management.

### Run Unit Tests
To execute the comprehensive verification suite (covers FS, Network, and Scoping):
```bash
nimble test
```

### Run Example Tool
To run the demonstration tool that performs various filesystem, network, and signaling operations:
```bash
nimble example
```

## Documentation

- **Blog Post:** See `landlock_blog_post.md` for a practical guide and technical deep dive.
- **Presentation:** Located in `docs/presentation.md` (viewable with Marp).
- **Official Source:** Visit [landlock.io](https://landlock.io) for the kernel API documentation.

## License
MIT
