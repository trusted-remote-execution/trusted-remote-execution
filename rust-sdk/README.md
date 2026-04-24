# Rust SDK

The Rust SDK is the **safe Rust layer** of the REX (Trusted Remote Execution) environment. It provides Cedar-authorized wrappers for system operations — file I/O, networking, process management, system information, and disk queries — that can be used directly from Rust code or exposed to [Rhai](https://rhai.rs/) scripts through the companion [Rhai SDK](../rhai-sdk/README.md).

Every API call passes through a Cedar authorization check before any system resource is touched. This makes the SDK suitable for executing untrusted or operator-supplied scripts with fine-grained, policy-driven access control.

## Crates

| Crate | Description | Platform |
|-------|-------------|----------|
| `rust-safe-io` | File and directory operations: read, write, copy, move, chmod, chown, gzip, tar, glob search, text replacement, ELF inspection, core dump analysis, and subprocess execution | Linux, macOS |
| `rust-network` | Networking: HTTP client (`reqwest`), raw TCP connections, DNS resolution, and `netstat`-style socket enumeration | Linux, macOS |
| `rust-safe-process-mgmt` | Process enumeration, signal delivery, `systemctl` control, `lsof`/`fuser`-style open-file queries, IPC info, and Linux namespace entry | **Linux only** |
| `rust-system-info` | Memory, swap, CPU, `dmesg`, `sysctl`, `uname`, slab info, and DNS resolver configuration | Linux, macOS |
| `rust-disk-info` | `df`-style filesystem statistics, `iostat` I/O counters, and unmount | Linux, macOS |
| `rust-sdk-common-utils` | Shared types (`DateTime`), random utilities, UNIX signal handling, Cedar authorization helpers, and shared error constants | Linux, macOS |

## Design Principles

- **Cedar-authorized** — every public API takes a `&CedarAuth` reference. The authorization check runs before any system call, so access decisions are always enforced by policy.
- **Path-traversal safe** — `safe-io` is built on [`cap-std`](https://github.com/bytecodealliance/cap-std), which opens files and directories through capability-based file descriptors rather than raw paths. This prevents `../` traversal and eliminates most TOCTOU races.
- **Minimal unsafe code** — unsafe code is forbidden (`#![forbid(unsafe_code)]`) in all crates except `safe-io`, which uses `#[allow(unsafe_code)]` for low-level capability-based file descriptor operations.
- **Builder pattern** — configuration options (open flags, filter criteria, network options, etc.) use the `derive_builder`-generated `*OptionsBuilder` / `*ConfigBuilder` types for ergonomic, compile-time-checked construction.
- **Typed errors** — each crate exposes its own `thiserror`-derived error enum so call sites can match on specific failure modes.

## Authorization Model

All APIs require a `CedarAuth` context. `CedarAuth` holds the compiled Cedar policy, schema, and entity store for the current execution. It is created once per script invocation and threaded through every call.

```rust
use rex_cedar_auth::cedar_auth::CedarAuth;

let policy = r#"
    permit(
        principal,
        action,
        resource is file_system::File
    ) when {
        resource.path like "/var/log/*"
    };
"#;

let (cedar_auth, _warnings) = CedarAuth::new(policy, schema_json, entities_json).unwrap();
```

See the [Cedar Policy Guide](../core/rex-cedar-auth/CEDAR_POLICY_GUIDE.md) for a full reference of namespaces, entity types, and available actions.

### Authorization namespaces quick reference

| Namespace | Covers |
|-----------|--------|
| `file_system` | `safe-io` file and directory operations |
| `network` | `safe-network` HTTP and connection operations |
| `process_system` | `safe-process-mgmt` process listing and signals |
| `systemd` | `safe-process-mgmt` systemctl service control |
| `sysinfo` | `safe-system-info` system information and hostname queries |
| `sysctl` | `safe-system-info` sysctl parameter access |

## Error Handling

Each crate exposes a typed error enum derived with [`thiserror`](https://docs.rs/thiserror):

| Crate | Error type |
|-------|------------|
| `safe-io` | `RustSafeIoError` |
| `safe-network` | `RustNetworkError` |
| `safe-process-mgmt` | `RustSafeProcessMgmtError` |
| `safe-system-info` | `RustSysteminfoError` |
| `safe-disk-info` | `RustDiskinfoError` |

Authorization failures are surfaced as a specific variant (e.g. `RustSafeIoError::AuthorizationError`) so callers can distinguish policy denials from I/O errors.

All functions return `anyhow::Result<T>` or `Result<T, CrateError>`. The two styles can be mixed freely because all crate errors implement `std::error::Error`.

## Platform Support

| Crate | Linux | macOS |
|-------|-------|-------|
| `safe-io` | ✅ | ✅ |
| `safe-network` | ✅ | ✅ |
| `safe-process-mgmt` | ✅ | ❌ |
| `safe-system-info` | ✅ | ✅ |
| `safe-disk-info` | ✅ | ✅ |
| `sdk-common-utils` | ✅ | ✅ |

Some features within a crate are also Linux-specific (e.g. `DiskAllocationOptions`, `ElfInfo`, `CoreDump` in `safe-io`; slab info in `safe-system-info`). These are gated with `#[cfg(target_os = "linux")]`.

## Testing

```sh
# Run all tests in the workspace
cargo test

# Run tests for a single crate
cargo test -p rust-safe-io

# Enable the Cedar test utilities (needed for most integration tests)
cargo test -p rust-safe-io --features rex-cedar-auth/test-utils
```

Integration tests use `TestCedarAuthBuilder` from `rex-cedar-auth` to construct a `CedarAuth` with a purpose-built policy for each test case, keeping tests self-contained and policy-explicit.

## Related Documentation

- [Cedar Policy Guide](../core/rex-cedar-auth/CEDAR_POLICY_GUIDE.md) — entity types, action names, and example policies for every namespace
- [REX environment README](../README.md) — overall architecture, Core crates, and Rhai SDK overview
- [Rhai SDK README](../rhai-sdk/README.md) — Rhai language bindings for the Rust SDK
- [Rex Runner README](../core/rex-runner/README.md) — running Rhai scripts locally with the REX engine
- [Contributing](../CONTRIBUTING.md) — development setup and guidelines
