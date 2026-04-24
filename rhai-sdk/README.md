# Rhai SDK

The Rhai SDK provides [Rhai](https://rhai.rs/) language bindings for the [Rust SDK](../rust-sdk/README.md). Each crate registers its Rust SDK APIs into the Rhai scripting engine so script authors can call them directly from Rhai scripts. The Cedar authorization context is captured in closures at registration time — it is not visible to or overridable by script authors.

## Crates

| Crate | Rust SDK counterpart | Description | Platform |
|-------|---------------------|-------------|----------|
| `rhai-safe-io` | `rust-safe-io` | File and directory operations, gzip, tar, glob search, subprocess execution, ELF inspection, and core dump analysis | Linux, macOS |
| `rhai-safe-network` | `rust-network` | HTTP client, raw TCP connections, DNS resolution, and socket enumeration | Linux, macOS |
| `rhai-safe-process-mgmt` | `rust-safe-process-mgmt` | Process listing, signal delivery, `systemctl` control, `lsof`/`fuser` queries | **Linux only** |
| `rhai-safe-system-info` | `rust-system-info` | Memory, swap, CPU, `dmesg`, `sysctl`, `uname`, and DNS resolver info | Linux, macOS |
| `rhai-safe-disk-info` | `rust-disk-info` | Filesystem statistics and I/O counters | Linux, macOS |
| `rhai-sdk-common-utils` | `rust-sdk-common-utils` | `DateTime`, duration, random utilities, and shared error types | Linux, macOS |

## Testing

```sh
# Run all tests in the Rhai SDK
cargo test -p rhai-safe-io -p rhai-safe-network -p rhai-safe-process-mgmt \
           -p rhai-safe-system-info -p rhai-safe-disk-info -p rhai-sdk-common-utils
```

For running end-to-end Rhai scripts with the REX engine, see the [Rex Runner README](../core/rex-runner/README.md).

## Related Documentation

- [Rust SDK README](../rust-sdk/README.md) — underlying Rust implementations, authorization model, and platform support
- [Cedar Policy Guide](../core/rex-cedar-auth/CEDAR_POLICY_GUIDE.md) — entity types, action names, and example policies
- [Rex Runner README](../core/rex-runner/README.md) — running Rhai scripts locally with the REX engine
- [REX environment README](../README.md) — overall architecture and project overview
