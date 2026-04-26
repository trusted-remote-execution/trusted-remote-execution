# Trusted Remote Execution (REX)

REX is a secure script execution engine that uses [Cedar](https://www.cedarpolicy.com/) policies to authorize every system operation a script performs. Scripts are written in [Rhai](https://rhai.rs/) and run inside a sandboxed environment where file I/O, network access, process management, and system queries are each gated by fine-grained Cedar authorization checks.

Cedar is a language for writing and enforcing authorization policies. REX integrates Cedar so that each API call — opening a file, reading a directory, resolving a hostname — is authorized against a declared policy before execution. This gives operators precise control over what a script can and cannot do.

## Key Properties

- **Cedar-authorized** — every resource access is checked against a Cedar policy at runtime
- **TOCTOU-mitigated** — file descriptors are used instead of paths where possible, reducing symlink and race-condition attacks
- **Sandboxed** — scripts run in Rhai with no direct access to the host; all operations go through authorized Rust APIs

## Quick Start

### 1. Install rex-runner

```sh
cargo install rex-runner
```

### 2. Create a policy file

```sh
cat > rex-policy.cedar << 'EOF'
// Allow opening /tmp on Linux, or /private/tmp on macOS (symlink target)
permit(
    principal,
    action in [file_system::Action::"open"],
    resource
) when {
    resource == file_system::Dir::"/tmp" ||
    resource == file_system::Dir::"/private/tmp"
};

// Allow opening, reading, writing, and creating the file on either platform
permit(
    principal,
    action in [file_system::Action::"open", file_system::Action::"read",
               file_system::Action::"write", file_system::Action::"create"],
    resource
) when {
    resource == file_system::File::"/tmp/rex-hello-world" ||
    resource == file_system::File::"/private/tmp/rex-hello-world"
};
EOF
```

### 3. Create a script file

```sh
cat > rex-script.rhai << 'EOF'
// Build the file path from the script argument
let path = "/tmp/" + file_name;

// Write a greeting to the file (replace mode overwrites if it already exists)
write([write::replace], path, "Hello from REX!\n");

// Read and return the file contents
let contents = cat(path);
contents
EOF
```

### 4. Create a script arguments file

```sh
cat > rex-script-args.json << 'EOF'
{
  "file_name": { "stringValue": "rex-hello-world" }
}
EOF
```

### 5. Run the script

```sh
rex-runner \
  --script-file rex-script.rhai \
  --policy-file rex-policy.cedar \
  --script-arguments-file rex-script-args.json \
  --output-format human
```

> **Try it:** Remove one of the `permit` statements from `rex-policy.cedar` and re-run the script. REX will deny the unauthorized operation and return an authorization error, demonstrating that the policy is enforced at runtime.

## Workspace Structure

The workspace is organized into three layers:

### Core

| Crate | Description |
|-------|-------------|
| `rex-cedar-auth` | Cedar policy validation and authorization engine |
| `rex-runner` | Script execution engine that runs signed Rhai scripts |
| `rex-runner-registrar` | Rhai engine builder and SDK function registration |
| `rex-logger` | Structured logging with tracing and in-memory log capture |
| `rex-metrics-and-alarms` | Metrics and alarm collection for script execution |
| `rex-runner-registrar-utils` | Macros for registering Rust functions into Rhai |
| `rex-sdk-registry` | Centralized SDK function registration |
| `rex-redaction` | Content redaction utilities |
| `rex-policy-schema` | Default Cedar policy and schema definitions |
| `rex-test-utils` | Test helpers for I/O, assertions, and Rhai engine setup |

### Rust SDK

Safe Rust implementations of system operations, each with Cedar authorization:

| Crate | Description |
|-------|-------------|
| `rust-safe-io` | File and directory operations (read, write, copy, move, search, chmod, gzip, etc.) |
| `rust-safe-network` | Networking operations (netstat, hostname, nc, nslookup, dig, curl, openssl) |
| `rust-safe-process-mgmt` | Process listing, signals, systemctl, and namespace operations |
| `rust-safe-system-info` | Memory, swap, CPU, hostname, dmesg, sysctl, and slab info |
| `rust-safe-disk-info` | Filesystem stats (df), iostat, and unmount |
| `rust-sdk-common-utils` | Shared types (DateTime), signal handling, and Cedar auth helpers |

### Rhai SDK

Rhai bindings that expose the Rust SDK to scripts:

| Crate | Description |
|-------|-------------|
| `rhai-safe-io` | Rhai bindings for file/directory/gzip/archive/execute operations |
| `rhai-safe-network` | Rhai bindings for HTTP and DNS |
| `rhai-safe-process-mgmt` | Rhai bindings for process and systemctl operations |
| `rhai-safe-system-info` | Rhai bindings for system info, sysctl, and disk info |
| `rhai-safe-disk-info` | Rhai bindings for filesystem and iostat queries |
| `rhai-sdk-common-utils` | Rhai bindings for DateTime, random, and error utilities |

## Building

To build, simply run `cargo build --workspace` (or `cargo build --workspace --release`).

## Testing

```sh
cargo test --workspace
```

## Documentation

- [Cedar Policy Guide](core/rex-cedar-auth/CEDAR_POLICY_GUIDE.md) — how Cedar entities, actions, and attributes map to REX operations
- [Cedar Policy Language](https://docs.cedarpolicy.com) — official Cedar documentation
- [Runner](core/rex-runner/README.md) — how to run scripts locally
- [Contributing](CONTRIBUTING.md) — development setup and guidelines
