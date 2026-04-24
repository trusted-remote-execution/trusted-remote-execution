# Contributing to Trusted Remote Execution (REX)

Thank you for your interest in contributing!

## Prerequisites

- [Rust](https://rustup.rs/) (stable toolchain)
- `cargo` (included with Rust)

## Building

```sh
cargo build --workspace
```

## Testing

```sh
cargo test --workspace
```

## Code Style

This project uses [`rustfmt`](https://github.com/rust-lang/rustfmt) for formatting:

```sh
cargo fmt --all
```

And [`clippy`](https://github.com/rust-lang/rust-clippy) for linting:

```sh
cargo clippy --workspace
```

Please ensure both pass before submitting a pull request.

## Adding Dependencies

Add dependencies directly to the relevant crate's `Cargo.toml`. Third-party crates are pulled from [crates.io](https://crates.io).

## Submitting Changes

1. Fork the repository and create a branch from `main`.
2. Make your changes with tests where applicable.
3. Ensure `cargo fmt --all`, `cargo clippy --workspace`, and `cargo test --workspace` all pass.
4. Open a pull request with a clear description of what was changed and why.

## Code of Conduct

Please review our [Code of Conduct](CODE_OF_CONDUCT.md) before contributing.
