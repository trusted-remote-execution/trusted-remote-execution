# Publishing a new version to crates.io

This guide walks through publishing a new version of the REX workspace crates to [crates.io](https://crates.io).

## Prerequisites

1. Install Rust and Cargo:
   ```sh
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. Create a crates.io account at https://crates.io (log in via GitHub).

3. Generate an API token at https://crates.io/settings/tokens and log in:
   ```sh
   cargo login <your-api-token>
   ```

4. Install [cargo-workspaces](https://github.com/pksunkara/cargo-workspaces):
   ```sh
   cargo install cargo-workspaces
   ```

## Step 1 — Bump the version

Update the version in the workspace root `Cargo.toml`:

```toml
[workspace.package]
version = "0.2.0"
```

Then update all inter-workspace `version = "..."` references to match:

```sh
# Find all inter-workspace version references:
grep -rn 'version = "0.1.0"' core/ rust-sdk/ rhai-sdk/ --include='Cargo.toml'

# Replace with the new version:
find core/ rust-sdk/ rhai-sdk/ -name 'Cargo.toml' \
  -exec sed -i '' 's/version = "0.1.0"/version = "0.2.0"/g' {} +
```

Commit and tag:

```sh
git commit -am "chore: bump version to 0.2.0"
git tag v0.2.0
```

## Step 2 — Run tests

```sh
cargo test --workspace
```

## Step 3 — Publish all crates

### Dry-run

```sh
cargo ws publish --from-git --dry-run
```

`--dry-run` runs all packaging checks without uploading anything. `--from-git` skips the interactive version-bump step and uses the versions already in your `Cargo.toml` files.

### Publish

```sh
cargo ws publish --from-git --publish-interval 10
```

The `--publish-interval 10` flag waits 10 seconds between crates to avoid crates.io rate limits.

### Useful options

| Option | Description |
|--------|-------------|
| `--from-git` | Skip version bumping; publish what's already in git |
| `--dry-run` | Run all checks without uploading |
| `--allow-dirty` | Allow uncommitted changes in the working directory |
| `--no-git-push` | Don't push the version commit and tags to the remote |
| `--publish-interval <SECS>` | Wait N seconds between publishes to avoid rate-limiting |
| `-y, --yes` | Skip confirmation prompts |

> `cargo ws` is just a shorthand alias for `cargo workspaces`.

## Step 4 — Verify the published crates

```sh
# Check that the main binary crate is installable:
cargo install rex-runner

# Or check any library crate:
cargo search rex-cedar-auth
```

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Dependency not found on crates.io | Publish the dependency first; wait 60s for index propagation |
| `version = "*"` rejected | Pin to an exact version like `"0.2.0"` |
| Name conflict on crates.io | Rename the crate in its `Cargo.toml` `[package].name` field |

## Adding a new crate to the workspace

When adding a new crate, complete these steps before publishing:

### Add required metadata

In the new crate's `Cargo.toml`, inherit workspace fields and add a crate-specific description:

```toml
[package]
name = "rex-my-new-crate"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
description = "Description of what this crate does"
```

Ensure there is no `publish = false` in the crate's `Cargo.toml`.

### Pin inter-workspace dependency versions

Any inter-workspace dependency must include a pinned `version` field (not `"*"`):

```toml
# Correct
rex-logger = { path = "../rex-logger", version = "0.2.0" }

# Wrong — will be rejected by crates.io
rex-logger = { path = "../rex-logger", version = "*" }
```
