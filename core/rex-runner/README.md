# REX Runner

The REX Runner executes Rhai scripts under a Cedar policy. Every API call the script
makes is authorized against the policy before execution.

## Building

```sh
cargo build -p rex-runner
```

The binary is produced at `target/debug/rex-runner` (or `target/release/rex-runner` with `--release`).

You can also install it locally:

```sh
cargo install --path core/rex-runner
```

## Usage

```
rex-runner [OPTIONS]
```

### Options

| Flag | Description |
|------|-------------|
| `-s, --script-file <PATH>` | Path to the Rhai script file to execute |
| `-p, --policy-file <PATH>` | Path to the Cedar policy file |
| `-a, --script-arguments-file <PATH>` | Path to a JSON file containing script arguments |
| `-o, --output-format <FORMAT>` | Output format: `json` (default), `pretty-json`, or `human` |
| `-v, --verbose` | Show additional detail (logs, metrics summary) in the output |
| `-h, --help` | Print help |

### Quick start

The `samples/read-file-example/` directory contains a working example that reads `/usr/share/misc/ascii`:

```sh
rex-runner \
  --script-file samples/read-file-example/read-file.rhai \
  --policy-file samples/read-file-example/read-file-policy.cedar \
  --script-arguments-file samples/read-file-example/read-file-args.json \
  --output-format human \
  --verbose
```

## Function Metadata

To print metadata about all registered functions (useful for debugging):

```sh
rex-runner --print-functions
```

## Example Scripts

Example Rhai scripts are included in the `samples/` directory.
