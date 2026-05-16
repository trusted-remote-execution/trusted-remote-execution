# REX Agent Context

## What is REX?

REX (Remote Execution) runs Rhai scripts with Cedar policy-based authorization.
Cedar policies define what file system operations a script is allowed to perform.
If a script tries to access a resource not permitted by the policy, it is denied.

## REX Binary

Path: `rex-runner`

Usage:
```
rex-runner \
  --script-file <path-to-rhai-script> \
  --policy-file <path-to-cedar-policy> \
  [--script-arguments KEY=VALUE ...]
```

## Important Constraints

- All file paths in Cedar policies and Rhai scripts must be absolute paths
  using `/private/tmp/...` (macOS resolves `/tmp` to `/private/tmp`).
- Scripts must be saved to disk before execution — REX reads from file paths,
  not stdin.

## REX Output Format

REX returns JSON:
- `output`: script output on success
- `status`: "SUCCESS" or "ERROR"
- `error`: `{error_type, message}` on failure
- `alarms`: array of alarm objects if security violations occur
- `logs`: array of log entries from `info()` calls

## Common Errors

- `ACCESS_DENIED_EXCEPTION` + policy violation — Cedar policy doesn't permit the action
- `SCRIPT_EXCEPTION` + "Function not found" — using wrong function name (see API below)

## Rhai Command API

### File Operations

```
cat(path)                              # Read file contents (returns String)
grep(pattern, path)                    # Search file contents
grep([grep::i, grep::n], pattern, path)
tail(path)                             # Last 10 lines
tail([tail::n(count)], path)           # Last N lines
wc(path)                               # Count lines, words, bytes
touch(path)                            # Create empty file
replace(path, content)                 # Overwrite file contents
append(path, content)                  # Append to file
sed(pattern, replacement, path)        # Find and replace
sed([sed::i], pattern, replacement, path)  # In-place find and replace
cp(src, dst)                           # Copy file
mv(src, dst)                           # Move/rename file
rm(path)                               # Remove file
```

### Directory Operations

```
ls(path)                               # List directory
ls([ls::a, ls::l], path)               # Hidden + long format
mkdir(path)                            # Create directory
mkdir([mkdir::p], path)                # Create parents
find_files(pattern, path)              # Find files by pattern
```

### Logging and Output

```
info(message)          # Log info-level message (appears in REX logs output)
```

### Rhai Language Basics

```rhai
// Variables
let x = 42;
let name = "hello";

// String interpolation (backtick strings)
info(`Value is: ${x}`);

// Conditionals
if x > 10 {
    info("big");
} else {
    info("small");
}

// Loops
for item in list {
    info(`Item: ${item}`);
}
```

## Example Scripts

### Read a file
```rhai
let content = cat("/private/tmp/rex-example/config.ini");
content
```

### Update a value in a config file using exact match
```rhai
sed([sed::i], "workers = 4", "workers = 8", "/private/tmp/rex-example/config.ini");
let content = cat("/private/tmp/rex-example/config.ini");
content
```

### Update a value in a config file using regex
```rhai
sed([sed::i, sed::regex], "port = \\d+", "port = 8080", "/private/tmp/rex-example/config.ini");
let content = cat("/private/tmp/rex-example/config.ini");
content
```
