# rex-redaction

A utility crate for converting printf-style format patterns into regex, used to power the redacted file read feature in the Rex safe I/O SDK.

## Overview

When a script performs a read on a file, the runtime automatically uses redacted mode if the Cedar policy grants `redacted_read` (but not `read`) on the file. This crate handles converting patterns from the redaction dictionary (written in printf format, e.g. from system log templates) into regex patterns that are matched against file content.

Lines that **match** a pattern are **preserved**; all other lines are replaced with `[REDACTED]`.

## How It Works

1. The redaction dictionary at `/etc/opt/rex/rex_redaction.config` contains printf-style format strings — one per line.
2. Each pattern is converted to a regex using this crate.
3. File content is scanned line-by-line; only lines matching at least one pattern are returned. Everything else becomes `[REDACTED]`.

The same `.read()` call in a Rhai script is used for both full and redacted reads — the Cedar policy determines which mode applies:
- If `read` is granted → full content is returned.
- If only `redacted_read` is granted → content is returned with redaction applied.

> **Note:** If the policy grants both `read` and `redacted_read` on the same file, the more permissive `read` takes precedence — content will be returned unredacted.

## Configuration

### Redaction dictionary

Create the redaction dictionary at `/etc/opt/rex/rex_redaction.config`. Each line is a printf-style format string describing an expected log pattern:

```
# Lines starting with '#' are comments and are ignored
could not open file "%s" for reading: %m
connection from %s rejected
error %d: authentication failed for user "%s"
```

> **Important:** When the policy grants only `redacted_read` (not `read`) on a file:
> - The redaction dictionary must exist — if it doesn't, the `.read()` call will fail with a file error.
> - If the dictionary is empty, every line will be replaced with `[REDACTED]` since no lines can match.

### Supported printf specifiers

| Specifier          | Matches                        |
|--------------------|--------------------------------|
| `%s`               | Non-whitespace word (`\S+`)    |
| `%d`               | Signed integer (`-?\d+`)       |
| `%u`, `%zu`, `%lu` | Unsigned integer (`\d+`)       |
| `%m`               | Any text (error message, `.*?`)|

Patterns containing unsupported specifiers (e.g. `%f`, `%p`, `%x`) are silently skipped.

### Cedar policy

To allow `redacted_read` on a target file, the policy must also grant `open` on the `/etc/opt/rex` directory and `open`+`read` on the redaction dictionary file itself (so the runtime can load the patterns):

```cedar
// --- Target file ---

// Grant redacted read on the target log file
permit(
    principal == User::"alice",
    action in [
        file_system::Action::"open",
        file_system::Action::"redacted_read"
    ],
    resource == file_system::File::"/var/log/app.log"
);

// Allow opening the target log directory
permit(
    principal == User::"alice",
    action == file_system::Action::"open",
    resource == file_system::Dir::"/var/log"
);

// --- Redaction dictionary ---

// Required: allow the runtime to read the redaction dictionary
permit(
    principal == User::"alice",
    action == file_system::Action::"open",
    resource == file_system::Dir::"/etc/opt/rex"
);

permit(
    principal == User::"alice",
    action in [
        file_system::Action::"open",
        file_system::Action::"read"
    ],
    resource == file_system::File::"/etc/opt/rex/rex_redaction.config"
);
```

### Rhai script example

No special API is needed — the standard `.read()` call is used. The runtime picks the read mode based on the Cedar policy:

```rhai
let dir = DirConfig()
    .path("/var/log")
    .build()
    .open(OpenDirOptions().build());

let file = dir.open_file("app.log", OpenFileOptions().read(true).build());

// Returns redacted content if only `redacted_read` is granted,
// or full content if `read` is granted.
let content = file.read();

content
```

## Example

Given this redaction dictionary at `/etc/opt/rex/rex_redaction.config`:

```
error %d: authentication failed for user "%s"
```

And this log file at `/var/log/app.log`:

```
2026-04-17 server started on port 8080
2026-04-17 listening for connections
error 401: authentication failed for user "bob"
2026-04-17 shutting down
```

With the Cedar policy from above granting `redacted_read` on `/var/log/app.log`, running the Rhai script produces:

```text
[REDACTED]
[REDACTED]
error 401: authentication failed for user "bob"
[REDACTED]
```

Only the line matching the dictionary pattern is preserved; everything else is redacted.
