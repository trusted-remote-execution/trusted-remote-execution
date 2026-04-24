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

- SSM commands run as root by default. rex-runner can be executed as root.
- All file paths in Cedar policies and Rhai scripts must be absolute paths
  using `/private/tmp/...` (macOS resolves `/tmp` to `/private/tmp`).
- Scripts must be saved to disk before execution — REX reads from file paths,
  not stdin.

## Available Policies

Two policies at `/tmp/rex_example/`:

- `readonly.cedar` — allows `open`, `read`, `stat`
- `readwrite.cedar` — allows `open`, `read`, `stat`, `write`, `create`, `delete`, `chmod`, `chown`

Both scoped to resources under `/tmp/rex_example`.

## Running REX via SSM

Use the helper scripts (relative to the package root):

```bash
# Read-only — script can only read files
./example/setup/run-rex-ro.sh /tmp/rex_example/script.rhai

# Read-write — script can read and write files
./example/setup/run-rex-rw.sh /tmp/rex_example/script.rhai

# With script arguments
./example/setup/run-rex-rw.sh /tmp/rex_example/script.rhai key=value

# Arbitrary shell command via SSM
./example/setup/run-command.sh 'some command'
```

## Authoring Scripts

To run a custom script, write it to `/tmp/rex_example/` first,
then invoke it via the appropriate run-rex helper. Example workflow:

1. Write the .rhai file to `/tmp/rex_example/myscript.rhai`
2. Run: `./example/setup/run-rex-ro.sh /tmp/rex_example/myscript.rhai`

You can write files to the managed instance via SSM:
```bash
./example/setup/run-command.sh 'tee /tmp/rex_example/myscript.rhai << '"'"'EOF'"'"'
let content = cat("/tmp/rex_example/hello.txt");
info(`File says: ${content}`);
EOF'
```

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

## Cedar Policy Actions Reference

All actions are in the `file_system` namespace:
- `open` — open a file or directory handle
- `read` — read file contents
- `stat` — get file/directory metadata
- `write` — write/overwrite file contents
- `create` — create new files or directories
- `delete` — remove files or directories
- `chmod` — change file permissions
- `chown` — change file ownership
- `move` — move/rename files (requires context with destination)
- `execute` — execute a file (requires context with arguments, environment, etc.)
- `redacted_read` — read with redaction (File only)
- `network_namespace` — network namespace operations (File only)
- `set_x_attr` — set extended attributes (requires context)
- `unmount` — unmount a directory

Actions apply to `File`, `Dir`, or both. Resources are scoped using:
```cedar
resource in file_system::Dir::"/some/absolute/path"
```


## Rhai Command API — Full Reference

### File Operations

```
# cat — Read file contents (returns String)
cat(path)
cat([cat::n], path)                    # with line numbers

# grep — Search file contents (returns String)
grep(pattern, path)
grep([flags], pattern, path)
  Flags: grep::i (case-insensitive), grep::c (count), grep::v (invert),
         grep::n (line numbers), grep::m(n) (max matches)

# tail — Read lines from end of file (returns String)
tail(path)                             # last 10 lines
tail([tail::n(count)], path)           # last N lines
tail([tail::from(line)], path)         # from line number
tail([tail::range(start, end)], path)  # line range

# wc — Count lines, words, bytes (returns Map {lines, words, bytes})
wc(path)
wc([wc::l], path)                      # lines only
wc([wc::w], path)                      # words only

# sed — Find and replace (returns String)
sed(pattern, replacement, path)
sed([sed::g], pattern, replacement, path)          # replace all
sed([sed::i], pattern, replacement, path)          # in-place
sed([sed::regex, sed::g], pattern, replacement, path)  # regex + global

# touch — Create empty file
touch(path)

# replace — Overwrite file contents
replace(path, content)

# append — Append to file
append(path, content)

# cp — Copy file
cp(src, dst)
cp([cp::f, cp::p], src, dst)          # force + preserve metadata

# mv — Move/rename file
mv(src, dst)
mv([mv::b], src, dst)                 # backup destination

# rm — Remove file or directory
rm(path)
rm([rm::r, rm::f], path)              # recursive + force
```

### Directory Operations

```
# ls — List directory (returns Array of Maps)
ls(path)
ls([ls::a, ls::l], path)              # hidden + long format
ls([ls::R], path)                      # recursive

# mkdir — Create directory
mkdir(path)
mkdir([mkdir::p], path)                # create parents

# find_files / glob — Find files by pattern (returns Array of Strings)
find_files(pattern, path)
find_files([glob::r], pattern, path)   # recursive

# du — Disk usage (returns Map)
du(path)
du([du::s], path)                      # summary only
du([du::d(n)], path)                   # max depth
```

### Text Processing (awk)

```
awk_split(text, separator)                        # split string → Array
awk_field(n, separator, path)                     # extract Nth field per line
awk_filter(pattern, path)                         # filter lines matching pattern
awk_filter_field(n, pattern, separator, path)     # filter by Nth field match
awk_sum(n, separator, path)                       # sum numeric Nth field
awk_count_unique(n, separator, path)              # count unique values → Map
awk_filter_range(n, min, max, separator, path)    # filter Nth field in range
```

### Sequence Generation

```
seq(start, end)                        # 1, 2, 3, ...
seq([seq::step(n)], start, end)        # custom step
```

### Networking

```
curl(url)              # HTTP GET → Response {.status, .text}
ip_addr()              # network interfaces → Array of {.interface_name, .addresses}
resolve(host)          # DNS → Array of IP strings
netstat()              # connections → {.internet_connections, .unix_sockets}
```

### System Information (Linux)

```
hostname()             # → String
uname()                # → {.kernel_name, .nodename, .kernel_release, .machine, ...}
nproc()                # CPU count → i64
free()                 # → {.memory {.total, .free, .available, .used}, .swap {...}}
df()                   # → Array of {.mounted_on, .block_use_percent, .size, ...}
iostat()               # → {.cpu_stats, .device_stats}
dmesg()                # → Array of {.timestamp_from_system_start, .message}
lsblk()                # → Map keyed by device name
```

### Process Management (Linux)

```
ps()                                   # → Array of {.pid, .name, .state, .command, ...}
kill(pid)                              # SIGTERM
kill([kill::SIGKILL], pid)             # force kill
kill([kill::signal(n)], pid)           # signal by number
```

### Kernel Parameters (Linux)

```
sysctl_read(key)                       # read parameter → String
sysctl_find(pattern)                   # find matching → Array
sysctl_write(key, value)               # write parameter
```

### Logging and Output

```
info(message)          # log an info-level message (appears in REX logs output)
print(message)         # print to script output
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

// Functions are not user-definable in REX — use the built-in commands above.
```

## Example Scripts

### Read a file and list a directory (RO)
```rhai
let content = cat("/tmp/rex_example/hello.txt");
info(`File says: ${content}`);

let files = ls("/tmp/rex_example");
info(`Directory listing: ${files}`);
```

### Create and write a file (RW)
```rhai
let path = "/tmp/rex_example/written.txt";
touch(path);
replace(path, "Hello from write-test!");
let content = cat(path);
info(`Wrote and read back: ${content}`);
```

### Search and process text (RO)
```rhai
let matches = grep([grep::i, grep::n], "hello", "/tmp/rex_example/hello.txt");
info(`Matches: ${matches}`);

let counts = wc("/tmp/rex_example/hello.txt");
info(`Lines: ${counts.lines}, Words: ${counts.words}`);
```
