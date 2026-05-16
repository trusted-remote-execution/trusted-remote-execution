# REX Demo — Open Source Summit

A self-contained demo showing how Cedar policies sandbox script execution,
whether the script is written by a human or an AI agent.

**Key message**: "Secure the environment, not the agent."

---

## Prerequisites

- `rex-runner` binary on PATH (`cargo install rex-runner`)
- Python 3.10+
- AWS credentials with Bedrock access (Claude)

---

## Quick Start

```bash
# 1. Initialize and activate (source to get the ops-agent alias)
source rex-demo/init.sh
```

---

## Demo Flow

### Segment 1: REX in 2 Minutes — The Foundation

Show the policy (write is commented out):

```bash
cat /tmp/rex-example/policy.cedar
```

Show the config file:

```bash
cat /tmp/rex-example/config.ini
```

Run a read script — succeeds:

```bash
rex-runner \
  --script-file /tmp/rex-example/read-config.rhai \
  --policy-file /tmp/rex-example/policy.cedar \
  --output-format human
```

Run a write script — denied:

```bash
rex-runner \
  --script-file /tmp/rex-example/update-config.rhai \
  --policy-file /tmp/rex-example/policy.cedar \
  --output-format human
```

### Segment 2: AI Agent Under Read-Only Policy

Agent reads the config (succeeds):

```bash
ops-agent "Show me the contents of config.ini"
```

Agent tries to write (denied):

```bash
ops-agent "Update the worker count to 8 in config.ini"
```

### Segment 3: Service Owner Enables Writes

Open `/tmp/rex-example/policy.cedar` and uncomment the write action:

```cedar
        file_system::Action::"stat",

        // --- Uncomment below to allow write operations ---
        file_system::Action::"write"
```

Save. Then re-run:

```bash
ops-agent "Update the worker count to 8 in config.ini inside /private/tmp/rex-example"
```

This time it succeeds. ✅

Optionally verify:

```bash
ops-agent "Show me the contents of config.ini"
```

---

## Closing Line

"Same agent. Same binary. The only thing that changed is what the service owner
permits. Secure the environment, not the agent."

---

## Reset Between Runs

To reset the demo to its initial state:

```bash
./rex-demo/init.sh
```

---

## Structure

```
rex-demo/
├── README.md              # This file (demo script)
├── init.sh                # One-time setup (files + Ollama)
├── files/
│   ├── config.ini         # Authentic server config
│   ├── read-config.rhai   # Read script (cat config.ini)
│   ├── update-config.rhai # Write script (sed workers)
│   └── policy.cedar       # Cedar policy (write commented out)
└── agent/
    ├── agent.py           # Strands agent (uses Ollama locally)
    ├── tools.py           # run_rex tool (calls rex-runner)
    ├── context.md         # Rhai API reference for the agent
    └── requirements.txt   # Python dependencies
```
