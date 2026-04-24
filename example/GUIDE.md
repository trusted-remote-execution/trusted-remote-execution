# Cedar Runbox — Getting Started Guide

This guide walks through three progressively more advanced demos of Rex, a secure
script execution engine that uses Cedar policies to control what scripts can do.

1. **Local execution** — Run Rex scripts directly on your machine
2. **Remote execution via SSM** — Run Rex scripts through AWS Systems Manager
3. **Agent execution** — Let an AI agent author and run Rex scripts through SSM

---

## Step 0: Initialize

All demos use example files under `/tmp/rex_example`. Run this once to set up:

```bash
./example/setup/init.sh
```

This copies the example Cedar policies, Rhai scripts, and test data to
`/tmp/rex_example`, adjusting paths for macOS if needed.

After running, you should have:

```
/tmp/rex_example/
├── readonly.cedar     # Cedar policy: read-only access
├── readwrite.cedar    # Cedar policy: read-write access
├── demo.rhai          # Rhai script: reads a file and lists a directory
├── write-test.rhai    # Rhai script: creates and writes a file
└── hello.txt          # Test data
```

---

## Demo 1: Local Execution

Run Rex scripts directly on your machine to see how Cedar policies control
what a script can do.

> **Note:** This demo is a work in progress. The commands below show the
> intended usage but may not work yet in all environments.

### Test 1: Read script + read-only policy ✅

The script only reads files, and the policy allows reading. This should succeed.

```bash
rex-runner \
  --script-file /tmp/rex_example/demo.rhai \
  --policy-file /tmp/rex_example/readonly.cedar
```

### Test 2: Write script + read-write policy ✅

The script writes a file, and the policy allows writing. This should succeed.

```bash
rex-runner \
  --script-file /tmp/rex_example/write-test.rhai \
  --policy-file /tmp/rex_example/readwrite.cedar
```

### Test 3: Write script + read-only policy ❌

The script tries to write, but the policy only allows reading. Cedar blocks it.

```bash
rex-runner \
  --script-file /tmp/rex_example/write-test.rhai \
  --policy-file /tmp/rex_example/readonly.cedar
```

You should see an `ACCESS_DENIED_EXCEPTION` — the same script, different
outcome, based solely on which policy was attached.

---

## Demo 2: Remote Execution via SSM

Run the same Rex scripts remotely through AWS Systems Manager. This demo
shows how custom SSM documents can hardcode Cedar policies, creating a
layered security model:

- **IAM** controls who can invoke which SSM document
- **SSM document** controls which Cedar policy is used
- **Cedar** controls what the script can do

### Prerequisites

- AWS CLI installed and configured (`aws sts get-caller-identity` should succeed)
- IAM permissions to create roles, policies, SSM activations, and documents

### Step 1: Set up the SSM agent

Install, register, and start the SSM agent on your machine:

```bash
./example/setup/ssm-server/setup-all.sh
```

Verify it's running:

```bash
./example/setup/ssm-server/check-agent.sh
```

### Step 2: Test Rex over SSM

Run the read script with the read-only policy:

```bash
./example/setup/ssm-client/run-rex-ro.sh /tmp/rex_example/demo.rhai
```

Run the write script with the read-write policy:

```bash
./example/setup/ssm-client/run-rex-rw.sh /tmp/rex_example/write-test.rhai
```

Run the write script with the read-only policy (should be denied by Cedar):

```bash
./example/setup/ssm-client/run-rex-ro.sh /tmp/rex_example/write-test.rhai
```

### Step 3: Create custom SSM documents (optional)

Create `Rex-RO` and `Rex-RW` documents that hardcode the Cedar policy. The
caller can only choose which script to run, not which policy:

```bash
./example/setup/ssm-server/create-ssm-documents.sh
```

### Step 4: Grant cross-account access (optional)

Allow another AWS account to invoke the Rex documents:

```bash
# Read-only access only
./example/setup/ssm-server/allow-account-rex.sh 123456789012 ro

# Both read-only and read-write
./example/setup/ssm-server/allow-account-rex.sh 123456789012 both
```

### Teardown

```bash
./example/setup/ssm-server/delete-ssm-documents.sh
./example/setup/ssm-server/teardown-all.sh
```

---

## Demo 3: Agent Execution

An AI agent (built with the Strands SDK) authors and executes Rex scripts on
your behalf. You describe what you want in natural language, and the agent
writes a Rhai script, sends it to the managed instance via SSM, and shows
you the result.

The agent operates in read-only or read-write mode, which determines which
Cedar policy is enforced. Even if the agent writes a script that attempts
write operations, Cedar will deny them in read-only mode.

### Prerequisites

- SSM agent running (complete Demo 2 setup first)
- AWS credentials with Amazon Bedrock access (Claude)
- Python 3.10+

### Step 1: Set up the agent

```bash
./example/setup/strands/setup.sh
source example/setup/strands/.venv/bin/activate
```

### Step 2: Run in read-only mode

```bash
python example/setup/strands/agent.py --mode ro \
  "What files are in /tmp/rex_example?"
```

### Step 3: See Cedar enforcement

Ask the agent to write a file while in read-only mode:

```bash
python example/setup/strands/agent.py --mode ro \
  "Create a file called secret.txt with the text 'you should not see this'"
```

The agent will attempt it, and Cedar will deny the operation.

### Step 4: Run in read-write mode

```bash
python example/setup/strands/agent.py --mode rw \
  "Create a file called greeting.txt that says 'Hello from the agent' and read it back"
```

This time it succeeds — the read-write policy permits the operation.
