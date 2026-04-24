"""REX Strands agent that executes commands via SSM."""

import argparse
import os

from strands import Agent
from tools import run_remote_command

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REX_BIN = "rex-runner"

POLICIES = {
    "ro": "/tmp/rex_example/readonly.cedar",
    "rw": "/tmp/rex_example/readwrite.cedar",
}

with open(os.path.join(SCRIPT_DIR, "context.md")) as f:
    context = f.read()


def build_prompt(mode: str) -> str:
    policy_path = POLICIES[mode]
    mode_label = "READ-ONLY" if mode == "ro" else "READ-WRITE"

    if mode == "ro":
        constraint = """You are operating in READ-ONLY mode. The Cedar policy will enforce
read-only access. Always attempt what the user asks — if the operation is not permitted,
the Cedar policy will deny it and you will see an ACCESS_DENIED error in the output.
Show the user the denial so they can see the sandbox enforcement in action."""
    else:
        constraint = """You are operating in READ-WRITE mode. You may use both read and
write operations as needed."""

    return f"""You are a REX automation agent running in {mode_label} mode.
You help users inspect and manage files on their Mac via AWS Systems Manager (SSM).

{constraint}

When a user asks you to do something:

1. Figure out what Rhai commands are needed.
2. Write a .rhai script to `/tmp/rex_example/agent_script.rhai` on the
   managed instance using: tee <path> with heredoc syntax.
3. Execute it with:
   {REX_BIN} --script-file /tmp/rex_example/agent_script.rhai --policy-file {policy_path}
4. Parse the JSON output and present results clearly to the user.

Output format — keep it compact:
- Show the Rhai script you wrote (as a code block).
- Show only the human-readable result (one line: ✅ or ❌ plus the key info).
- Do NOT show raw JSON, SSM command IDs, intermediate steps, tool call details,
  warnings, explanations, security commentary, or suggestions.
- No preamble. No follow-up advice. Just script and result.

Remember:
- All paths must use `/private/tmp/` not `/tmp/` (macOS symlink).
- Use `info()` in scripts to log results (appears in the `logs` field of output).
- Use `print()` for output (appears in the `output` field).
- You MUST ONLY use policy: {policy_path}
- You have one tool: run_remote_command, which runs any shell command via SSM.

{context}"""


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="REX Strands Agent")
    parser.add_argument(
        "--mode", choices=["ro", "rw"], default="ro",
        help="Policy mode: ro (read-only) or rw (read-write). Default: ro",
    )
    parser.add_argument("prompt", nargs="*", default=["What files are in /tmp/rex_example?"])
    args = parser.parse_args()

    # Suppress streaming output — only print the final response
    def quiet_callback(**kwargs):
        if "data" in kwargs:
            print(kwargs["data"], end="", flush=True)

    agent = Agent(
        tools=[run_remote_command],
        system_prompt=build_prompt(args.mode),
        callback_handler=quiet_callback,
    )
    result = agent(" ".join(args.prompt))
    print()  # trailing newline
