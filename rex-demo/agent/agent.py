"""REX demo agent — AI writes scripts, Cedar enforces policy."""

import argparse
import os

from strands import Agent
from tools import run_rex

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(SCRIPT_DIR, "context.md")) as f:
    context = f.read()

SYSTEM_PROMPT = f"""You are a REX automation agent. You help users accomplish tasks by
writing Rhai scripts and executing them through REX.

When a user asks you to do something:
1. Write a Rhai script to accomplish the task. Use proper escape sequence when contructing regex.
2. Call the run_rex tool with the script source code only once. DO NOT RETRY.
3. Show the complete output from rex-runner.
4. If the script fails for ANY reason (policy denial, script error, etc.), do NOT retry or attempt a different approach. Just display the error and stop. Never call run_rex more than once per user request.

You do NOT control which Cedar policy is in effect — that is decided by the
service owner.

Output format — STRICT RULES:
1. Always show the Rhai script you will execute (as a fenced code block). 
2. Always add a newline after script code block.
3. Print the rex-runner result verbatim in a fenced code block.
4. Never deviate from the output format rules.
- NEVER add introductory text like "I'll write a script" or "Let me try".
- NEVER add concluding text like "has been successfully updated" or explanations.
- NEVER say "Hmm" or think out loud.
- Your entire response must be: script code block, then result code block. That's it.

If a script fails for ANY reason, show the script and the error output. Stop.
NEVER call run_rex more than once. NEVER retry. One attempt only.

Important:
- Your working directory is /private/tmp/rex-example. All file paths must be under this directory.
- Always use the full absolute path `/private/tmp/rex-example/` prefix for any file or directory.
- Use `info()` in scripts to log results (appears in the `logs` field of output).
- Return the output (appears in the `output` field).

{context}"""


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="REX Demo Agent")
    parser.add_argument("prompt", nargs="*", default=["What files are in /tmp/rex-example?"])
    args = parser.parse_args()

    def quiet_callback(**kwargs):
        if "data" in kwargs:
            text = kwargs["data"]
            # Add visual separation between consecutive code blocks
            if hasattr(quiet_callback, '_last') and quiet_callback._last.endswith('```') and text.startswith('```'):
                print("\n", end="")
            print(text, end="", flush=True)
            quiet_callback._last = text
    quiet_callback._last = ""

    agent = Agent(
        tools=[run_rex],
        system_prompt=SYSTEM_PROMPT,
        callback_handler=quiet_callback,
    )
    result = agent(" ".join(args.prompt))
    print()
