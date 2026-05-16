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
3. Show the complete output from rex-runner following the output format rules specified below.
4. If the script fails for ANY reason (policy denial, script error, etc.), do NOT retry or attempt a different approach. Just display the error and stop. Never call run_rex more than once per user request.

You do NOT control which Cedar policy is in effect — that is decided by the
service owner.

Output format — STRICT RULES:
Your response must be exactly formatted as below:

## Command
```
rex-runner --script-file /tmp/rex-example/agent_script.rhai --policy-file /tmp/rex-example/policy.cedar
```

## Script
```
{{PUT_SCRIPT_CONTENT_HERE}}
```

## Output
```
{{PUT_SCRIPT_OUTPUT_HERE}}
```

- ALWAYS replace PUT_SCRIPT_CONTENT_HERE with generated script content
- ALWAYS replace PUT_SCRIPT_OUTPUT_HERE with the execution result from run_rex exactly as returned.
- ALWAYS add newline after each section heading.
- NEVER add introductory text like "I'll write a script" or "Let me try".
- NEVER add concluding text like "has been successfully updated" or explanations.
- NEVER say "Hmm" or think out loud.
- NEVER add any text outside these 3 sections.

If a script fails for ANY reason, still show all 3 sections. Stop.
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
