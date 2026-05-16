"""Custom tools for the REX demo agent."""

import json
import subprocess

from strands import tool

POLICY_FILE = "/tmp/rex-example/policy.cedar"
SCRIPT_FILE = "/tmp/rex-example/agent_script.rhai"
REX_BIN = "rex-runner"


@tool
def run_rex(script: str) -> str:
    """Execute a Rhai script through REX with the system policy.

    Writes the script to disk and runs it through rex-runner with
    whatever Cedar policy the service owner has deployed.

    Args:
        script: The Rhai script source code to execute.

    Returns:
        str: The script output on success, or the error message on failure.
    """
    # Write the script to disk
    with open(SCRIPT_FILE, "w") as f:
        f.write(script)

    # Run rex-runner locally
    result = subprocess.run(
        [REX_BIN, "--script-file", SCRIPT_FILE, "--policy-file", POLICY_FILE],
        capture_output=True,
        text=True,
    )

    raw = result.stdout.strip()
    if result.returncode != 0 and not raw:
        return f"rex-runner failed:\n{result.stderr}"

    # Parse JSON and return clean output
    try:
        data = json.loads(raw)
        if data.get("status") == "SUCCESS":
            output = data.get("output", "")
            logs = data.get("logs", [])
            # Extract log messages if present
            log_messages = []
            for log in logs:
                if isinstance(log, dict) and "attributes" in log:
                    log_messages.append(log["attributes"].get("message", ""))
                elif isinstance(log, str):
                    log_messages.append(log)
            return output or "\n".join(log_messages) or "SUCCESS (no output)"
        else:
            error = data.get("error", {})
            error_type = error.get("error_type", "UNKNOWN_ERROR")
            message = error.get("message", "Unknown error")
            return f"{error_type}: {message}"
    except (json.JSONDecodeError, KeyError):
        return raw
