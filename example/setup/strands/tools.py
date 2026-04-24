"""Custom tools for the REX Strands agent."""

import json
import subprocess

from strands import tool


def _get_instance_id() -> str:
    """Read the managed instance ID from the SSM registration file."""
    result = subprocess.run(
        ["sudo", "cat", "/opt/aws/ssm/data/registration"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError("SSM agent not registered. Run setup-all.sh first.")
    return json.loads(result.stdout)["ManagedInstanceID"]


@tool
def run_remote_command(command: str) -> str:
    """Run a shell command on the local managed instance via AWS SSM.

    Use this tool when you need to execute a command remotely through
    Systems Manager rather than running it directly.

    Args:
        command: The shell command to execute on the managed instance.

    Returns:
        str: The stdout output from the command, or an error message.
    """
    setup_dir = subprocess.run(
        ["dirname", subprocess.run(
            ["realpath", __file__], capture_output=True, text=True
        ).stdout.strip()],
        capture_output=True, text=True,
    ).stdout.strip()

    run_script = f"{setup_dir}/../ssm-client/run-command.sh"

    result = subprocess.run(
        [run_script, command],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        return result.stdout
    return f"Command failed:\n{result.stderr or result.stdout}"
