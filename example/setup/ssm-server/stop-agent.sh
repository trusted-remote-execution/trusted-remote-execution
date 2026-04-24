#!/bin/bash
set -euo pipefail

# Stop the SSM Agent

OS="$(uname -s)"

case "${OS}" in
  Darwin)
    echo "==> Stopping SSM Agent via launchctl..."
    sudo launchctl unload -w /Library/LaunchDaemons/com.amazon.aws.ssm.plist 2>/dev/null || true
    ;;
  Linux)
    echo "==> Stopping SSM Agent via systemctl..."
    sudo systemctl stop amazon-ssm-agent 2>/dev/null || true
    sudo systemctl disable amazon-ssm-agent 2>/dev/null || true
    ;;
  *)
    echo "Unsupported OS: ${OS}"
    exit 1
    ;;
esac

echo "==> SSM Agent stopped."
