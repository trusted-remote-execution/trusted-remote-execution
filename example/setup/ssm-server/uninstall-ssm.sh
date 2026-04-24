#!/bin/bash
set -euo pipefail

# Uninstall the SSM Agent

OS="$(uname -s)"

case "${OS}" in
  Darwin)
    echo "==> Removing SSM Agent files..."
    sudo rm -rf /opt/aws/ssm
    sudo rm -f /Library/LaunchDaemons/com.amazon.aws.ssm.plist

    echo "==> Removing package receipt..."
    sudo pkgutil --forget com.amazon.aws.ssm 2>/dev/null || true
    ;;

  Linux)
    echo "==> Removing SSM Agent package..."
    if command -v dpkg >/dev/null 2>&1; then
      sudo dpkg -r amazon-ssm-agent 2>/dev/null || true
    elif command -v rpm >/dev/null 2>&1; then
      sudo rpm -e amazon-ssm-agent 2>/dev/null || true
    fi
    ;;

  *)
    echo "Unsupported OS: ${OS}"
    exit 1
    ;;
esac

echo "==> SSM Agent uninstalled."
