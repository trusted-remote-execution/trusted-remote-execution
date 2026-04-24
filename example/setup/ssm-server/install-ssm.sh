#!/bin/bash
set -euo pipefail

# Step 1: Install the SSM Agent

REGION="${AWS_DEFAULT_REGION:-us-east-1}"
OS="$(uname -s)"
ARCH="$(uname -m)"

case "${OS}" in
  Darwin)
    case "${ARCH}" in
      arm64) PKG_ARCH="darwin_arm64" ;;
      x86_64) PKG_ARCH="darwin_amd64" ;;
      *) echo "Unsupported Mac architecture: ${ARCH}" && exit 1 ;;
    esac

    URL="https://s3.${REGION}.amazonaws.com/amazon-ssm-${REGION}/latest/${PKG_ARCH}/amazon-ssm-agent.pkg"

    echo "==> Downloading SSM Agent for macOS (${PKG_ARCH})..."
    curl -sfS "${URL}" -o /tmp/amazon-ssm-agent.pkg

    echo "==> Installing (requires sudo)..."
    sudo installer -pkg /tmp/amazon-ssm-agent.pkg -target /
    ;;

  Linux)
    case "${ARCH}" in
      x86_64) PKG_ARCH="amd64" ;;
      aarch64) PKG_ARCH="arm64" ;;
      *) echo "Unsupported Linux architecture: ${ARCH}" && exit 1 ;;
    esac

    if command -v dpkg >/dev/null 2>&1; then
      URL="https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/debian_${PKG_ARCH}/amazon-ssm-agent.deb"
      echo "==> Downloading SSM Agent for Linux/deb (${PKG_ARCH})..."
      curl -sfS "${URL}" -o /tmp/amazon-ssm-agent.deb
      echo "==> Installing (requires sudo)..."
      sudo dpkg -i /tmp/amazon-ssm-agent.deb
    elif command -v rpm >/dev/null 2>&1; then
      URL="https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_${PKG_ARCH}/amazon-ssm-agent.rpm"
      echo "==> Downloading SSM Agent for Linux/rpm (${PKG_ARCH})..."
      curl -sfS "${URL}" -o /tmp/amazon-ssm-agent.rpm
      echo "==> Installing (requires sudo)..."
      sudo rpm -U /tmp/amazon-ssm-agent.rpm 2>/dev/null || sudo rpm -q amazon-ssm-agent >/dev/null
    else
      echo "ERROR: Neither dpkg nor rpm found. Cannot install SSM Agent."
      exit 1
    fi
    ;;

  *)
    echo "Unsupported OS: ${OS}"
    exit 1
    ;;
esac

echo "==> SSM Agent installed successfully."
