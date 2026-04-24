#!/bin/bash
set -euo pipefail

# Step 4: Register the SSM Agent with the hybrid activation

REGION="${AWS_DEFAULT_REGION:-us-east-1}"

if [ $# -lt 2 ]; then
  echo "Usage: $0 <ACTIVATION_CODE> <ACTIVATION_ID>"
  echo "  These values come from the create-activation step."
  exit 1
fi

ACTIVATION_CODE="$1"
ACTIVATION_ID="$2"

OS="$(uname -s)"
case "${OS}" in
  Darwin) AGENT_BIN="/opt/aws/ssm/bin/amazon-ssm-agent" ;;
  Linux)  AGENT_BIN="/usr/bin/amazon-ssm-agent" ;;
  *)      echo "Unsupported OS: ${OS}" && exit 1 ;;
esac

echo "==> Registering SSM Agent (region: ${REGION})..."

# Skip if already registered
OS_CHECK="$(uname -s)"
case "${OS_CHECK}" in
  Darwin) REGISTRATION_FILE="/opt/aws/ssm/data/registration" ;;
  Linux)  REGISTRATION_FILE="/var/lib/amazon/ssm/registration" ;;
esac

if sudo test -f "${REGISTRATION_FILE}"; then
  EXISTING_ID=$(sudo cat "${REGISTRATION_FILE}" | python3 -c "import sys,json; print(json.load(sys.stdin)['ManagedInstanceID'])")
  echo "==> Already registered as ${EXISTING_ID}. Skipping."
else
  sudo "${AGENT_BIN}" -register \
    -code "${ACTIVATION_CODE}" \
    -id "${ACTIVATION_ID}" \
    -region "${REGION}"
  echo "==> Agent registered. Note the mi-xxxxxxxxxxxx instance ID from the output above."
fi
