#!/bin/bash
set -euo pipefail

# Get the SSM managed instance ID for this machine.
# Checks EC2 metadata first (and verifies it's actually registered with SSM),
# then falls back to the hybrid registration file.
# Prints the instance ID to stdout.

REGION="${AWS_DEFAULT_REGION:-us-east-1}"

# Try EC2 metadata first
EC2_ID=$(curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo "")
if [ -n "${EC2_ID}" ] && [[ "${EC2_ID}" == i-* ]]; then
  # Verify this EC2 identity is actually registered with SSM
  STATUS=$(aws ssm describe-instance-information \
    --filters "Key=InstanceIds,Values=${EC2_ID}" \
    --region "${REGION}" \
    --query "InstanceInformationList[0].PingStatus" \
    --output text 2>/dev/null || echo "None")
  if [ "${STATUS}" != "None" ]; then
    echo "${EC2_ID}"
    exit 0
  fi
fi

# Fall back to registration file (hybrid activation)
OS="$(uname -s)"
case "${OS}" in
  Darwin) REGISTRATION_FILE="/opt/aws/ssm/data/registration" ;;
  Linux)  REGISTRATION_FILE="/var/lib/amazon/ssm/registration" ;;
  *)      echo "Unsupported OS: ${OS}" >&2 && exit 1 ;;
esac

if sudo test -f "${REGISTRATION_FILE}"; then
  sudo cat "${REGISTRATION_FILE}" | python3 -c "import sys,json; print(json.load(sys.stdin)['ManagedInstanceID'])"
  exit 0
fi

echo "ERROR: Cannot determine instance ID" >&2
exit 1
