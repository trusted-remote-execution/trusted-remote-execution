#!/bin/bash
set -euo pipefail

# Deregister the managed instance from SSM
# Skips EC2 instances — they're managed by EC2, not hybrid activations.

REGION="${AWS_DEFAULT_REGION:-us-east-1}"
SCRIPT_DIR="$(dirname "$0")"

INSTANCE_ID=$("${SCRIPT_DIR}/get-instance-id.sh" 2>/dev/null || echo "")

if [ -z "${INSTANCE_ID}" ]; then
  echo "No instance ID found — nothing to deregister."
  exit 0
fi

if [[ "${INSTANCE_ID}" == i-* ]]; then
  echo "==> EC2 instance ${INSTANCE_ID} — skipping deregister (managed by EC2)."
  exit 0
fi

echo "==> Deregistering managed instance: ${INSTANCE_ID}..."
if aws ssm deregister-managed-instance \
  --instance-id "${INSTANCE_ID}" \
  --region "${REGION}" 2>/dev/null; then
  echo "==> Instance ${INSTANCE_ID} deregistered."
  # Clean up the registration file
  OS="$(uname -s)"
  case "${OS}" in
    Darwin) sudo rm -f /opt/aws/ssm/data/registration ;;
    Linux)  sudo rm -f /var/lib/amazon/ssm/registration ;;
  esac
else
  echo "==> Instance ${INSTANCE_ID} was already deregistered or not found. Skipping."
fi
