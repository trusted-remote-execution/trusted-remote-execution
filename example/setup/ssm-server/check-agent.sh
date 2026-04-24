#!/bin/bash
set -euo pipefail

# Check if the SSM Agent is registered and online

REGION="${AWS_DEFAULT_REGION:-us-east-1}"
SCRIPT_DIR="$(dirname "$0")"

INSTANCE_ID=$("${SCRIPT_DIR}/get-instance-id.sh")

STATUS=$(aws ssm describe-instance-information \
  --filters "Key=InstanceIds,Values=${INSTANCE_ID}" \
  --region "${REGION}" \
  --query "InstanceInformationList[0].PingStatus" \
  --output text 2>/dev/null || echo "Unknown")

echo "Instance: ${INSTANCE_ID}"
echo "Status:   ${STATUS}"

if [ "${STATUS}" = "Online" ]; then
  exit 0
else
  exit 1
fi
