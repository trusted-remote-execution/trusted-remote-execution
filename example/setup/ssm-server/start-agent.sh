#!/bin/bash
set -euo pipefail

# Step 5: Start the SSM Agent and verify it comes online

REGION="${AWS_DEFAULT_REGION:-us-east-1}"
OS="$(uname -s)"
SCRIPT_DIR="$(dirname "$0")"
MAX_ATTEMPTS=12
SLEEP_SECONDS=5

INSTANCE_ID=$("${SCRIPT_DIR}/get-instance-id.sh")
echo "==> Found instance ID: ${INSTANCE_ID}"

case "${OS}" in
  Darwin)
    echo "==> Starting SSM Agent via launchctl..."
    sudo launchctl load -w /Library/LaunchDaemons/com.amazon.aws.ssm.plist 2>/dev/null || true
    ;;
  Linux)
    echo "==> Starting SSM Agent via systemctl..."
    sudo systemctl enable amazon-ssm-agent
    sudo systemctl start amazon-ssm-agent
    ;;
  *)
    echo "Unsupported OS: ${OS}"
    exit 1
    ;;
esac

echo "==> Waiting for agent to come online..."
for i in $(seq 1 "${MAX_ATTEMPTS}"); do
  STATUS=$(aws ssm describe-instance-information \
    --filters "Key=InstanceIds,Values=${INSTANCE_ID}" \
    --region "${REGION}" \
    --query "InstanceInformationList[0].PingStatus" \
    --output text 2>/dev/null || echo "Unknown")

  if [ "${STATUS}" = "Online" ]; then
    echo "==> Agent is online. Instance ID: ${INSTANCE_ID}"
    exit 0
  fi

  echo "    Attempt ${i}/${MAX_ATTEMPTS}: status=${STATUS}, retrying in ${SLEEP_SECONDS}s..."
  sleep "${SLEEP_SECONDS}"
done

case "${OS}" in
  Darwin) LOG_PATH="/opt/aws/ssm/logs/amazon-ssm-agent.log" ;;
  Linux)  LOG_PATH="/var/log/amazon/ssm/amazon-ssm-agent.log" ;;
esac
echo "ERROR: Agent did not come online after $((MAX_ATTEMPTS * SLEEP_SECONDS))s."
echo "Check the agent log at ${LOG_PATH}"
exit 1
