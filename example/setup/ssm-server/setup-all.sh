#!/bin/bash
set -euo pipefail

# One-click SSM setup: install, configure IAM, activate, register, and start

SCRIPT_DIR="$(dirname "$0")"
INSTANCE_NAME="${1:-$(hostname -s)}"

echo "========================================="
echo "  SSM Agent Setup"
echo "========================================="
echo ""

# Check if running on EC2 with a working SSM identity
EC2_INSTANCE_ID=$(curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo "")

if [ -n "${EC2_INSTANCE_ID}" ] && [[ "${EC2_INSTANCE_ID}" == i-* ]]; then
  REGION="${AWS_DEFAULT_REGION:-us-east-1}"
  STATUS=$(aws ssm describe-instance-information \
    --filters "Key=InstanceIds,Values=${EC2_INSTANCE_ID}" \
    --region "${REGION}" \
    --query "InstanceInformationList[0].PingStatus" \
    --output text 2>/dev/null || echo "None")

  if [ "${STATUS}" != "None" ]; then
    echo "==> Running on EC2 instance: ${EC2_INSTANCE_ID} (SSM active)"
    echo "==> Ensuring SSM agent is installed and running..."
    "${SCRIPT_DIR}/install-ssm.sh"
    "${SCRIPT_DIR}/start-agent.sh"
    echo "========================================="
    exit 0
  else
    echo "==> EC2 instance detected (${EC2_INSTANCE_ID}) but not registered with SSM."
    echo "==> Proceeding with hybrid activation setup..."
  fi
fi

# Check if already registered as a hybrid managed instance
OS="$(uname -s)"
case "${OS}" in
  Darwin) REGISTRATION_FILE="/opt/aws/ssm/data/registration" ;;
  Linux)  REGISTRATION_FILE="/var/lib/amazon/ssm/registration" ;;
  *)      echo "Unsupported OS: ${OS}" && exit 1 ;;
esac

if sudo test -f "${REGISTRATION_FILE}"; then
  EXISTING_ID=$(sudo cat "${REGISTRATION_FILE}" | python3 -c "import sys,json; print(json.load(sys.stdin)['ManagedInstanceID'])")
  if [[ "${EXISTING_ID}" == mi-* ]]; then
    echo "==> Already registered as hybrid instance: ${EXISTING_ID}"
    echo "==> Verifying agent is running..."
    "${SCRIPT_DIR}/start-agent.sh"
    echo "========================================="
    exit 0
  fi
fi

# Step 1: Install the SSM Agent
echo "--- Step 1/5: Install SSM Agent ---"
"${SCRIPT_DIR}/install-ssm.sh"
echo ""

# Step 2: Create IAM Role
echo "--- Step 2/5: Create IAM Role ---"
"${SCRIPT_DIR}/create-iam-role.sh"
echo ""

# Step 3: Create Hybrid Activation (capture output to extract code/id)
# Retry to handle IAM eventual consistency after role creation
echo "--- Step 3/5: Create Hybrid Activation ---"
REGION="${AWS_DEFAULT_REGION:-us-east-1}"
MAX_RETRIES=6
RETRY_DELAY=10
ACTIVATION=""
for i in $(seq 1 "${MAX_RETRIES}"); do
  ACTIVATION=$(aws ssm create-activation \
    --default-instance-name "${INSTANCE_NAME}" \
    --iam-role SSMServiceRole \
    --registration-limit 1 \
    --region "${REGION}" \
    --output json 2>/dev/null) && break

  echo "    IAM role not yet visible to SSM. Retry ${i}/${MAX_RETRIES} in ${RETRY_DELAY}s..."
  sleep "${RETRY_DELAY}"
done

if [ -z "${ACTIVATION}" ]; then
  echo "ERROR: Failed to create activation after ${MAX_RETRIES} retries."
  exit 1
fi

ACTIVATION_ID=$(echo "${ACTIVATION}" | python3 -c "import sys,json; print(json.load(sys.stdin)['ActivationId'])")
ACTIVATION_CODE=$(echo "${ACTIVATION}" | python3 -c "import sys,json; print(json.load(sys.stdin)['ActivationCode'])")
echo "==> Activation created: ID=${ACTIVATION_ID}"
echo ""

# Step 4: Stop any existing agent, then register with new credentials
echo "--- Step 4/5: Register Agent ---"
"${SCRIPT_DIR}/stop-agent.sh" 2>/dev/null || true
"${SCRIPT_DIR}/register-agent.sh" "${ACTIVATION_CODE}" "${ACTIVATION_ID}"
echo ""

# Step 5: Start and Verify
echo "--- Step 5/5: Start Agent ---"
"${SCRIPT_DIR}/start-agent.sh"
echo ""

echo "========================================="
echo "  Setup complete."
echo "========================================="
