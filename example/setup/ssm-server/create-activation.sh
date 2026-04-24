#!/bin/bash
set -euo pipefail

# Step 3: Create a Hybrid Activation

REGION="${AWS_DEFAULT_REGION:-us-east-1}"
ROLE_NAME="SSMServiceRole"
INSTANCE_NAME="${1:-my-laptop}"

echo "==> Creating hybrid activation (region: ${REGION}, name: ${INSTANCE_NAME})..."
ACTIVATION=$(aws ssm create-activation \
  --default-instance-name "${INSTANCE_NAME}" \
  --iam-role "${ROLE_NAME}" \
  --registration-limit 1 \
  --region "${REGION}" \
  --output json)

ACTIVATION_ID=$(echo "${ACTIVATION}" | python3 -c "import sys,json; print(json.load(sys.stdin)['ActivationId'])")
ACTIVATION_CODE=$(echo "${ACTIVATION}" | python3 -c "import sys,json; print(json.load(sys.stdin)['ActivationCode'])")

echo "==> Activation created successfully."
echo ""
echo "  ActivationId:   ${ACTIVATION_ID}"
echo "  ActivationCode: ${ACTIVATION_CODE}"
echo ""
echo "Save these values — you'll need them for the register step."
