#!/bin/bash
set -euo pipefail

# Allow a specific AWS account to invoke Rex-RO and/or Rex-RW SSM documents.
# Usage: allow-account-rex.sh <account-id> <ro|rw|both>

REGION="${AWS_DEFAULT_REGION:-us-east-1}"

if [ $# -lt 2 ]; then
  echo "Usage: $0 <account-id> <ro|rw|both>"
  echo "  ro   — only allow Rex-RO (read-only)"
  echo "  rw   — only allow Rex-RW (read-write)"
  echo "  both — allow both Rex-RO and Rex-RW"
  exit 1
fi

CALLER_ACCOUNT_ID="$1"
ACCESS_LEVEL="$2"

LOCAL_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Get instance ID
OS="$(uname -s)"
case "${OS}" in
  Darwin) REGISTRATION_FILE="/opt/aws/ssm/data/registration" ;;
  Linux)  REGISTRATION_FILE="/var/lib/amazon/ssm/registration" ;;
  *)      echo "Unsupported OS: ${OS}" && exit 1 ;;
esac
INSTANCE_ID=$(sudo cat "${REGISTRATION_FILE}" | python3 -c "import sys,json; print(json.load(sys.stdin)['ManagedInstanceID'])")

# Build document ARN list based on access level
case "${ACCESS_LEVEL}" in
  ro)
    DOC_ARNS="\"arn:aws:ssm:${REGION}:${LOCAL_ACCOUNT_ID}:document/Rex-RO\""
    ROLE_SUFFIX="RO"
    ;;
  rw)
    DOC_ARNS="\"arn:aws:ssm:${REGION}:${LOCAL_ACCOUNT_ID}:document/Rex-RW\""
    ROLE_SUFFIX="RW"
    ;;
  both)
    DOC_ARNS="\"arn:aws:ssm:${REGION}:${LOCAL_ACCOUNT_ID}:document/Rex-RO\", \"arn:aws:ssm:${REGION}:${LOCAL_ACCOUNT_ID}:document/Rex-RW\""
    ROLE_SUFFIX="Both"
    ;;
  *)
    echo "Invalid access level: ${ACCESS_LEVEL}. Use ro, rw, or both."
    exit 1
    ;;
esac

ROLE_NAME="RexCaller-${CALLER_ACCOUNT_ID}-${ROLE_SUFFIX}"
POLICY_NAME="RexAccess-${CALLER_ACCOUNT_ID}-${ROLE_SUFFIX}"

echo "==> Local account:    ${LOCAL_ACCOUNT_ID}"
echo "==> Caller account:   ${CALLER_ACCOUNT_ID}"
echo "==> Instance:         ${INSTANCE_ID}"
echo "==> Access level:     ${ACCESS_LEVEL}"

# Create the cross-account role
echo "==> Creating role: ${ROLE_NAME}..."
if aws iam get-role --role-name "${ROLE_NAME}" >/dev/null 2>&1; then
  echo "    Role already exists. Skipping creation."
else
  aws iam create-role \
    --role-name "${ROLE_NAME}" \
    --assume-role-policy-document "{
      \"Version\": \"2012-10-17\",
      \"Statement\": [{
        \"Effect\": \"Allow\",
        \"Principal\": {\"AWS\": \"arn:aws:iam::${CALLER_ACCOUNT_ID}:root\"},
        \"Action\": \"sts:AssumeRole\"
      }]
    }" >/dev/null
fi

# Create the scoped policy
POLICY_DOC="{
  \"Version\": \"2012-10-17\",
  \"Statement\": [
    {
      \"Effect\": \"Allow\",
      \"Action\": \"ssm:SendCommand\",
      \"Resource\": [
        \"arn:aws:ssm:${REGION}:${LOCAL_ACCOUNT_ID}:managed-instance/${INSTANCE_ID}\",
        ${DOC_ARNS}
      ]
    },
    {
      \"Effect\": \"Allow\",
      \"Action\": \"ssm:GetCommandInvocation\",
      \"Resource\": \"*\"
    }
  ]
}"

echo "==> Creating policy: ${POLICY_NAME}..."
EXISTING_ARN=$(aws iam list-policies --scope Local --query "Policies[?PolicyName=='${POLICY_NAME}'].Arn" --output text 2>/dev/null || echo "")

if [ -n "${EXISTING_ARN}" ] && [ "${EXISTING_ARN}" != "None" ]; then
  echo "    Policy exists. Updating..."
  aws iam create-policy-version \
    --policy-arn "${EXISTING_ARN}" \
    --policy-document "${POLICY_DOC}" \
    --set-as-default >/dev/null
  POLICY_ARN="${EXISTING_ARN}"
else
  POLICY_ARN=$(aws iam create-policy \
    --policy-name "${POLICY_NAME}" \
    --policy-document "${POLICY_DOC}" \
    --query "Policy.Arn" --output text)
fi

echo "==> Attaching policy to role..."
aws iam attach-role-policy \
  --role-name "${ROLE_NAME}" \
  --policy-arn "${POLICY_ARN}"

echo ""
echo "==> Done. Account ${CALLER_ACCOUNT_ID} can assume:"
echo "    arn:aws:iam::${LOCAL_ACCOUNT_ID}:role/${ROLE_NAME}"
echo ""
echo "    Allowed documents: ${ACCESS_LEVEL}"
echo "    Scoped to instance: ${INSTANCE_ID}"
