#!/bin/bash
set -euo pipefail

# Allow a specific AWS account to call SSM SendCommand and GetCommandInvocation
# on the managed instance in this account.

REGION="${AWS_DEFAULT_REGION:-us-east-1}"

if [ $# -lt 1 ]; then
  echo "Usage: $0 <account-id>"
  echo "  Grants the specified AWS account permission to run SSM commands"
  echo "  on the managed instance registered in this account."
  exit 1
fi

CALLER_ACCOUNT_ID="$1"
POLICY_NAME="AllowSSMFromAccount-${CALLER_ACCOUNT_ID}"
ROLE_NAME="SSMCrossAccountRole-${CALLER_ACCOUNT_ID}"

# Get the local account ID
LOCAL_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Get the managed instance ID
OS="$(uname -s)"
case "${OS}" in
  Darwin) REGISTRATION_FILE="/opt/aws/ssm/data/registration" ;;
  Linux)  REGISTRATION_FILE="/var/lib/amazon/ssm/registration" ;;
  *)      echo "Unsupported OS: ${OS}" && exit 1 ;;
esac

INSTANCE_ID=$(sudo cat "${REGISTRATION_FILE}" | python3 -c "import sys,json; print(json.load(sys.stdin)['ManagedInstanceID'])")

echo "==> Local account:    ${LOCAL_ACCOUNT_ID}"
echo "==> Caller account:   ${CALLER_ACCOUNT_ID}"
echo "==> Managed instance: ${INSTANCE_ID}"

# Create a role that the caller account can assume
echo "==> Creating cross-account role: ${ROLE_NAME}..."
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
    }"
fi

# Create and attach the policy that allows SSM commands on this instance
echo "==> Creating policy: ${POLICY_NAME}..."
POLICY_DOC="{
  \"Version\": \"2012-10-17\",
  \"Statement\": [
    {
      \"Effect\": \"Allow\",
      \"Action\": [
        \"ssm:SendCommand\",
        \"ssm:GetCommandInvocation\"
      ],
      \"Resource\": [
        \"arn:aws:ssm:${REGION}:${LOCAL_ACCOUNT_ID}:managed-instance/${INSTANCE_ID}\",
        \"arn:aws:ssm:${REGION}::document/AWS-RunShellScript\"
      ]
    },
    {
      \"Effect\": \"Allow\",
      \"Action\": \"ssm:ListCommandInvocations\",
      \"Resource\": \"*\"
    }
  ]
}"

# Check if policy already exists
EXISTING_ARN=$(aws iam list-policies --scope Local --query "Policies[?PolicyName=='${POLICY_NAME}'].Arn" --output text 2>/dev/null || echo "")

if [ -n "${EXISTING_ARN}" ] && [ "${EXISTING_ARN}" != "None" ]; then
  echo "    Policy already exists. Updating..."
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
echo "==> Done. Account ${CALLER_ACCOUNT_ID} can now assume this role:"
echo "    arn:aws:iam::${LOCAL_ACCOUNT_ID}:role/${ROLE_NAME}"
echo ""
echo "    The role allows ssm:SendCommand and ssm:GetCommandInvocation"
echo "    scoped to instance ${INSTANCE_ID} and document AWS-RunShellScript only."
