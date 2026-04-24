#!/bin/bash
set -euo pipefail

# Delete the SSM IAM Role

ROLE_NAME="SSMServiceRole"

echo "==> Detaching policy from ${ROLE_NAME}..."
aws iam detach-role-policy \
  --role-name "${ROLE_NAME}" \
  --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore 2>/dev/null || true

echo "==> Deleting role ${ROLE_NAME}..."
if aws iam delete-role --role-name "${ROLE_NAME}" 2>/dev/null; then
  echo "==> IAM role ${ROLE_NAME} deleted."
else
  echo "==> IAM role ${ROLE_NAME} was already deleted or not found. Skipping."
fi
