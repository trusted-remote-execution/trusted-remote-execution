#!/bin/bash
set -euo pipefail

# Step 2: Create the IAM Role for SSM

ROLE_NAME="SSMServiceRole"

echo "==> Creating IAM role: ${ROLE_NAME}..."
if aws iam get-role --role-name "${ROLE_NAME}" >/dev/null 2>&1; then
  echo "    Role already exists. Skipping creation."
else
  aws iam create-role \
    --role-name "${ROLE_NAME}" \
    --assume-role-policy-document '{
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "ssm.amazonaws.com"},
        "Action": "sts:AssumeRole"
      }]
    }'
fi

echo "==> Attaching AmazonSSMManagedInstanceCore policy..."
aws iam attach-role-policy \
  --role-name "${ROLE_NAME}" \
  --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore

echo "==> IAM role ${ROLE_NAME} created and policy attached."
