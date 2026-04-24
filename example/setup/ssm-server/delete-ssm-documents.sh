#!/bin/bash
set -euo pipefail

# Delete custom SSM documents for Rex-RO and Rex-RW

REGION="${AWS_DEFAULT_REGION:-us-east-1}"

for DOC_NAME in Rex-RO Rex-RW; do
  echo "==> Deleting SSM document: ${DOC_NAME}..."
  if aws ssm delete-document --name "${DOC_NAME}" --region "${REGION}" 2>/dev/null; then
    echo "    Deleted."
  else
    echo "    Not found or already deleted. Skipping."
  fi
done

echo "==> Done."
