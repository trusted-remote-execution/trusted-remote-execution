#!/bin/bash
set -euo pipefail

# List all SSM managed instances

REGION="${AWS_DEFAULT_REGION:-us-east-1}"

aws ssm describe-instance-information \
  --region "${REGION}" \
  --query "InstanceInformationList[].{ID:InstanceId,Name:Name,Status:PingStatus,Platform:PlatformName,IP:IPAddress}" \
  --output table
