#!/bin/bash
set -euo pipefail

# Run a command on the managed instance via SSM

REGION="${AWS_DEFAULT_REGION:-us-east-1}"
SCRIPT_DIR="$(dirname "$0")"

# Support --target <instance-id> to target a specific host
INSTANCE_ID=""
if [ "${1:-}" = "--target" ]; then
  INSTANCE_ID="$2"
  shift 2
fi

if [ $# -lt 1 ]; then
  echo "Usage: $0 [--target <instance-id>] <command> [command2] ..."
  echo "  Example: $0 'ls /tmp'"
  echo "  Example: $0 --target mi-077276a44fec059af 'ls /tmp'"
  exit 1
fi

if [ -z "${INSTANCE_ID}" ]; then
  INSTANCE_ID=$("${SCRIPT_DIR}/../ssm-server/get-instance-id.sh")
fi

# Build the commands JSON array
COMMANDS=$(python3 -c "import sys,json; print(json.dumps(sys.argv[1:]))" "$@")

echo "==> Sending command to ${INSTANCE_ID}..."
RESULT=$(aws ssm send-command \
  --instance-ids "${INSTANCE_ID}" \
  --document-name "AWS-RunShellScript" \
  --parameters "{\"commands\":${COMMANDS}}" \
  --region "${REGION}" \
  --output json)

COMMAND_ID=$(echo "${RESULT}" | python3 -c "import sys,json; print(json.load(sys.stdin)['Command']['CommandId'])")
echo "==> CommandId: ${COMMAND_ID}"
echo "==> Waiting for result..."

# Poll until the command completes
for i in $(seq 1 24); do
  sleep 2
  INVOCATION=$(aws ssm get-command-invocation \
    --command-id "${COMMAND_ID}" \
    --instance-id "${INSTANCE_ID}" \
    --region "${REGION}" \
    --output json 2>/dev/null || echo "")

  if [ -z "${INVOCATION}" ]; then
    continue
  fi

  STATUS=$(echo "${INVOCATION}" | python3 -c "import sys,json; print(json.load(sys.stdin)['Status'])")

  case "${STATUS}" in
    Success)
      echo "${INVOCATION}" | python3 -c "import sys,json; print(json.load(sys.stdin)['StandardOutputContent'])"
      exit 0
      ;;
    Failed|TimedOut|Cancelled)
      echo "==> Command ${STATUS}"
      STDOUT=$(echo "${INVOCATION}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('StandardOutputContent',''))")
      STDERR=$(echo "${INVOCATION}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('StandardErrorContent',''))")
      if [ -n "${STDOUT}" ]; then
        echo "==> STDOUT:"
        echo "${STDOUT}"
      fi
      if [ -n "${STDERR}" ]; then
        echo "==> STDERR:"
        echo "${STDERR}"
      fi
      exit 1
      ;;
    *)
      continue
      ;;
  esac
done

echo "ERROR: Timed out waiting for command result."
exit 1
