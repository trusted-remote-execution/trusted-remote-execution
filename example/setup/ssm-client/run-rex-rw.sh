#!/bin/bash
set -euo pipefail

# Run a Rhai script via SSM with READ-WRITE policy.
# Uses the Rex-RW SSM document which hardcodes the readwrite.cedar policy.
# The caller only provides the script — never the policy.

REGION="${AWS_DEFAULT_REGION:-us-east-1}"
SCRIPT_DIR="$(dirname "$0")"

if [ $# -lt 1 ]; then
  echo "Usage: $0 <script-file-or-inline> [--target <instance-id>] [--args <json-file>]"
  echo ""
  echo "Examples:"
  echo "  $0 'replace(\"/tmp/data.txt\", \"hello world\")'"
  echo "  $0 ./my-script.rhai"
  echo "  $0 ./my-script.rhai --target mi-abc123"
  echo "  $0 ./my-script.rhai --args /tmp/args.json"
  exit 1
fi

SCRIPT_INPUT="$1"
shift

# Parse optional flags
INSTANCE_ID=""
SCRIPT_ARGS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --target) INSTANCE_ID="$2"; shift 2 ;;
    --args)   SCRIPT_ARGS="$2"; shift 2 ;;
    *)        echo "Unknown option: $1"; exit 1 ;;
  esac
done

# Resolve instance ID if not provided
if [ -z "${INSTANCE_ID}" ]; then
  INSTANCE_ID=$("${SCRIPT_DIR}/../ssm-server/get-instance-id.sh")
fi

# Build parameters
PARAMS="{\"script\":[$(python3 -c "import json; print(json.dumps(open('${SCRIPT_INPUT}').read() if __import__('os').path.isfile('${SCRIPT_INPUT}') else '${SCRIPT_INPUT}'))")]"
if [ -n "${SCRIPT_ARGS}" ]; then
  PARAMS="${PARAMS},\"scriptArgs\":[\"${SCRIPT_ARGS}\"]"
fi
PARAMS="${PARAMS}}"

echo "==> Running Rex (READ-WRITE) on ${INSTANCE_ID}..."
RESULT=$(aws ssm send-command \
  --document-name "Rex-RW" \
  --instance-ids "${INSTANCE_ID}" \
  --parameters "${PARAMS}" \
  --region "${REGION}" \
  --output json)

COMMAND_ID=$(echo "${RESULT}" | python3 -c "import sys,json; print(json.load(sys.stdin)['Command']['CommandId'])")
echo "==> CommandId: ${COMMAND_ID}"
echo "==> Waiting for result..."

for i in $(seq 1 30); do
  sleep 2
  INVOCATION=$(aws ssm get-command-invocation \
    --command-id "${COMMAND_ID}" \
    --instance-id "${INSTANCE_ID}" \
    --region "${REGION}" \
    --output json 2>/dev/null || echo "")

  [ -z "${INVOCATION}" ] && continue

  STATUS=$(echo "${INVOCATION}" | python3 -c "import sys,json; print(json.load(sys.stdin)['Status'])")

  case "${STATUS}" in
    Success)
      echo "${INVOCATION}" | python3 -c "import sys,json; print(json.load(sys.stdin)['StandardOutputContent'])"
      exit 0
      ;;
    Failed|TimedOut|Cancelled)
      echo "==> Command ${STATUS}"
      echo "${INVOCATION}" | python3 -c "
import sys,json
inv = json.load(sys.stdin)
out = inv.get('StandardOutputContent','')
err = inv.get('StandardErrorContent','')
if out: print('STDOUT:', out)
if err: print('STDERR:', err)
"
      exit 1
      ;;
  esac
done

echo "ERROR: Timed out waiting for command result."
exit 1
