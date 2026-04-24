#!/bin/bash
set -euo pipefail

# Generic Rex runner via SSM — specify which document (Rex-RO or Rex-RW).
# For convenience, use run-rex-ro.sh or run-rex-rw.sh instead.

REGION="${AWS_DEFAULT_REGION:-us-east-1}"
SCRIPT_DIR="$(dirname "$0")"

if [ $# -lt 2 ]; then
  echo "Usage: $0 <Rex-RO|Rex-RW> <script-file-or-inline> [--target <instance-id>] [--args <json-file>]"
  echo ""
  echo "Examples:"
  echo "  $0 Rex-RO 'cat(\"/etc/hostname\")'"
  echo "  $0 Rex-RW ./my-script.rhai --target mi-abc123"
  echo ""
  echo "Prefer the convenience wrappers:"
  echo "  run-rex-ro.sh <script>   — read-only policy"
  echo "  run-rex-rw.sh <script>   — read-write policy"
  exit 1
fi

DOC_NAME="$1"
SCRIPT_INPUT="$2"
shift 2

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

# Build parameters — read file content if it's a file
PARAMS="{\"script\":[$(python3 -c "import json; print(json.dumps(open('${SCRIPT_INPUT}').read() if __import__('os').path.isfile('${SCRIPT_INPUT}') else '${SCRIPT_INPUT}'))")]"
if [ -n "${SCRIPT_ARGS}" ]; then
  PARAMS="${PARAMS},\"scriptArgs\":[\"${SCRIPT_ARGS}\"]"
fi
PARAMS="${PARAMS}}"

echo "==> Running Rex (${DOC_NAME}) on ${INSTANCE_ID}..."
RESULT=$(aws ssm send-command \
  --document-name "${DOC_NAME}" \
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
