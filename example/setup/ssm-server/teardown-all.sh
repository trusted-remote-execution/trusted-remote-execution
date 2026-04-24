#!/bin/bash
set -uo pipefail

# One-click SSM teardown: stop, deregister, uninstall, and remove IAM role

SCRIPT_DIR="$(dirname "$0")"
ERRORS=0

echo "========================================="
echo "  SSM Agent Teardown"
echo "========================================="
echo ""

# On EC2, don't uninstall the agent, but still deregister hybrid instances and clean up IAM
EC2_ID=$(curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo "")
if [ -n "${EC2_ID}" ] && [[ "${EC2_ID}" == i-* ]]; then
  echo "==> EC2 instance detected (${EC2_ID}). Will deregister hybrid identity and clean up IAM."
  echo "==> Agent will not be uninstalled."
  echo ""

  echo "--- Step 1/3: Stop Agent ---"
  "${SCRIPT_DIR}/stop-agent.sh" || { echo "Warning: Stop agent failed, continuing..."; ERRORS=$((ERRORS + 1)); }
  echo ""

  echo "--- Step 2/3: Deregister Hybrid Instance ---"
  "${SCRIPT_DIR}/deregister-agent.sh" || { echo "Warning: Deregister failed, continuing..."; ERRORS=$((ERRORS + 1)); }
  echo ""

  echo "--- Step 3/3: Delete IAM Role ---"
  "${SCRIPT_DIR}/delete-iam-role.sh" || { echo "Warning: Delete IAM role failed, continuing..."; ERRORS=$((ERRORS + 1)); }
  echo ""

  # Restart the agent so it picks up EC2 identity if available
  sudo systemctl start amazon-ssm-agent 2>/dev/null || true

  echo "========================================="
  if [ "${ERRORS}" -ne 0 ]; then
    echo "  Teardown completed with ${ERRORS} error(s). Review output above."
  else
    echo "  Teardown complete (EC2 — agent restarted with EC2 identity)."
  fi
  echo "========================================="
  exit "${ERRORS}"
fi

echo "--- Step 1/4: Stop Agent ---"
"${SCRIPT_DIR}/stop-agent.sh" || { echo "Warning: Stop agent failed, continuing..."; ERRORS=$((ERRORS + 1)); }
echo ""

echo "--- Step 2/4: Deregister Instance ---"
"${SCRIPT_DIR}/deregister-agent.sh" || { echo "Warning: Deregister failed, continuing..."; ERRORS=$((ERRORS + 1)); }
echo ""

echo "--- Step 3/4: Uninstall Agent ---"
"${SCRIPT_DIR}/uninstall-ssm.sh" || { echo "Warning: Uninstall failed, continuing..."; ERRORS=$((ERRORS + 1)); }
echo ""

echo "--- Step 4/4: Delete IAM Role ---"
"${SCRIPT_DIR}/delete-iam-role.sh" || { echo "Warning: Delete IAM role failed, continuing..."; ERRORS=$((ERRORS + 1)); }
echo ""

echo "========================================="
if [ "${ERRORS}" -ne 0 ]; then
  echo "  Teardown completed with ${ERRORS} error(s). Review output above."
  exit 1
else
  echo "  Teardown complete."
fi
echo "========================================="
