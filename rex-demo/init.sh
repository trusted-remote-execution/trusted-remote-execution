#!/bin/bash

# Initialize the rex-demo environment
# Safe to both execute (./rex-demo/init.sh) and source (source rex-demo/init.sh)

SCRIPT_DIR="$(dirname "${BASH_SOURCE[0]:-$0}")"

echo "==> Creating /tmp/rex-example..."
rm -rf /tmp/rex-example
mkdir -p /tmp/rex-example

echo "==> Copying demo files..."
cp "${SCRIPT_DIR}"/files/* /tmp/rex-example/

# Set up Python venv if not already present
AGENT_DIR="${SCRIPT_DIR}/agent"
if [ ! -d "${AGENT_DIR}/.venv" ]; then
  # Find a Python >= 3.10
  find_python() {
    for cmd in python3.13 python3.12 python3.11 python3; do
      PY=$(command -v "${cmd}" 2>/dev/null || echo "")
      if [ -n "${PY}" ]; then
        VERSION=$("${PY}" -c "import sys; print(sys.version_info >= (3, 10))" 2>/dev/null || echo "False")
        if [ "${VERSION}" = "True" ]; then
          echo "${PY}"
          return
        fi
      fi
    done
    echo ""
  }

  PYTHON=$(find_python)
  if [ -z "${PYTHON}" ]; then
    echo "ERROR: Python 3.10+ not found."
    return 1 2>/dev/null || exit 1
  fi

  echo "==> Creating Python venv (${PYTHON})..."
  "${PYTHON}" -m venv "${AGENT_DIR}/.venv"
  echo "==> Installing Python dependencies..."
  "${AGENT_DIR}/.venv/bin/pip" install -q -r "${AGENT_DIR}/requirements.txt"
else
  echo "==> Python venv already exists, skipping"
fi

echo "==> Done. Contents of /tmp/rex-example:"
ls -la /tmp/rex-example/

echo ""
echo "==> To start the demo, run:"
echo "    source rex-demo/init.sh"
echo ""
echo "Or manually:"
echo "    source ${AGENT_DIR}/.venv/bin/activate"
echo "    ops-agent 'your prompt here'"

# If this script is sourced (not executed), activate venv and create alias
if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
  source "${AGENT_DIR}/.venv/bin/activate"
  AGENT_PY="$(cd "${AGENT_DIR}" && pwd)/agent.py"
  alias ops-agent="python ${AGENT_PY}"
  clear
  echo "✅ Demo ready. Use: ops-agent 'your prompt here'"
fi
