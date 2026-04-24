#!/bin/bash
set -euo pipefail

# Set up the Strands agent virtual environment

SCRIPT_DIR="$(dirname "$0")"

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

  # Check common linuxbrew paths
  for ver in 3.13 3.12 3.11; do
    PY="/home/linuxbrew/.linuxbrew/opt/python@${ver}/bin/python${ver}"
    if [ -x "${PY}" ]; then
      echo "${PY}"
      return
    fi
  done

  echo ""
}

PYTHON=$(find_python)
if [ -z "${PYTHON}" ]; then
  echo "ERROR: Python 3.10+ not found."
  echo "Install it via your package manager or linuxbrew."
  exit 1
fi

echo "==> Using Python: ${PYTHON} ($("${PYTHON}" --version))"

# Always recreate the venv to avoid cross-machine symlink issues
rm -rf "${SCRIPT_DIR}/.venv"

echo "==> Creating virtual environment..."
"${PYTHON}" -m venv "${SCRIPT_DIR}/.venv"

echo "==> Installing dependencies..."
"${SCRIPT_DIR}/.venv/bin/pip" install -q -r "${SCRIPT_DIR}/requirements.txt"

echo "==> Done. Run the agent with:"
echo "    source ${SCRIPT_DIR}/.venv/bin/activate"
echo "    python ${SCRIPT_DIR}/agent.py 'your prompt here'"
