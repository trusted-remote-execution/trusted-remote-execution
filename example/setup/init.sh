#!/bin/bash
set -euo pipefail

# Initialize the /tmp/rex_example directory with example scripts and policies

SCRIPT_DIR="$(dirname "$0")"

echo "==> Creating /tmp/rex_example..."
mkdir -p /tmp/rex_example

echo "==> Copying example files..."
cp "${SCRIPT_DIR}"/files/* /tmp/rex_example/

# macOS resolves /tmp to /private/tmp — Cedar needs the real path
if [ "$(uname -s)" = "Darwin" ]; then
  echo "==> Adjusting paths for macOS..."
  sed -i '' 's|/tmp/rex_example|/private/tmp/rex_example|g' /tmp/rex_example/*.cedar /tmp/rex_example/*.rhai
fi

echo "==> Done. Contents:"
ls -la /tmp/rex_example/
