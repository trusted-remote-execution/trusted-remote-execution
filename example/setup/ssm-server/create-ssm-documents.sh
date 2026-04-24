#!/bin/bash
set -euo pipefail

# Create custom SSM documents for Rex-RO and Rex-RW.
#
# Each document:
#   - Accepts a "script" parameter (inline Rhai script content)
#   - Embeds the Cedar policy directly (immutable, not caller-controllable)
#   - Writes both script and policy to temp files, runs the runner, cleans up
#
# The runner binary must be installed at /opt/rex/bin/runner on the instance.
# No policy files need to be pre-deployed — they're embedded in the document.

REGION="${AWS_DEFAULT_REGION:-us-east-1}"
RUNNER_BIN="${REX_RUNNER_BIN:-/opt/rex/bin/runner}"

# ── Read-only Cedar policy (embedded in Rex-RO document) ────────────────
read -r -d '' RO_POLICY << 'CEDAR_EOF' || true
permit(
    principal,
    action in [
        file_system::Action::"open",
        file_system::Action::"read",
        file_system::Action::"stat"
    ],
    resource
) when {
    resource in file_system::Dir::"/tmp/rex" ||
    resource == file_system::Dir::"/tmp/rex"
};
permit(
    principal,
    action in [
        file_system::Action::"open",
        file_system::Action::"read",
        file_system::Action::"stat"
    ],
    resource
) when {
    resource == file_system::Dir::"/tmp" ||
    resource == file_system::File::"/tmp"
};
permit(
    principal,
    action in [
        file_system::Action::"open",
        file_system::Action::"read",
        file_system::Action::"stat"
    ],
    resource
) when {
    resource in file_system::Dir::"/proc" ||
    resource == file_system::Dir::"/proc" ||
    resource == file_system::File::"/proc"
};
permit(
    principal,
    action in [sysinfo::Action::"list", sysinfo::Action::"resolve_hostname"],
    resource
);
permit(
    principal,
    action in [process_system::Action::"list", process_system::Action::"list_fds"],
    resource
);
permit(
    principal,
    action in [file_system::Action::"stat"],
    resource
);
CEDAR_EOF

# ── Read-write Cedar policy (embedded in Rex-RW document) ───────────────
read -r -d '' RW_POLICY << 'CEDAR_EOF' || true
permit(
    principal,
    action in [
        file_system::Action::"open",
        file_system::Action::"read",
        file_system::Action::"write",
        file_system::Action::"create",
        file_system::Action::"delete",
        file_system::Action::"stat",
        file_system::Action::"chmod",
        file_system::Action::"chown",
        file_system::Action::"move",
        file_system::Action::"execute"
    ],
    resource
) when {
    resource in file_system::Dir::"/tmp/rex" ||
    resource == file_system::Dir::"/tmp/rex"
};
permit(
    principal,
    action in [
        file_system::Action::"open",
        file_system::Action::"read",
        file_system::Action::"stat",
        file_system::Action::"create"
    ],
    resource
) when {
    resource == file_system::Dir::"/tmp" ||
    resource == file_system::File::"/tmp"
};
permit(
    principal,
    action in [
        file_system::Action::"open",
        file_system::Action::"read",
        file_system::Action::"stat"
    ],
    resource
) when {
    resource in file_system::Dir::"/proc" ||
    resource == file_system::Dir::"/proc" ||
    resource == file_system::File::"/proc"
};
permit(
    principal,
    action in [
        file_system::Action::"open",
        file_system::Action::"read",
        file_system::Action::"stat",
        file_system::Action::"execute"
    ],
    resource
) when {
    resource in file_system::Dir::"/usr/bin" ||
    resource == file_system::Dir::"/usr/bin"
};
permit(
    principal,
    action in [sysinfo::Action::"list", sysinfo::Action::"resolve_hostname"],
    resource
);
permit(
    principal,
    action in [process_system::Action::"list", process_system::Action::"list_fds"],
    resource
);
permit(
    principal,
    action in [file_system::Action::"stat"],
    resource
);
permit(
    principal,
    action in [network::Action::"GET", network::Action::"connect"],
    resource
) when {
    resource.url like "https://*" ||
    resource.url like "http://*"
};
CEDAR_EOF

create_document() {
  local DOC_NAME="$1"
  local POLICY_CONTENT="$2"
  local DESCRIPTION="$3"

  # Escape the policy for JSON embedding
  local ESCAPED_POLICY
  ESCAPED_POLICY=$(printf '%s' "${POLICY_CONTENT}" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))")

  local DOC_CONTENT
  DOC_CONTENT=$(cat <<DOCEOF
{
  "schemaVersion": "2.2",
  "description": "${DESCRIPTION}",
  "parameters": {
    "script": {
      "type": "String",
      "description": "Rhai script content to execute"
    },
    "scriptArgs": {
      "type": "String",
      "description": "Optional: JSON file path for script arguments",
      "default": ""
    }
  },
  "mainSteps": [{
    "action": "aws:runShellScript",
    "name": "runRex",
    "inputs": {
      "runCommand": [
        "#!/bin/bash",
        "set -euo pipefail",
        "TMPSCRIPT=\$(mktemp /tmp/rex-XXXXXX.rhai)",
        "TMPPOLICY=\$(mktemp /tmp/rex-XXXXXX.cedar)",
        "trap 'rm -f \"\$TMPSCRIPT\" \"\$TMPPOLICY\"' EXIT",
        "cat <<'RHAI_SCRIPT_EOF' > \"\$TMPSCRIPT\"",
        "{{ script }}",
        "RHAI_SCRIPT_EOF",
        "cat <<'CEDAR_POLICY_EOF' > \"\$TMPPOLICY\"",
        ${ESCAPED_POLICY},
        "CEDAR_POLICY_EOF",
        "ARGS=\"\"",
        "if [ -n '{{ scriptArgs }}' ] && [ -f '{{ scriptArgs }}' ]; then",
        "  ARGS=\"-a '{{ scriptArgs }}'\"",
        "fi",
        "${RUNNER_BIN} -s \"\$TMPSCRIPT\" -p \"\$TMPPOLICY\" -o human \$ARGS"
      ]
    }
  }]
}
DOCEOF
)

  echo "==> Creating SSM document: ${DOC_NAME}..."
  if aws ssm describe-document --name "${DOC_NAME}" --region "${REGION}" >/dev/null 2>&1; then
    echo "    Document exists. Updating..."
    aws ssm update-document \
      --name "${DOC_NAME}" \
      --content "${DOC_CONTENT}" \
      --document-version "\$LATEST" \
      --region "${REGION}" >/dev/null 2>&1 || echo "    Already up to date."
  else
    aws ssm create-document \
      --name "${DOC_NAME}" \
      --document-type "Command" \
      --content "${DOC_CONTENT}" \
      --document-format "JSON" \
      --region "${REGION}" >/dev/null
  fi
  echo "==> ${DOC_NAME} ready."
}

create_document "Rex-RO" "${RO_POLICY}" "Run a Rhai script with read-only Cedar policy"
create_document "Rex-RW" "${RW_POLICY}" "Run a Rhai script with read-write Cedar policy"

echo ""
echo "==> Documents created."
echo ""
echo "Usage (from caller account):"
echo "  aws ssm send-command \\"
echo "    --document-name Rex-RO \\"
echo "    --targets 'Key=instanceids,Values=<instance-id>' \\"
echo "    --parameters '{\"script\":[\"let x = cat(\\\"/etc/hostname\\\"); x\"]}' \\"
echo "    --region ${REGION}"
echo ""
echo "Prerequisites on the managed instance:"
echo "  - Runner binary at: ${RUNNER_BIN}"
