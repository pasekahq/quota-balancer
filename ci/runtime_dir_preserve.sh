#!/usr/bin/env bash
# Fails unless the effective RuntimeDirectoryPreserve in the [Service] section of the given unit is
# yes; as in systemd, the last assignment in the section wins and an empty one resets it.
# Usage: ci/runtime_dir_preserve.sh path/to/unit.service
set -euo pipefail

unit="${1:?usage: ci/runtime_dir_preserve.sh UNIT}"
value=$(awk '
  /^[[:space:]]*[#;]/ { next }
  /^[[:space:]]*\[/ { section = $0; gsub(/[[:space:]]/, "", section); next }
  section == "[Service]" && /^[[:space:]]*RuntimeDirectoryPreserve[[:space:]]*=/ {
    v = $0
    sub(/^[^=]*=[[:space:]]*/, "", v)
    sub(/[[:space:]]+$/, "", v)
    value = v
  }
  END { print value }
' "$unit")

if [ "$value" != yes ]; then
  echo "::error file=$unit::$unit: [Service] RuntimeDirectoryPreserve is ${value:-unset}, expected yes"
  exit 1
fi
echo "$unit: RuntimeDirectoryPreserve=yes"
