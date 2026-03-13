#!/usr/bin/env bash

set -euo pipefail

# Backward-compatible wrapper. The actual cross-platform implementation
# now lives in install_deps.sh and supports both Linux and macOS.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${SCRIPT_DIR}/install_deps.sh" "$@"
