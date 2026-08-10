#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if ! command -v lake >/dev/null 2>&1; then
  echo "error: lake is not installed; install elan and the pinned Lean toolchain" >&2
  exit 1
fi

if ! command -v node >/dev/null 2>&1; then
  echo "error: node is not installed; install Node.js 24" >&2
  exit 1
fi

lake exe cache get
lake build CCFConsistency
