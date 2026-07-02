#!/usr/bin/env bash
# Quick-start: run the morning scan locally.
#
# Usage:
#   GITHUB_TOKEN=ghp_xxx ./scripts/run-morning-scan.sh
#   GITHUB_TOKEN=ghp_xxx ./scripts/run-morning-scan.sh --top 20
#
# Create a fine-grained PAT at https://github.com/settings/tokens?type=beta
# with "Contents: Read-only" on all your repos.

set -euo pipefail

if [ -z "${GITHUB_TOKEN:-}" ] && [ -z "${GH_TOKEN:-}" ]; then
  echo "Error: Set GITHUB_TOKEN or GH_TOKEN to scan private repos."
  echo "Public repos can be scanned without a token (subject to rate limits)."
  echo ""
  echo "Create a token: https://github.com/settings/tokens?type=beta"
  echo "  -> Fine-grained -> Contents: Read-only -> Select repositories: All"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
node "$SCRIPT_DIR/morning-scan.js" "$@"
