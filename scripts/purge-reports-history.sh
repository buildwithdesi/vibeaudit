#!/usr/bin/env bash
#
# purge-reports-history.sh
#
# One-time, DESTRUCTIVE operation: permanently erase the committed morning-scan
# reports (reports/*.json and reports/*.md) from the ENTIRE git history of this
# repository, then force-push the rewritten history to the remote.
#
# Why: those reports enumerate security findings (file:line) across many repos.
# Deleting them from HEAD (done in .gitignore) does NOT remove them from history
# — anyone can still read them in old commits. This rewrite removes them for good.
#
# ─────────────────────────────────────────────────────────────────────────────
# READ THIS BEFORE RUNNING
# ─────────────────────────────────────────────────────────────────────────────
#  * This REWRITES EVERY COMMIT SHA. It is irreversible.
#  * It force-pushes over the remote's history. Coordinate first:
#      - Merge or close open PRs (they are built on the old history and will
#        need to be recreated/rebased afterwards).
#      - Temporarily disable branch protection / "require linear history" on the
#        default branch if enabled, then re-enable it after.
#      - Tell every collaborator to re-clone (their old clones keep the data and
#        can re-introduce it on their next push).
#  * The data was already PUBLIC. Forks, existing clones, and GitHub's cached
#    views may retain copies. Treat the findings as already leaked: also fix the
#    underlying issues (e.g. missing-auth) in the affected repos.
#
# Requirements: git, git-filter-repo (https://github.com/newren/git-filter-repo)
#   Install:  pip3 install git-filter-repo   (or: brew install git-filter-repo)
#
# Usage:
#   ./scripts/purge-reports-history.sh            # DRY RUN: rewrites a temp
#                                                 # mirror clone and reports the
#                                                 # result, but does NOT push.
#   ./scripts/purge-reports-history.sh --execute  # Actually force-push the
#                                                 # rewritten history to origin.
#
set -euo pipefail

REMOTE_URL="${REMOTE_URL:-https://github.com/buildwithdesi/vibeaudit}"
PURGE_PATH="reports"
WORKDIR="$(mktemp -d -t vibeaudit-purge-XXXXXX)"
MIRROR="${WORKDIR}/repo.git"
EXECUTE="no"

if [[ "${1:-}" == "--execute" ]]; then
  EXECUTE="yes"
fi

cleanup() { rm -rf "${WORKDIR}"; }
trap cleanup EXIT

if ! git filter-repo --version >/dev/null 2>&1; then
  echo "ERROR: git-filter-repo is not installed or not on PATH." >&2
  echo "       Install with: pip3 install git-filter-repo" >&2
  exit 1
fi

echo "▶ Mirror-cloning ${REMOTE_URL} ..."
git clone --mirror "${REMOTE_URL}" "${MIRROR}" >/dev/null 2>&1
cd "${MIRROR}"

BEFORE_COMMITS="$(git log --all --oneline -- "${PURGE_PATH}" | wc -l | tr -d ' ')"
BEFORE_BLOBS="$(git rev-list --all --objects | grep -c "${PURGE_PATH}/morning-scan" || true)"
echo "  before: ${BEFORE_COMMITS} commits touch ${PURGE_PATH}/, ${BEFORE_BLOBS} report blobs in history"

echo "▶ Rewriting history to drop '${PURGE_PATH}/' ..."
git filter-repo --path "${PURGE_PATH}" --invert-paths --force >/dev/null

AFTER_COMMITS="$(git log --all --oneline -- "${PURGE_PATH}" | wc -l | tr -d ' ')"
AFTER_BLOBS="$(git rev-list --all --objects | grep -c "${PURGE_PATH}/morning-scan" || true)"
echo "  after:  ${AFTER_COMMITS} commits touch ${PURGE_PATH}/, ${AFTER_BLOBS} report blobs in history"

if [[ "${AFTER_COMMITS}" != "0" || "${AFTER_BLOBS}" != "0" ]]; then
  echo "ERROR: purge did not fully remove ${PURGE_PATH}/ — aborting before push." >&2
  exit 1
fi
echo "✔ Verified: ${PURGE_PATH}/ is gone from all history in the rewritten mirror."

if [[ "${EXECUTE}" != "yes" ]]; then
  cat <<EOF

DRY RUN complete — nothing was pushed.
Rewritten mirror is intact and verified. To actually publish the purge, re-run:

    ./scripts/purge-reports-history.sh --execute

(Only after you have merged/closed open PRs and relaxed branch protection.)
EOF
  exit 0
fi

echo "▶ Force-pushing rewritten history to origin (all refs) ..."
# filter-repo removes the 'origin' remote by design; re-add it to push.
git remote add origin "${REMOTE_URL}"
git push --force --mirror origin
echo "✔ Done. History rewritten on the remote."
echo "  Reminder: re-enable branch protection, and have collaborators re-clone."
