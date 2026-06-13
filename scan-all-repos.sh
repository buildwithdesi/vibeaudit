#!/bin/bash
# Vibe Audit — Multi-Repo Scanner
# Scans all accessible jackdog668 public repos

SCAN_DIR="/tmp/vibeaudit-scan"
RESULTS_DIR="/home/user/vibeaudit/scan-results"
VIBE_AUDIT="/home/user/vibeaudit/bin/vibe-audit.js"

mkdir -p "$SCAN_DIR" "$RESULTS_DIR"

REPOS=(
  "vibeaudit"
  "percolator-class-guide"
  "da-video-tool"
  "Siftly"
  "photo-organizer-da"
  "sierrabakerconsulting"
  "vibe-tracker"
  "a-silly-idea"
  "second-brain-system"
  "myfirstdeploy"
  "vibe-vocab"
)

echo "========================================="
echo "  VIBE AUDIT — MULTI-REPO SCAN"
echo "  Date: $(date '+%Y-%m-%d %H:%M')"
echo "  Repos: ${#REPOS[@]} public"
echo "========================================="
echo ""

for repo in "${REPOS[@]}"; do
  echo "--- Scanning: $repo ---"

  # Clone (shallow, quiet)
  repo_dir="$SCAN_DIR/$repo"
  if [ ! -d "$repo_dir" ]; then
    git clone --depth 1 --quiet "https://github.com/jackdog668/$repo.git" "$repo_dir" 2>/dev/null
    if [ $? -ne 0 ]; then
      echo "  SKIP: clone failed"
      echo "{\"repo\":\"$repo\",\"error\":\"clone failed\",\"findings\":[]}" > "$RESULTS_DIR/$repo.json"
      continue
    fi
  fi

  # Run vibeaudit with JSON output
  node "$VIBE_AUDIT" "$repo_dir" --format json --skip-sca 2>/dev/null > "$RESULTS_DIR/$repo.json"

  # Quick summary
  findings=$(node -e "
    const fs = require('fs');
    try {
      const d = JSON.parse(fs.readFileSync('$RESULTS_DIR/$repo.json','utf8'));
      const f = d.findings || d || [];
      const crit = f.filter(x=>x.severity==='critical').length;
      const high = f.filter(x=>x.severity==='high').length;
      const med = f.filter(x=>x.severity==='medium').length;
      const warn = f.filter(x=>x.severity==='warning').length;
      console.log(JSON.stringify({total:f.length,critical:crit,high:high,medium:med,warning:warn}));
    } catch(e) { console.log('{\"total\":0,\"critical\":0,\"high\":0,\"medium\":0,\"warning\":0}'); }
  " 2>/dev/null)

  echo "  $findings"
  echo ""
done

echo "========================================="
echo "  SCAN COMPLETE"
echo "========================================="
