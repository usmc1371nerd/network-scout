#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
repository_dir=$(git -C "$project_dir" rev-parse --show-toplevel)
version=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$project_dir/manifest.json")
output_dir="${1:-$repository_dir/dist}"
archive="$output_dir/omarchy-cyber-scout-widget-$version.tar.gz"
staging_dir=$(mktemp -d)
package_dir="$staging_dir/omarchy-cyber-scout-widget-$version"
trap 'rm -rf "$staging_dir"' EXIT

mkdir -p "$output_dir"
git -C "$repository_dir" diff --quiet
git -C "$repository_dir" diff --cached --quiet
mkdir -p "$package_dir"
cp -a "$project_dir"/BarWidget.qml "$project_dir"/Panel.qml "$project_dir"/manifest.json \
  "$project_dir"/scanner.py "$project_dir"/cyber_scout "$project_dir"/OPERATIONS.md \
  "$project_dir"/SECURITY.md "$project_dir"/packaging "$package_dir"/
tar -C "$staging_dir" -czf "$archive" "omarchy-cyber-scout-widget-$version"
sha256sum "$archive" > "$archive.sha256"
echo "$archive"
