#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"

usage() {
  echo "Usage: $0 --install | --remove"
  echo "This changes user systemd configuration and must be run explicitly."
}

case "${1:-}" in
  --install)
    mkdir -p "$unit_dir"
    for name in cyber-scout-monitor cyber-scout-dashboard; do
      sed "s|@PROJECT_DIR@|$project_dir|g" \
        "$project_dir/packaging/systemd/$name.service.in" > "$unit_dir/$name.service"
    done
    systemctl --user daemon-reload
    systemctl --user enable --now cyber-scout-monitor.service
    echo "Monitor enabled. The dashboard remains socket-free until opened or explicitly enabled."
    ;;
  --remove)
    systemctl --user disable --now cyber-scout-monitor.service cyber-scout-dashboard.service 2>/dev/null || true
    rm -f "$unit_dir/cyber-scout-monitor.service" "$unit_dir/cyber-scout-dashboard.service"
    systemctl --user daemon-reload
    echo "Cyber Scout user services removed. Inventory and configuration were retained."
    ;;
  *)
    usage
    exit 2
    ;;
esac
