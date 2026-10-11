"""Authorization gates for optional scheduled active discovery."""

from __future__ import annotations

import ipaddress

from .config import CyberScoutConfig
from .discovery import Runner, run_json, subprocess_runner


def approved_local_scan_targets(
    config: CyberScoutConfig, runner: Runner = subprocess_runner
) -> list[tuple[str, str]]:
    if not config.active_discovery_enabled or config.scheduled_scan_minutes <= 0:
        return []
    interface = config.interface
    if interface == "auto":
        routes = run_json(runner, ["ip", "-j", "route", "show", "default"])
        interface = str(routes[0].get("dev") or "") if routes else ""
    if not interface:
        return []
    rows = run_json(runner, ["ip", "-j", "address", "show", "dev", interface])
    local_addresses = []
    for row in rows:
        for info in row.get("addr_info", []):
            if info.get("family") == "inet" and info.get("scope") == "global" and info.get("local"):
                local_addresses.append(ipaddress.ip_address(info["local"]))
    targets = []
    for value in config.approved_networks:
        network = ipaddress.ip_network(value, strict=True)
        if network.version != 4 or network.num_addresses > 256:
            continue
        if any(address in network for address in local_addresses):
            targets.append((interface, str(network)))
    return targets
