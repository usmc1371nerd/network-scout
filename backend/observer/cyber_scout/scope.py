"""Dynamic scope derived from currently attached private IPv4 interfaces."""

from __future__ import annotations

import ipaddress
import json
import subprocess
from typing import Callable

Runner = Callable[[list[str]], str]


def _run(command: list[str]) -> str:
    result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=5, shell=False)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Unable to inspect network interfaces")
    return result.stdout


def current_ipv4_scopes(runner: Runner = _run) -> list[dict[str, str]]:
    rows = json.loads(runner(["ip", "-j", "address", "show"]) or "[]")
    routes = json.loads(runner(["ip", "-j", "route", "show", "default"]) or "[]")
    gateways = {str(row.get("dev")): str(row.get("gateway") or "") for row in routes if row.get("dev")}
    scopes: list[dict[str, str]] = []
    for row in rows:
        interface = str(row.get("ifname") or "")
        if not interface or interface == "lo" or "UP" not in row.get("flags", []):
            continue
        for info in row.get("addr_info", []):
            if info.get("family") != "inet" or info.get("scope") != "global":
                continue
            address = ipaddress.ip_address(str(info.get("local") or ""))
            network = ipaddress.ip_network(f"{address}/{int(info.get('prefixlen', 24))}", strict=False)
            if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
                continue
            scopes.append({
                "interface": interface,
                "address": str(address),
                "network": str(network),
                "gateway": gateways.get(interface, ""),
            })
    return scopes
