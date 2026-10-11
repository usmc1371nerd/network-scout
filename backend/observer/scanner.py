#!/usr/bin/env python3
"""Quiet LAN inventory plus explicit, bounded reconnaissance actions."""

from __future__ import annotations

import ipaddress
import json
import os
import pathlib
import re
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import quote

from cyber_scout import InventoryStore, PassiveDiscoveryManager
from cyber_scout.diagnostics import explain_open_port, summarize_findings
from cyber_scout.scope import current_ipv4_scopes
from cyber_scout.config import ConfigManager
from cyber_scout.security import load_or_create_session_secret

CACHE = pathlib.Path.home() / ".cache" / "omarchy-lan-devices.json"
WAN_CACHE = pathlib.Path.home() / ".cache" / "omarchy-lan-wan.json"
NAMES = pathlib.Path.home() / ".local" / "share" / "omarchy-lan-devices" / "names.json"
OUI_FILES = (pathlib.Path("/usr/share/hwdata/oui.txt"), pathlib.Path("/usr/share/nmap/nmap-mac-prefixes"))
SAFETY_PORTS = {
    21: ("FTP", "higher"),
    22: ("SSH", "review"),
    23: ("Telnet", "higher"),
    25: ("SMTP", "review"),
    53: ("DNS", "review"),
    80: ("HTTP", "review"),
    111: ("RPC", "higher"),
    135: ("MS RPC", "higher"),
    139: ("NetBIOS", "higher"),
    443: ("HTTPS", "review"),
    445: ("SMB", "higher"),
    554: ("RTSP", "review"),
    631: ("Printing", "review"),
    1433: ("SQL Server", "higher"),
    3306: ("MySQL", "higher"),
    3389: ("Remote Desktop", "higher"),
    5432: ("PostgreSQL", "higher"),
    5900: ("VNC", "higher"),
    8080: ("HTTP alternate", "review"),
    8443: ("HTTPS alternate", "review"),
}


def run(*args: str, timeout: int = 12) -> tuple[int, str]:
    try:
        result = subprocess.run(args, check=False, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout
    except (OSError, subprocess.TimeoutExpired):
        return 124, ""


def active_network() -> tuple[str, ipaddress.IPv4Network, str, str] | None:
    _, raw = run("ip", "-j", "route", "show", "default")
    routes = json.loads(raw or "[]")
    if not routes:
        return None
    interface, gateway = routes[0].get("dev", ""), routes[0].get("gateway", "")
    _, raw = run("ip", "-j", "address", "show", "dev", interface)
    for item in json.loads(raw or "[]"):
        for info in item.get("addr_info", []):
            if info.get("family") == "inet" and info.get("scope") == "global":
                local = info.get("local", "")
                network = ipaddress.ip_network(f"{local}/{int(info.get('prefixlen', 24))}", strict=False)
                if network.num_addresses > 256:
                    network = ipaddress.ip_network(f"{local}/24", strict=False)
                return interface, network, local, gateway
    return None


def checked_target(value: str, network: ipaddress.IPv4Network) -> str:
    address = ipaddress.ip_address(value)
    if not isinstance(address, ipaddress.IPv4Address) or address not in network:
        raise ValueError("Target is outside the active local network")
    return str(address)


def vendors() -> dict[str, str]:
    result: dict[str, str] = {}
    for path in OUI_FILES:
        if not path.exists():
            continue
        try:
            for line in path.read_text(errors="ignore").splitlines():
                match = re.match(r"^([0-9A-Fa-f]{6})\s+(?:\(base 16\)\s+)?(.+)$", line)
                if match:
                    result[match.group(1).upper()] = match.group(2).strip()
        except OSError:
            pass
        if result:
            break
    return result


def neighbor_table(interface: str) -> dict[str, str]:
    _, output = run("ip", "neigh", "show", "dev", interface)
    table: dict[str, str] = {}
    for line in output.splitlines():
        parts = line.split()
        if parts and "lladdr" in parts and not any(x in parts for x in ("FAILED", "INCOMPLETE")):
            try:
                table[str(ipaddress.ip_address(parts[0]))] = parts[parts.index("lladdr") + 1].upper()
            except (ValueError, IndexError):
                pass
    return table


def names_from_nmap(output: str) -> dict[str, str]:
    names: dict[str, str] = {}
    for line in output.splitlines():
        if line.startswith("Nmap scan report for "):
            value = line.removeprefix("Nmap scan report for ").strip()
            match = re.match(r"(.+) \(([0-9.]+)\)$", value)
            names[match.group(2) if match else value] = match.group(1) if match else ""
    return names


def custom_names() -> dict[str, dict[str, str]]:
    try:
        data = json.loads(NAMES.read_text())
        return {
            "mac": {str(key).upper(): str(value) for key, value in data.get("mac", {}).items()},
            "ip": {str(key): str(value) for key, value in data.get("ip", {}).items()},
        }
    except (OSError, json.JSONDecodeError, AttributeError):
        return {"mac": {}, "ip": {}}


def write_custom_names(data: dict[str, dict[str, str]]) -> None:
    NAMES.parent.mkdir(parents=True, exist_ok=True)
    temporary = NAMES.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, NAMES)


def network_signature(scopes: list[dict[str, str]]) -> str:
    return "|".join(sorted(
        f"{item.get('interface','')}:{item.get('network','')}:{item.get('gateway','')}"
        for item in scopes
    ))


def cached_wan(signature: str = "", max_age: int = 900) -> dict:
    try:
        data = json.loads(WAN_CACHE.read_text())
        if not isinstance(data, dict):
            return {}
        fresh = int(data.get("checkedAt") or 0) >= int(time.time()) - max_age
        same_network = not signature or data.get("networkSignature") == signature
        if data.get("publicIp") and fresh and same_network:
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def fetch_wan(signature: str = "") -> dict:
    request = urllib.request.Request(
        "https://ipwho.is/?fields=success,message,ip,connection",
        headers={"User-Agent": "Omarchy-LAN-Devices/1.2"},
    )
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            data = json.loads(response.read(262144).decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, urllib.error.URLError) as error:
        raise ValueError(f"WAN lookup failed: {error}") from error
    if not data.get("success", False):
        raise ValueError(data.get("message") or "WAN lookup failed")
    address = str(ipaddress.ip_address(data.get("ip", "")))
    connection = data.get("connection") or {}
    isp = str(connection.get("isp") or connection.get("org") or "Unknown ISP").strip()
    result = {
        "publicIp": address,
        "isp": isp,
        "asn": int(connection.get("asn") or 0),
        "checkedAt": int(time.time()),
        "networkSignature": signature,
    }
    WAN_CACHE.parent.mkdir(parents=True, exist_ok=True)
    temporary = WAN_CACHE.with_suffix(".tmp")
    temporary.write_text(json.dumps(result, separators=(",", ":")))
    os.replace(temporary, WAN_CACHE)
    return {"action": "wan", "ok": True, "result": f"{address} • {isp}", "wan": result}


def current_wan(scopes: list[dict[str, str]]) -> dict:
    signature = network_signature(scopes)
    cached = cached_wan(signature)
    if cached:
        return cached
    try:
        return fetch_wan(signature)["wan"]
    except ValueError:
        # Never show a prior network's ISP as though it were current.
        return {}


def clean_name(value: str) -> str:
    name = " ".join(value.split())
    if not name:
        raise ValueError("Device name cannot be empty")
    if len(name) > 64:
        raise ValueError("Device name must be 64 characters or fewer")
    if any(not character.isprintable() for character in name):
        raise ValueError("Device name contains unsupported characters")
    return name


def device_type(name: str, vendor: str, gateway: bool) -> str:
    if gateway:
        return "Router"
    text = f"{name} {vendor}".lower()
    rules = (
        (("iphone", "ipad", "android", "pixel", "samsung"), "Phone / tablet"),
        (("roku", "chromecast", "fire tv", "smart tv", "sonos"), "Media / TV"),
        (("printer", "brother", "epson", "xerox", "hewlett"), "Printer"),
        (("raspberry", "espressif", "tuya", "nest", "ring"), "Smart device"),
        (("macbook", "laptop", "desktop", "intel", "dell", "lenovo"), "Computer"),
        (("apple",), "Apple device"), (("google",), "Google device"),
    )
    for needles, label in rules:
        if any(needle in text for needle in needles):
            return label
    return "Device"


def inventory(active: tuple[str, ipaddress.IPv4Network, str, str], discover: bool) -> dict:
    interface, network, local_ip, gateway = active
    try:
        scopes = current_ipv4_scopes()
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError):
        scopes = [{"interface": interface, "network": str(network), "address": local_ip, "gateway": gateway}]
    cached: dict = {}
    if CACHE.exists():
        try:
            cached = json.loads(CACHE.read_text())
        except (OSError, json.JSONDecodeError):
            pass
    old = {d["ip"]: d for d in cached.get("devices", [])}
    # The cache enriches currently observed rows; it must never resurrect rows
    # from a network that is no longer attached.
    live: dict[str, str] = {}
    if discover:
        _, output = run("nmap", "-sn", "-n", str(network), timeout=25)
        live = names_from_nmap(output)
    neighbors: dict[str, str] = {}
    address_interfaces: dict[str, str] = {}
    local_ips = {item["address"] for item in scopes}
    gateways = {item["gateway"] for item in scopes if item.get("gateway")}
    for scope in scopes:
        for address, mac in neighbor_table(scope["interface"]).items():
            parsed = ipaddress.ip_address(address)
            if isinstance(parsed, ipaddress.IPv4Address) and parsed in ipaddress.ip_network(scope["network"]):
                neighbors[address] = mac
                address_interfaces[address] = scope["interface"]
    if not discover:
        for address in neighbors:
            prior = old.get(address, {})
            live.setdefault(address, prior.get("detectedName", prior.get("name", "")))
    for scope in scopes:
        live[scope["address"]] = socket.gethostname()
        address_interfaces[scope["address"]] = scope["interface"]
        if scope.get("gateway"):
            live.setdefault(scope["gateway"], "Gateway")
            address_interfaces[scope["gateway"]] = scope["interface"]
    vendor_map, aliases, devices, now = vendors(), custom_names(), [], int(time.time())
    for address in sorted(live, key=ipaddress.ip_address):
        prior = old.get(address, {})
        mac = neighbors.get(address, prior.get("mac", ""))
        is_local = address in local_ips
        if is_local and (not mac or mac == "Unavailable"):
            try:
                device_interface = address_interfaces.get(address, interface)
                mac = pathlib.Path(f"/sys/class/net/{device_interface}/address").read_text().strip().upper()
            except OSError:
                mac = ""
        vendor = vendor_map.get(mac.replace(":", "")[:6], "") if mac else ""
        detected_name = live[address] or prior.get("detectedName", prior.get("name", ""))
        is_gateway = address in gateways
        custom_name = aliases["mac"].get(mac.upper(), "") if mac and mac != "Unavailable" else ""
        custom_name = custom_name or aliases["ip"].get(address, "")
        name = custom_name or detected_name or ("Gateway" if is_gateway else "Unknown device")
        devices.append({
            "ip": address, "mac": mac or "Unavailable",
            "name": name, "detectedName": detected_name,
            "customName": custom_name, "hasCustomName": bool(custom_name),
            "vendor": vendor or prior.get("vendor", "Unknown vendor"),
            "type": device_type(detected_name, vendor or prior.get("vendor", ""), is_gateway),
            "self": is_local, "gateway": is_gateway,
            "lastSeen": now if discover or address in neighbors or is_local else prior.get("lastSeen", 0),
        })
    result = {
        "interface": interface,
        "network": ", ".join(item["network"] for item in scopes),
        "devices": devices,
        "wan": current_wan(scopes) if ConfigManager().load().external_wan_lookup_enabled else {},
        "mode": "discover" if discover else "passive",
    }
    try:
        with InventoryStore() as store:
            result["storage"] = PassiveDiscoveryManager(store).observe_once(now)
            for device in devices:
                category = "Router" if device.get("gateway") else ("Computer" if device.get("self") else None)
                store.enrich_device_by_mac(
                    device.get("mac", ""),
                    user_name=device.get("customName") or None,
                    manufacturer=device.get("vendor") or None,
                    category=category,
                )
                stored = store.get_device_by_mac(device.get("mac", ""))
                if stored:
                    device.update({
                        "deviceId": stored["id"],
                        "recognition": stored["recognition"],
                        "category": stored["category"],
                        "notes": stored["notes"],
                        "firstObserved": stored["first_observed"],
                        "lastObserved": stored["last_observed"],
                        "lastActive": stored["last_active"],
                        "identificationConfidence": stored["identification_confidence"],
                        "randomizedMac": bool(stored["randomized_mac"]),
                    })
            result["counts"] = store.counts_for_networks([item["network"] for item in scopes], now)
    except (OSError, RuntimeError, sqlite3.Error, ValueError) as error:
        # The compatibility widget remains usable if the history foundation is
        # temporarily unavailable. The error is returned for visible status
        # and diagnostics rather than discarded.
        result["storage"] = {"errors": [{"source": "inventory", "error": str(error)[:256]}]}
    if discover:
        CACHE.parent.mkdir(parents=True, exist_ok=True)
        temporary = CACHE.with_suffix(".tmp")
        temporary.write_text(json.dumps(result, separators=(",", ":")))
        os.replace(temporary, CACHE)
    return result


def set_custom_name(active: tuple[str, ipaddress.IPv4Network, str, str], target: str, value: str | None) -> dict:
    interface, network, _, _ = active
    address = checked_target(target, network)
    cached: dict = {}
    try:
        cached = json.loads(CACHE.read_text())
    except (OSError, json.JSONDecodeError):
        pass
    prior = next((device for device in cached.get("devices", []) if device.get("ip") == address), {})
    mac = neighbor_table(interface).get(address, prior.get("mac", ""))
    aliases = custom_names()
    bucket, key = ("mac", mac.upper()) if mac and mac != "Unavailable" else ("ip", address)
    if value is None:
        aliases[bucket].pop(key, None)
        # Remove a legacy IP fallback after the MAC becomes available.
        aliases["ip"].pop(address, None)
        result = "Custom name removed"
    else:
        name = clean_name(value)
        aliases[bucket][key] = name
        if bucket == "mac":
            aliases["ip"].pop(address, None)
        result = f"Saved as {name}"
    write_custom_names(aliases)
    if mac and mac != "Unavailable":
        with InventoryStore() as store:
            stored = store.get_device_by_mac(mac)
            if stored:
                store.update_device(stored["id"], user_name=value or "")
    return {"action": "name", "ip": address, "ok": True, "result": result}


def set_recognition(device_id: str, state: str) -> dict:
    if state not in {"recognized", "unrecognized", "ignored"}:
        raise ValueError("Invalid recognition state")
    with InventoryStore() as store:
        device = store.update_device(device_id, recognition=state)
    labels = {"recognized": "Device recognized", "unrecognized": "Device marked unrecognized", "ignored": "Device ignored"}
    return {"action": "recognition", "deviceId": device_id, "ok": True, "result": labels[state], "recognition": state}


def set_device_metadata(device_id: str, field: str, value: str) -> dict:
    allowed = {"category", "notes"}
    if field not in allowed:
        raise ValueError("Invalid device field")
    with InventoryStore() as store:
        device = store.update_device(device_id, **{field: value})
    label = "Device category updated" if field == "category" else "Device note saved"
    return {"action": "metadata", "deviceId": device_id, "ok": True, "result": label, field: device[field]}


def launch_diagnostic_worker() -> None:
    subprocess.Popen(
        [sys.executable, "-B", "-m", "cyber_scout.jobs", "worker"],
        cwd=pathlib.Path(__file__).parent,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
    )


def queue_diagnostic(
    active: tuple[str, ipaddress.IPv4Network, str, str], device_id: str, kind: str, target: str
) -> dict:
    address = checked_target(target, active[1])
    with InventoryStore() as store:
        job = store.queue_diagnostic(device_id, address, kind)
    launch_diagnostic_worker()
    return {"action": "diagnostic", "ok": True, "job": job}


def diagnostic_status(job_id: str) -> dict:
    with InventoryStore() as store:
        return {"action": "diagnostic-status", "ok": True, "job": store.get_diagnostic_job(job_id)}


def cancel_diagnostic(job_id: str) -> dict:
    with InventoryStore() as store:
        job = store.request_diagnostic_cancel(job_id)
    return {"action": "diagnostic-cancel", "ok": True, "job": job, "result": "Cancellation requested"}


def queue_scan(active: tuple[str, ipaddress.IPv4Network, str, str]) -> dict:
    interface, network, _, _ = active
    with InventoryStore() as store:
        job = store.queue_scan(str(network), interface, trigger="manual")
    launch_diagnostic_worker()
    return {"action": "scan", "ok": True, "job": job}


def scan_status(job_id: str) -> dict:
    with InventoryStore() as store:
        return {"action": "scan-status", "ok": True, "job": store.get_scan_job(job_id)}


def cancel_scan(job_id: str) -> dict:
    with InventoryStore() as store:
        job = store.request_scan_cancel(job_id)
    return {"action": "scan-cancel", "ok": True, "job": job, "result": "Cancellation requested"}


def safety_port_result(output: str) -> tuple[str, list[dict]]:
    found: list[dict] = []
    for match in re.finditer(r"^(\d+)/tcp\s+open\s+", output, re.M):
        port = int(match.group(1))
        if port in SAFETY_PORTS:
            service, level = SAFETY_PORTS[port]
            found.append(explain_open_port(port, service, level))
    return summarize_findings(found), found


def persist_services(address: str, ports: list[dict], source: str) -> None:
    if not ports:
        return
    normalized = []
    for item in ports:
        technical = item.get("technicalDetails", item)
        normalized.append({
            "port": technical["port"], "protocol": technical.get("protocol", "tcp"),
            "service": technical.get("service", "unknown"),
        })
    with InventoryStore() as store:
        store.record_services_for_address(address, normalized, source=source)


def action(active: tuple[str, ipaddress.IPv4Network, str, str], kind: str, target: str) -> dict:
    interface, network, _, _ = active
    address = checked_target(target, network)
    if kind == "ping":
        code, output = run("ping", "-n", "-c", "4", "-W", "1", address, timeout=7)
        summary = re.search(r"(\d+) packets transmitted, (\d+) received.*?(\d+(?:\.\d+)?)% packet loss", output)
        timing = re.search(r"= [\d.]+/([\d.]+)/[\d.]+/[\d.]+ ms", output)
        text = f"The device answered {summary.group(2)} of {summary.group(1)} connectivity checks with {summary.group(3)}% packet loss." if summary else "The device did not answer the connectivity test. Some devices block these requests, so this does not necessarily mean the device is disconnected."
        if timing:
            text += f" • {timing.group(1)} ms avg"
        return {"action": kind, "ip": address, "ok": code == 0, "result": text}
    if kind == "identify":
        mac = neighbor_table(interface).get(address, "Unavailable")
        vendor = vendors().get(mac.replace(":", "")[:6], "Unknown vendor") if mac != "Unavailable" else "Unknown vendor"
        _, mdns = run("avahi-resolve-address", address, timeout=3)
        hostname = mdns.strip().split("\t")[-1] if mdns.strip() else "No mDNS name"
        return {"action": kind, "ip": address, "ok": True, "result": f"{hostname} • {vendor} • {mac}"}
    if kind == "services":
        code, output = run("nmap", "-sT", "-n", "--top-ports", "20", "--host-timeout", "8s", address, timeout=11)
        if code != 0:
            return {"action": kind, "ip": address, "ok": False, "error": "Service identification timed out or failed; no conclusion was recorded."}
        ports = [{"port": int(m.group(1)), "protocol": m.group(2), "service": "unknown"} for m in re.finditer(r"^(\d+)/(tcp|udp)\s+open\s+", output, re.M)]
        persist_services(address, ports, "nmap_top_ports")
        text = "Reachable services: " + ", ".join(f"{item['port']}/{item['protocol']}" for item in ports) if ports else "No common TCP services accepted a connection. Filtering or timeout can hide a service, so this is not proof that none exist."
        return {"action": kind, "ip": address, "ok": True, "result": text, "ports": ports}
    if kind == "exposure":
        selected = ",".join(str(port) for port in SAFETY_PORTS)
        code, output = run(
            "nmap", "-sT", "-Pn", "-n", "--max-retries", "1",
            "--host-timeout", "10s", "-p", selected, address, timeout=13,
        )
        text, ports = safety_port_result(output)
        if code not in (0,):
            return {"action": kind, "ip": address, "ok": False, "error": "Safety port check timed out or failed"}
        persist_services(address, ports, "safety_port_check")
        return {"action": kind, "ip": address, "ok": True, "result": text, "ports": ports}
    raise ValueError("Unsupported action")


def main() -> int:
    try:
        mode = sys.argv[1] if len(sys.argv) > 1 else "passive"
        if mode == "dashboard" and len(sys.argv) == 2:
            probe = socket.socket()
            try:
                probe.settimeout(0.2)
                running = probe.connect_ex(("127.0.0.1", 8765)) == 0
            finally:
                probe.close()
            if not running:
                subprocess.Popen(
                    [sys.executable, "-B", "-m", "cyber_scout.dashboard"],
                    cwd=pathlib.Path(__file__).parent,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                deadline = time.monotonic() + 3.0
                while time.monotonic() < deadline:
                    time.sleep(0.1)
                    check = socket.socket()
                    try:
                        check.settimeout(0.2)
                        if check.connect_ex(("127.0.0.1", 8765)) == 0:
                            running = True
                            break
                    finally:
                        check.close()
            if not running:
                raise OSError("Dashboard server did not start")
            token = load_or_create_session_secret()
            subprocess.Popen(
                ["xdg-open", f"http://127.0.0.1:8765/#session={quote(token, safe='')}"],
                start_new_session=True,
            )
            print(json.dumps({"action": "dashboard", "ok": True}))
            return 0
        if mode == "wan" and len(sys.argv) == 2:
            try:
                scopes = current_ipv4_scopes()
            except (OSError, RuntimeError, ValueError, json.JSONDecodeError):
                scopes = []
            result = fetch_wan(network_signature(scopes))
            print(json.dumps(result, separators=(",", ":")))
            return 0
        if mode == "recognition" and len(sys.argv) == 4:
            result = set_recognition(sys.argv[2], sys.argv[3])
            print(json.dumps(result, separators=(",", ":")))
            return 0
        if mode == "metadata" and len(sys.argv) == 5:
            result = set_device_metadata(sys.argv[2], sys.argv[3], sys.argv[4])
            print(json.dumps(result, separators=(",", ":")))
            return 0
        if mode == "diagnostic-status" and len(sys.argv) == 3:
            result = diagnostic_status(sys.argv[2])
            print(json.dumps(result, separators=(",", ":")))
            return 0
        if mode == "diagnostic-cancel" and len(sys.argv) == 3:
            result = cancel_diagnostic(sys.argv[2])
            print(json.dumps(result, separators=(",", ":")))
            return 0
        if mode == "scan-status" and len(sys.argv) == 3:
            result = scan_status(sys.argv[2])
            print(json.dumps(result, separators=(",", ":")))
            return 0
        if mode == "scan-cancel" and len(sys.argv) == 3:
            result = cancel_scan(sys.argv[2])
            print(json.dumps(result, separators=(",", ":")))
            return 0

        active = active_network()
        if not active:
            print(json.dumps({"error": "No active IPv4 network", "devices": []}))
            return 1
        if mode in ("passive", "discover"):
            result = inventory(active, mode == "discover")
        elif mode == "scan-start" and len(sys.argv) == 2:
            result = queue_scan(active)
        elif mode == "diagnostic-start" and len(sys.argv) == 5:
            result = queue_diagnostic(active, sys.argv[2], sys.argv[3], sys.argv[4])
        elif mode in ("ping", "identify", "services", "exposure") and len(sys.argv) == 3:
            result = action(active, mode, sys.argv[2])
        elif mode == "name" and len(sys.argv) == 4:
            result = set_custom_name(active, sys.argv[2], sys.argv[3])
        elif mode == "unname" and len(sys.argv) == 3:
            result = set_custom_name(active, sys.argv[2], None)
        else:
            raise ValueError("Invalid command")
        print(json.dumps(result, separators=(",", ":")))
        return 0
    except (KeyError, OSError, sqlite3.Error, ValueError) as error:
        print(json.dumps({"error": str(error)}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
