"""Passive, non-probing Linux discovery adapters."""

from __future__ import annotations

import json
import ipaddress
from pathlib import Path
import socket
import subprocess
import time
from typing import Callable, Protocol

from .database import InventoryStore
from .models import ACTIVE_NEIGHBOR_STATES, Observation, normalize_mac

Runner = Callable[[list[str], int], tuple[int, str, str]]


def subprocess_runner(command: list[str], timeout: int) -> tuple[int, str, str]:
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return result.returncode, result.stdout, result.stderr
    except (OSError, subprocess.TimeoutExpired) as error:
        return 124, "", str(error)


def run_json(runner: Runner, command: list[str], timeout: int = 5) -> list[dict]:
    code, output, error = runner(command, timeout)
    if code != 0:
        raise RuntimeError(f"{' '.join(command[:3])} failed: {error.strip() or f'exit {code}'}")
    try:
        value = json.loads(output or "[]")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{' '.join(command[:3])} returned malformed JSON") from exc
    if not isinstance(value, list):
        raise RuntimeError(f"{' '.join(command[:3])} returned an unexpected JSON type")
    return value


class PassiveAdapter(Protocol):
    name: str

    def observe(self, observed_at: int) -> list[Observation]: ...


class NeighborTableAdapter:
    name = "neighbor_table"

    def __init__(self, runner: Runner = subprocess_runner) -> None:
        self.runner = runner

    @staticmethod
    def parse(rows: list[dict], observed_at: int) -> list[Observation]:
        observations: list[Observation] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            address = row.get("dst")
            interface = row.get("dev")
            mac = normalize_mac(row.get("lladdr"))
            raw_states = row.get("state", [])
            if isinstance(raw_states, str):
                states = {raw_states.upper()}
            elif isinstance(raw_states, list):
                states = {str(value).upper() for value in raw_states}
            else:
                states = set()
            if not address or not interface or not mac or states & {"FAILED", "INCOMPLETE"}:
                continue
            state = sorted(states)[0] if states else "OBSERVED"
            observations.append(
                Observation(
                    source="neighbor_table",
                    interface=str(interface),
                    address=str(address),
                    mac=mac,
                    state=state,
                    observed_at=observed_at,
                    active=bool(states & ACTIVE_NEIGHBOR_STATES),
                    metadata={"states": sorted(states), "router": bool(row.get("router"))},
                )
            )
        return observations

    def observe(self, observed_at: int) -> list[Observation]:
        return self.parse(run_json(self.runner, ["ip", "-j", "neigh", "show"]), observed_at)


class NeighborEventAdapter:
    """Parse the stable text form emitted by ``ip monitor neigh``.

    The monitor itself is started by the long-running observer. This parser is
    intentionally side-effect free and does not turn deletion/failure events
    into claims that a device is offline.
    """

    name = "neighbor_event"
    command = ["ip", "monitor", "neigh"]

    @staticmethod
    def parse_line(line: str, observed_at: int) -> Observation | None:
        fields = line.strip().split()
        if not fields or fields[0].lower() == "deleted":
            return None
        try:
            ipaddress.ip_address(fields[0])
            dev_index = fields.index("dev")
            interface = fields[dev_index + 1]
            mac_index = fields.index("lladdr")
            mac = normalize_mac(fields[mac_index + 1])
        except (ValueError, IndexError):
            return None
        if not mac or not interface:
            return None
        states = {field.upper() for field in fields if field.upper() in {
            "INCOMPLETE", "REACHABLE", "STALE", "DELAY", "PROBE", "FAILED", "NOARP", "PERMANENT"
        }}
        if states & {"INCOMPLETE", "FAILED"}:
            return None
        state = sorted(states)[0] if states else "OBSERVED"
        return Observation(
            source="neighbor_event",
            interface=interface,
            address=fields[0],
            mac=mac,
            state=state,
            observed_at=observed_at,
            active=bool(states & ACTIVE_NEIGHBOR_STATES),
            metadata={"states": sorted(states), "event": True},
        )


class LocalInterfaceAdapter:
    name = "local_interface"

    def __init__(self, runner: Runner = subprocess_runner, sys_class_net: Path = Path("/sys/class/net")) -> None:
        self.runner = runner
        self.sys_class_net = sys_class_net

    def observe(self, observed_at: int) -> list[Observation]:
        rows = run_json(self.runner, ["ip", "-j", "address", "show"])
        hostname = socket.gethostname()
        observations: list[Observation] = []
        for row in rows:
            interface = str(row.get("ifname") or "")
            if not interface or interface == "lo":
                continue
            mac = normalize_mac(row.get("address"))
            for address in row.get("addr_info", []):
                if not isinstance(address, dict) or address.get("scope") not in {"global", "link"}:
                    continue
                value = address.get("local")
                if not value:
                    continue
                observations.append(
                    Observation(
                        source="local_interface",
                        interface=interface,
                        address=str(value),
                        mac=mac,
                        hostname=hostname,
                        state="LOCAL",
                        observed_at=observed_at,
                        active=True,
                        metadata={"scope": address.get("scope"), "dynamic": bool(address.get("dynamic"))},
                    )
                )
        return observations


class PassiveDiscoveryManager:
    def __init__(
        self,
        store: InventoryStore,
        adapters: list[PassiveAdapter] | None = None,
    ) -> None:
        self.store = store
        self.adapters = adapters or [LocalInterfaceAdapter(), NeighborTableAdapter()]

    def observe_once(self, observed_at: int | None = None) -> dict:
        timestamp = int(observed_at if observed_at is not None else time.time())
        observations: list[Observation] = []
        errors: list[dict[str, str]] = []
        sources: list[str] = []
        for adapter in self.adapters:
            try:
                current = adapter.observe(timestamp)
                observations.extend(current)
                sources.append(adapter.name)
            except (OSError, RuntimeError, ValueError) as error:
                errors.append({"source": adapter.name, "error": str(error)[:256]})
        result = self.store.ingest_many(observations)
        result.update({"sources": sources, "errors": errors, "observedAt": timestamp})
        return result
