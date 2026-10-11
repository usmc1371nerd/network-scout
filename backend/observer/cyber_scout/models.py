"""Typed observations and validation helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import re
import time
from typing import Any

MAC_RE = re.compile(r"^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$")
ACTIVE_NEIGHBOR_STATES = frozenset({"REACHABLE", "DELAY", "PROBE", "PERMANENT", "NOARP"})


def normalize_mac(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.strip().replace("-", ":").upper()
    if not MAC_RE.fullmatch(candidate) or candidate in {
        "00:00:00:00:00:00",
        "FF:FF:FF:FF:FF:FF",
    }:
        return None
    return candidate


def is_locally_administered(mac: str | None) -> bool:
    normalized = normalize_mac(mac)
    return bool(normalized and (int(normalized[:2], 16) & 0x02))


def normalize_hostname(value: str | None) -> str | None:
    if not value:
        return None
    candidate = " ".join(str(value).split()).rstrip(".")
    if not candidate or len(candidate) > 253 or any(not c.isprintable() for c in candidate):
        return None
    return candidate


@dataclass(frozen=True, slots=True)
class Observation:
    source: str
    interface: str
    address: str | None = None
    mac: str | None = None
    hostname: str | None = None
    state: str = "OBSERVED"
    observed_at: int = field(default_factory=lambda: int(time.time()))
    active: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.source or len(self.source) > 64:
            raise ValueError("Observation source is required and must be at most 64 characters")
        if not self.interface or len(self.interface) > 64:
            raise ValueError("Observation interface is required and must be at most 64 characters")
        if self.address is not None:
            object.__setattr__(self, "address", str(ipaddress.ip_address(self.address)))
        object.__setattr__(self, "mac", normalize_mac(self.mac))
        object.__setattr__(self, "hostname", normalize_hostname(self.hostname))
        state = str(self.state or "OBSERVED").upper()
        object.__setattr__(self, "state", state[:32])
        if self.observed_at < 0:
            raise ValueError("Observation timestamp cannot be negative")

    @property
    def family(self) -> int | None:
        if self.address is None:
            return None
        return ipaddress.ip_address(self.address).version
