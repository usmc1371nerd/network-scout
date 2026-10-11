"""Validated local configuration with conservative defaults."""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import ipaddress
import json
import os
from pathlib import Path
import re

DEFAULT_CONFIG = Path.home() / ".config" / "cyber-scout" / "config.json"
INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


@dataclass(frozen=True, slots=True)
class CyberScoutConfig:
    interface: str = "auto"
    passive_interval_seconds: int = 30
    active_discovery_enabled: bool = False
    approved_networks: tuple[str, ...] = ()
    active_rate_limit: int = 32
    active_timeout_seconds: int = 10
    scheduled_scan_minutes: int = 0
    retention_days: int = 90
    notify_new_devices: bool = True
    external_wan_lookup_enabled: bool = False
    zeek_log_directory: str = ""
    suricata_eve_path: str = ""

    @classmethod
    def from_mapping(cls, data: dict) -> "CyberScoutConfig":
        if not isinstance(data, dict):
            raise ValueError("Configuration root must be an object")
        known = {field.name for field in fields(cls)}
        unknown = sorted(set(data) - known)
        if unknown:
            raise ValueError("Unknown configuration keys: " + ", ".join(unknown))
        values = dict(data)
        boolean_fields = {
            "active_discovery_enabled",
            "notify_new_devices",
            "external_wan_lookup_enabled",
        }
        integer_fields = {
            "passive_interval_seconds",
            "active_rate_limit",
            "active_timeout_seconds",
            "scheduled_scan_minutes",
            "retention_days",
        }
        for name in boolean_fields:
            if name in values and type(values[name]) is not bool:
                raise ValueError(f"{name} must be a boolean")
        for name in integer_fields:
            if name in values and (type(values[name]) is not int):
                raise ValueError(f"{name} must be an integer")
        if "approved_networks" in values and not isinstance(values["approved_networks"], (list, tuple)):
            raise ValueError("approved_networks must be a list")
        for name in ("interface", "zeek_log_directory", "suricata_eve_path"):
            if name in values and not isinstance(values[name], str):
                raise ValueError(f"{name} must be a string")
        values["approved_networks"] = tuple(values.get("approved_networks", ()))
        config = cls(**values)
        config.validate()
        return config

    def validate(self) -> None:
        if self.interface != "auto" and not INTERFACE_RE.fullmatch(self.interface):
            raise ValueError("Invalid network interface name")
        if not 5 <= self.passive_interval_seconds <= 3600:
            raise ValueError("Passive interval must be between 5 and 3600 seconds")
        if not 1 <= self.active_rate_limit <= 256:
            raise ValueError("Active rate limit must be between 1 and 256")
        if not 1 <= self.active_timeout_seconds <= 60:
            raise ValueError("Active timeout must be between 1 and 60 seconds")
        if not 0 <= self.scheduled_scan_minutes <= 10080:
            raise ValueError("Scheduled scan interval must be zero or at most one week")
        if not 1 <= self.retention_days <= 3650:
            raise ValueError("Retention must be between 1 and 3650 days")
        for value in self.approved_networks:
            network = ipaddress.ip_network(value, strict=True)
            if not (network.is_private or network.is_link_local):
                raise ValueError(f"Approved scan network must be private or link-local: {network}")
        for path in (self.zeek_log_directory, self.suricata_eve_path):
            if "\x00" in path or len(path) > 4096:
                raise ValueError("Invalid monitoring path")
            if path and not Path(path).is_absolute():
                raise ValueError("Monitoring paths must be absolute")

    def allows_target(self, value: str) -> bool:
        address = ipaddress.ip_address(value)
        return any(address in ipaddress.ip_network(network) for network in self.approved_networks)

    def to_mapping(self) -> dict:
        result = asdict(self)
        result["approved_networks"] = list(self.approved_networks)
        return result


class ConfigManager:
    def __init__(self, path: Path | str = DEFAULT_CONFIG) -> None:
        self.path = Path(path)

    def load(self) -> CyberScoutConfig:
        if not self.path.exists():
            return CyberScoutConfig()
        try:
            data = json.loads(self.path.read_text())
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(f"Could not read configuration: {error}") from error
        return CyberScoutConfig.from_mapping(data)

    def save(self, config: CyberScoutConfig) -> None:
        config.validate()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            self.path.parent.chmod(0o700)
        except OSError:
            pass
        temporary = self.path.with_suffix(".tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(descriptor, "w") as stream:
                json.dump(config.to_mapping(), stream, indent=2, sort_keys=True)
                stream.write("\n")
            os.replace(temporary, self.path)
            self.path.chmod(0o600)
        except BaseException:
            try:
                temporary.unlink()
            except OSError:
                pass
            raise
