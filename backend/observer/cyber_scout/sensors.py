"""Bounded, payload-free ingestion for optional Zeek JSON and Suricata EVE logs."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
import stat
import time
from typing import Callable

from .database import InventoryStore

MAX_BYTES_PER_FILE = 2 * 1024 * 1024
MAX_LINE_BYTES = 256 * 1024
MAX_RECORDS_PER_FILE = 2000


def _number(value: object, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError, OverflowError):
        return default


def _identifier(sensor: str, record_type: str, data: dict, fields: tuple[str, ...]) -> str:
    values = [str(data.get(field, "")) for field in fields]
    if any(values):
        return ":".join((record_type, *values))[:256]
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
    return f"{record_type}:{hashlib.sha256((sensor + canonical).encode()).hexdigest()}"


def parse_zeek_json(data: dict) -> dict | None:
    """Normalize Zeek JSON without retaining packet content or application payloads."""
    if not isinstance(data, dict):
        return None
    record_type = "notice" if any(key in data for key in ("note", "msg", "sub")) else "connection"
    timestamp = _number(data.get("ts"), int(time.time()))
    source_ip = data.get("id.orig_h") or data.get("src")
    destination_ip = data.get("id.resp_h") or data.get("dst")
    source_port, destination_port = data.get("id.orig_p"), data.get("id.resp_p")
    protocol = str(data.get("proto") or "").lower()
    if record_type == "notice":
        note = str(data.get("note") or "Zeek notice")[:160]
        message = " ".join(str(data.get("msg") or note).split())[:512]
        return {
            "sensor": "zeek", "external_id": _identifier("zeek", "notice", data, ("uid", "note", "ts")),
            "record_type": "notice", "severity": "review", "summary": message,
            "observed_at": timestamp, "source_ip": source_ip, "source_port": source_port,
            "destination_ip": destination_ip, "destination_port": destination_port,
            "protocol": protocol,
            "details": {"note": note, "actions": data.get("actions"), "source": "Zeek JSON"},
        }
    if not source_ip or not destination_ip:
        return None
    service = str(data.get("service") or "unknown")[:128]
    return {
        "sensor": "zeek", "external_id": _identifier("zeek", "connection", data, ("uid",)),
        "record_type": "connection", "severity": "info",
        "summary": f"Zeek observed {protocol or 'network'} connection {source_ip} → {destination_ip}",
        "observed_at": timestamp, "source_ip": source_ip, "source_port": source_port,
        "destination_ip": destination_ip, "destination_port": destination_port,
        "protocol": protocol,
        "details": {"service": service, "connectionState": data.get("conn_state"),
                    "duration": data.get("duration"), "source": "Zeek JSON"},
    }


def parse_suricata_eve(data: dict) -> dict | None:
    """Normalize alert and flow metadata from EVE JSON; payload fields are ignored."""
    if not isinstance(data, dict) or data.get("event_type") not in {"alert", "flow"}:
        return None
    record_type = str(data["event_type"])
    timestamp_value = data.get("timestamp")
    try:
        observed_at = int(datetime.fromisoformat(
            str(timestamp_value).replace("Z", "+00:00")
        ).timestamp())
    except (TypeError, ValueError):
        observed_at = int(time.time())
    alert = data.get("alert") if isinstance(data.get("alert"), dict) else {}
    flow_id = str(data.get("flow_id") or "")
    signature_id = str(alert.get("signature_id") or alert.get("signature") or "")
    if record_type == "alert":
        severity_number = _number(alert.get("severity"), 3)
        severity = "higher" if severity_number <= 1 else "review"
        summary = " ".join(str(alert.get("signature") or "Suricata alert").split())[:512]
        external_id = _identifier("suricata", "alert", data, ("flow_id",)) + f":{signature_id}"[:128]
        details = {"signatureId": alert.get("signature_id"), "category": alert.get("category"),
                   "action": alert.get("action"), "source": "Suricata EVE"}
    else:
        severity, summary = "info", f"Suricata observed flow {data.get('src_ip')} → {data.get('dest_ip')}"
        external_id = _identifier("suricata", "flow", data, ("flow_id",))
        flow = data.get("flow") if isinstance(data.get("flow"), dict) else {}
        details = {"state": flow.get("state"), "reason": flow.get("reason"),
                   "age": flow.get("age"), "source": "Suricata EVE"}
    return {
        "sensor": "suricata", "external_id": external_id, "record_type": record_type,
        "severity": severity, "summary": summary, "observed_at": observed_at,
        "source_ip": data.get("src_ip"), "source_port": data.get("src_port"),
        "destination_ip": data.get("dest_ip"), "destination_port": data.get("dest_port"),
        "protocol": str(data.get("proto") or "").lower(), "details": details,
    }


class SensorLogIngestor:
    def __init__(self, store: InventoryStore) -> None:
        self.store = store

    def ingest_file(self, path: Path | str, sensor: str,
                    parser: Callable[[dict], dict | None]) -> dict:
        source = Path(path)
        result = {"sensor": sensor, "path": str(source), "records": 0, "duplicates": 0,
                  "ignored": 0, "parseErrors": 0, "error": None}
        try:
            metadata = source.stat()
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("Sensor path is not a regular file")
            cursor = self.store.get_sensor_cursor(str(source))
            offset = int(cursor["offset"]) if cursor and int(cursor["inode"]) == metadata.st_ino else 0
            if offset > metadata.st_size:
                offset = 0
            end = min(metadata.st_size, offset + MAX_BYTES_PER_FILE)
            with source.open("rb") as stream:
                stream.seek(offset)
                while stream.tell() < end and result["records"] + result["ignored"] < MAX_RECORDS_PER_FILE:
                    start = stream.tell()
                    line = stream.readline(MAX_LINE_BYTES + 1)
                    if not line:
                        break
                    if len(line) > MAX_LINE_BYTES:
                        result["parseErrors"] += 1
                        continue
                    if not line.endswith(b"\n") and stream.tell() >= metadata.st_size:
                        stream.seek(start)
                        break
                    try:
                        data = json.loads(line)
                        finding = parser(data)
                        if finding is None:
                            result["ignored"] += 1
                            continue
                        stored = self.store.record_sensor_finding(finding)
                        result["duplicates"] += int(stored["occurrences"] > 1)
                        result["records"] += 1
                    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
                        result["parseErrors"] += 1
                final_offset = stream.tell()
            self.store.update_sensor_cursor(
                str(source), sensor, metadata.st_ino, final_offset,
                records_read=result["records"], parse_errors=result["parseErrors"],
            )
        except (OSError, ValueError) as error:
            result["error"] = str(error)[:512]
            previous = self.store.get_sensor_cursor(str(source))
            inode = int(previous["inode"]) if previous else 0
            offset = int(previous["offset"]) if previous else 0
            self.store.update_sensor_cursor(str(source), sensor, inode, offset, error=result["error"])
        return result

    def ingest_configured(self, config) -> dict:
        results = []
        if config.zeek_log_directory:
            directory = Path(config.zeek_log_directory)
            for filename in ("conn.log", "notice.log"):
                results.append(self.ingest_file(directory / filename, "zeek", parse_zeek_json))
        if config.suricata_eve_path:
            results.append(self.ingest_file(config.suricata_eve_path, "suricata", parse_suricata_eve))
        return {
            "enabled": bool(config.zeek_log_directory or config.suricata_eve_path),
            "sources": results,
            "visibility": "This host sees only traffic delivered to its sensor interface; full-LAN visibility requires a mirror port, network tap, or gateway sensor.",
            "packetPayloadStored": False,
        }
