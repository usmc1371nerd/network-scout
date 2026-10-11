"""Loopback-only Cyber Scout dashboard with narrowly validated local writes."""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import sqlite3
import time
from urllib.parse import parse_qs, urlsplit

from .database import DEFAULT_DATABASE, InventoryStore
from .api_v1 import ApiValidationError, inventory_devices
from .config import DEFAULT_CONFIG, ConfigManager, CyberScoutConfig
from .runtime import runtime_logger
from .scope import current_ipv4_scopes
from .security import allowed_authority, allowed_origin, load_or_create_session_secret, token_matches

HOST = "127.0.0.1"
PORT = 8765
ASSET = Path(__file__).with_name("dashboard.html")


PERIODS = {"24h": 86400, "7d": 604800, "30d": 2592000}


def dashboard_snapshot(store: InventoryStore, now: int | None = None, networks: list[str] | None = None,
                       period: str = "24h", include_history: bool = False) -> dict:
    timestamp = int(now if now is not None else time.time())
    active_networks = networks if networks is not None else [item["network"] for item in current_ipv4_scopes()]
    network_filter = None if include_history else active_networks
    visible_ids = {item["id"] for item in store.list_devices(networks=network_filter, limit=1000)}
    changes: dict[str, int] = {}
    seconds = PERIODS.get(period)
    if seconds is None:
        raise ValueError("Invalid change period")
    for event in store.list_events(since=timestamp - seconds, until=timestamp, limit=1000):
        if event.get("device_id") not in visible_ids:
            continue
        changes[event["event_type"]] = changes.get(event["event_type"], 0) + 1
    return {
        "generatedAt": timestamp,
        "networks": active_networks,
        "counts": (store.counts_for_networks(active_networks, timestamp) if not include_history else {
            "total": len(visible_ids),
            "recently_active": sum((item["last_active"] or 0) >= timestamp - 900
                                   for item in store.list_devices(limit=1000)),
            "new_24h": sum(item["first_observed"] >= timestamp - 86400
                           for item in store.list_devices(limit=1000)),
            "unrecognized": sum(item["recognition"] == "unrecognized"
                                for item in store.list_devices(limit=1000)),
        }),
        "period": period,
        "changes": changes,
        "changes24h": changes if period == "24h" else {},
    }


def _device_rows(store: InventoryStore, query: dict[str, list[str]], networks: list[str]) -> list[dict]:
    devices = store.list_devices(
        search=query.get("search", [""])[0],
        recognition=query.get("recognition", [None])[0],
        category=query.get("category", [None])[0],
        limit=int(query.get("limit", ["250"])[0]),
        networks=networks,
    )
    for device in devices:
        details = store.get_device(device["id"])
        device["addresses"] = details["addresses"]
        device["hostnames"] = details["hostnames"]
    return devices


def make_handler(database: Path | str = DEFAULT_DATABASE,
                 config_path: Path | str = DEFAULT_CONFIG, *, port: int = PORT,
                 session_token: str | None = None) -> type[BaseHTTPRequestHandler]:
    csrf_token = session_token or load_or_create_session_secret()
    logger = runtime_logger("dashboard")

    class DashboardHandler(BaseHTTPRequestHandler):
        server_version = "CyberScout/1"

        def _headers(self, status: int, content_type: str, *, length: int | None = None,
                     download: str | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
            if length is not None:
                self.send_header("Content-Length", str(length))
            if download:
                self.send_header("Content-Disposition", f'attachment; filename="{download}"')
            self.end_headers()

        def _json(self, value: object, status: int = 200, *, download: str | None = None) -> None:
            body = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
            self._headers(status, "application/json; charset=utf-8", length=len(body), download=download)
            self.wfile.write(body)

        def _scope(self, query: dict[str, list[str]]) -> tuple[str, list[str] | None]:
            scope = query.get("scope", ["current"])[0]
            if scope not in {"current", "history"}:
                raise ValueError("Invalid inventory scope")
            networks = [item["network"] for item in current_ipv4_scopes()]
            return scope, networks if scope == "current" else None

        def _valid_host(self) -> bool:
            return allowed_authority(self.headers.get("Host"), self.server.server_port)

        def _authenticated(self) -> bool:
            return token_matches(self.headers.get("X-Cyber-Scout-Token"), csrf_token)

        def _authenticated_v1(self) -> bool:
            return token_matches(self.headers.get("X-Network-Scout-Token"), csrf_token)

        def _api_error(self, status: int, code: str, message: str, *, field: str | None = None) -> None:
            error = {"code": code, "message": message, "requestId": secrets.token_hex(8)}
            if field:
                error["fields"] = [{"path": field, "code": code}]
            self._json({"error": error}, status)

        def _visible_ids(self, store: InventoryStore, networks: list[str] | None) -> set[str]:
            return {item["id"] for item in store.list_devices(networks=networks, limit=1000)}

        def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
            request = urlsplit(self.path)
            try:
                if not self._valid_host():
                    if request.path.startswith("/api/v1/"):
                        self._api_error(421, "invalid_authority", "The request authority is not allowed.")
                    else:
                        self._json({"error": "Invalid request authority"}, 421)
                    return
                if request.path in {"/", "/index.html"}:
                    body = ASSET.read_bytes()
                    self._headers(200, "text/html; charset=utf-8", length=len(body))
                    self.wfile.write(body)
                    return
                if request.path == "/dashboard.js":
                    body = ASSET.with_name("dashboard.js").read_bytes()
                    self._headers(200, "text/javascript; charset=utf-8", length=len(body))
                    self.wfile.write(body)
                    return
                if request.path.startswith("/api/v1/"):
                    if not self._authenticated_v1():
                        self._api_error(401, "authentication_required", "Authentication is required.")
                        return
                    if request.path != "/api/v1/inventory/devices":
                        self._api_error(404, "not_found", "The requested resource was not found.")
                        return
                    try:
                        query = parse_qs(request.query, keep_blank_values=True)
                        with InventoryStore(database) as store:
                            self._json(inventory_devices(store, query))
                    except ApiValidationError as error:
                        self._api_error(400, error.code, error.message, field=error.field)
                    except (OSError, RuntimeError, sqlite3.Error, UnicodeError):
                        self._api_error(500, "internal_error", "The inventory could not be loaded.")
                    return
                if request.path.startswith("/api/") and not self._authenticated():
                    self._json({"error": "Authentication required"}, 401)
                    return
                with InventoryStore(database) as store:
                    query = parse_qs(request.query)
                    scope, network_filter = self._scope(query)
                    networks = [item["network"] for item in current_ipv4_scopes()]
                    visible_ids = self._visible_ids(store, network_filter)
                    if request.path == "/api/session":
                        self._json({"settings": ConfigManager(config_path).load().to_mapping(),
                                    "currentNetworks": networks})
                        return
                    if request.path == "/api/overview":
                        period = query.get("period", ["24h"])[0]
                        snapshot = dashboard_snapshot(store, networks=networks, period=period,
                                                      include_history=scope == "history")
                        snapshot["scope"] = scope
                        snapshot["networks"] = networks
                        self._json(snapshot)
                        return
                    if request.path == "/api/devices":
                        self._json({"networks": networks, "scope": scope,
                                    "devices": _device_rows(store, query, network_filter)})
                        return
                    if request.path == "/api/events":
                        since = int(query.get("since", [str(int(time.time()) - 604800)])[0])
                        events = [item for item in store.list_events(since=since, limit=1000)
                                  if item.get("device_id") in visible_ids]
                        state = query.get("state", ["open"])[0]
                        if state == "open":
                            events = [item for item in events if not item["dismissed_at"]]
                        elif state != "all":
                            raise ValueError("Invalid event state")
                        self._json({"networks": networks, "scope": scope, "events": events[:250]})
                        return
                    if request.path == "/api/sensors":
                        since = int(query.get("since", [str(int(time.time()) - 604800)])[0])
                        self._json({
                            "status": store.list_sensor_status(),
                            "findings": store.list_sensor_findings(since=since, limit=250),
                            "visibility": "Sensor data covers only traffic delivered to this host. Full-LAN visibility requires a mirror port, network tap, or gateway sensor.",
                            "packetPayloadStored": False,
                        })
                        return
                    if request.path.startswith("/api/devices/"):
                        device_id = request.path.removeprefix("/api/devices/")
                        if not device_id or "/" in device_id or len(device_id) > 64:
                            raise ValueError("Invalid device ID")
                        report = store.get_device_report(device_id)
                        if device_id not in visible_ids:
                            raise KeyError("Device is outside the selected inventory scope")
                        if query.get("download") == ["1"]:
                            self._json(report, download=f"cyber-scout-device-{device_id}.json")
                            return
                        self._json({"device": report})
                        return
                    if request.path == "/api/export":
                        visible = store.list_devices(networks=network_filter, limit=1000)
                        devices = [store.get_device_report(item["id"]) for item in visible]
                        self._json(
                            {"exportedAt": int(time.time()), "scope": scope, "networks": networks,
                             "devices": devices},
                            download="cyber-scout-inventory.json",
                        )
                        return
                self._json({"error": "Not found"}, 404)
            except (KeyError, OSError, ValueError) as error:
                self._json({"error": str(error)}, 400)

        def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
            try:
                if not self._valid_host():
                    self._json({"error": "Invalid request authority"}, 421)
                    return
                if not allowed_origin(self.headers.get("Origin"), self.server.server_port):
                    self._json({"error": "Invalid request origin"}, 403)
                    return
                if not self._authenticated():
                    self._json({"error": "Invalid dashboard session token"}, 403)
                    return
                if self.headers.get_content_type() != "application/json":
                    raise ValueError("Content-Type must be application/json")
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 65536:
                    raise ValueError("Invalid request size")
                body = json.loads(self.rfile.read(length))
                if not isinstance(body, dict):
                    raise ValueError("Request body must be an object")
                request = urlsplit(self.path)
                if request.path.startswith("/api/events/"):
                    parts = request.path.strip("/").split("/")
                    if len(parts) != 4 or parts[:2] != ["api", "events"]:
                        raise ValueError("Invalid event action")
                    with InventoryStore(database) as store:
                        event = store.set_event_state(int(parts[2]), parts[3])
                        store.record_authorization_decision(
                            f"events.{parts[3]}", "event", resource_id=parts[2],
                            request_context={"origin": self.headers.get("Origin")},
                        )
                        self._json({"event": event})
                    return
                if request.path == "/api/settings":
                    allowed = {"retention_days", "active_discovery_enabled", "approved_networks",
                               "active_rate_limit", "active_timeout_seconds", "scheduled_scan_minutes",
                               "zeek_log_directory", "suricata_eve_path"}
                    if set(body) - allowed:
                        raise ValueError("Unsupported setting")
                    manager = ConfigManager(config_path)
                    values = manager.load().to_mapping()
                    values.update(body)
                    config = CyberScoutConfig.from_mapping(values)
                    manager.save(config)
                    with InventoryStore(database) as store:
                        store.record_authorization_decision(
                            "settings.write", "settings",
                            request_context={"origin": self.headers.get("Origin")},
                        )
                    self._json({"settings": config.to_mapping()})
                    return
                self._json({"error": "Not found"}, 404)
            except (json.JSONDecodeError, KeyError, OSError, ValueError) as error:
                self._json({"error": str(error)}, 400)

        def log_message(self, message_format: str, *args: object) -> None:
            logger.info(message_format, *args)

    return DashboardHandler


def main() -> int:
    parser = argparse.ArgumentParser(description="Cyber Scout loopback dashboard")
    parser.add_argument("--host", default=HOST, choices=[HOST, "::1"])
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("port must be between 1024 and 65535")
    server = ThreadingHTTPServer((args.host, args.port), make_handler(port=args.port))
    logger = runtime_logger("dashboard")
    logger.info("dashboard listening on %s:%s", args.host, args.port)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        logger.info("dashboard stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
