"""Bounded read projections for the versioned local API."""

from __future__ import annotations

import base64
import binascii
from datetime import datetime, timezone
import hashlib
import json
import time

from .database import DEVICE_CATEGORIES, RECOGNITION_STATES, InventoryStore


DEFAULT_LIMIT = 100
MAX_LIMIT = 250
MAX_PROJECTED_DEVICES = 1000
VALID_STATES = {"reachable", "unavailable", "unknown"}
QUERY_FIELDS = {"cursor", "limit", "recognition", "state", "category", "updatedAfter", "search"}


class ApiValidationError(ValueError):
    def __init__(self, code: str, message: str, *, field: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.field = field


def _one(query: dict[str, list[str]], name: str) -> str | None:
    values = query.get(name)
    if values is None:
        return None
    if len(values) != 1 or values[0] == "":
        raise ApiValidationError("validation_error", "The request could not be accepted.", field=name)
    return values[0]


def _rfc3339(value: int | None) -> str | None:
    if value is None:
        return None
    return datetime.fromtimestamp(int(value), timezone.utc).isoformat().replace("+00:00", "Z")


def _filter_key(values: dict[str, object]) -> str:
    encoded = json.dumps(values, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()[:16]


def _encode_cursor(offset: int, key: str) -> str:
    raw = json.dumps({"o": offset, "f": key}, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _decode_cursor(value: str | None, key: str) -> int:
    if value is None:
        return 0
    try:
        padded = value + "=" * (-len(value) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded).decode())
        offset = payload["o"]
        if set(payload) != {"o", "f"} or payload["f"] != key:
            raise ValueError
        if not isinstance(offset, int) or isinstance(offset, bool) or not 0 <= offset <= MAX_PROJECTED_DEVICES:
            raise ValueError
        return offset
    except (binascii.Error, KeyError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise ApiValidationError("invalid_cursor", "The pagination cursor is invalid.", field="cursor") from error


def parse_inventory_query(query: dict[str, list[str]]) -> dict[str, object]:
    unknown = set(query) - QUERY_FIELDS
    if unknown:
        raise ApiValidationError("validation_error", "The request could not be accepted.", field=sorted(unknown)[0])
    raw_limit = _one(query, "limit")
    try:
        limit = DEFAULT_LIMIT if raw_limit is None else int(raw_limit)
    except ValueError as error:
        raise ApiValidationError("validation_error", "The request could not be accepted.", field="limit") from error
    if not 1 <= limit <= MAX_LIMIT:
        raise ApiValidationError("validation_error", "The request could not be accepted.", field="limit")
    recognition = _one(query, "recognition")
    if recognition is not None and recognition not in RECOGNITION_STATES:
        raise ApiValidationError("validation_error", "The request could not be accepted.", field="recognition")
    category = _one(query, "category")
    if category is not None and category not in DEVICE_CATEGORIES:
        raise ApiValidationError("validation_error", "The request could not be accepted.", field="category")
    state = _one(query, "state")
    if state is not None and state not in VALID_STATES:
        raise ApiValidationError("validation_error", "The request could not be accepted.", field="state")
    search = _one(query, "search") or ""
    if len(search) > 128 or any(ord(character) < 32 for character in search):
        raise ApiValidationError("validation_error", "The request could not be accepted.", field="search")
    raw_updated = _one(query, "updatedAfter")
    updated_after = None
    if raw_updated is not None:
        try:
            parsed = datetime.fromisoformat(raw_updated.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError
            updated_after = int(parsed.timestamp())
        except (OverflowError, ValueError) as error:
            raise ApiValidationError("validation_error", "The request could not be accepted.", field="updatedAfter") from error
    filters = {
        "recognition": recognition,
        "category": category,
        "state": state,
        "search": search,
        "updatedAfter": updated_after,
    }
    cursor_key = _filter_key(filters)
    filters["limit"] = limit
    filters["offset"] = _decode_cursor(_one(query, "cursor"), cursor_key)
    return filters


def _state(device: dict, now: int) -> str:
    positive = max(int(device.get("last_active") or 0), int(device.get("last_connectivity") or 0))
    return "reachable" if positive and positive >= now - 900 else "unknown"


def _display_name(device: dict) -> str:
    hostnames = device.get("hostnames") or []
    candidates = [
        device.get("user_name"),
        hostnames[0].get("hostname") if hostnames else None,
        device.get("manufacturer"),
        device.get("category") if device.get("category") != "Unknown" else None,
        "Unknown device",
    ]
    return next(str(value) for value in candidates if value)


def _project(device: dict, now: int) -> dict:
    addresses = [
        {
            "family": item["family"],
            "address": item["address"],
            "interface": item["interface"],
            "lastObservedAt": _rfc3339(item["last_observed"]),
        }
        for item in device.get("addresses", [])[:8]
    ]
    return {
        "id": str(device["id"]),
        "displayName": _display_name(device),
        "category": str(device.get("category") or "Unknown").lower(),
        "recognition": device.get("recognition") or "unrecognized",
        "state": _state(device, now),
        "identityConfidence": float(device.get("identification_confidence") or 0),
        "manufacturer": device.get("manufacturer"),
        "primaryMac": device.get("primary_mac"),
        "addresses": addresses,
        "firstObservedAt": _rfc3339(device.get("first_observed")),
        "lastObservedAt": _rfc3339(device.get("last_observed")),
        "revision": int(device.get("updated_at") or device.get("last_observed") or 0),
    }


def inventory_devices(store: InventoryStore, query: dict[str, list[str]], *, now: int | None = None) -> dict:
    values = parse_inventory_query(query)
    timestamp = int(time.time() if now is None else now)
    rows = store.list_devices(
        search=str(values["search"]),
        recognition=values["recognition"],
        category=values["category"],
        limit=MAX_PROJECTED_DEVICES,
    )
    projected = []
    for row in rows:
        if values["updatedAfter"] is not None and int(row.get("updated_at") or 0) <= values["updatedAfter"]:
            continue
        item = _project(store.get_device(str(row["id"])), timestamp)
        if values["state"] is None or item["state"] == values["state"]:
            projected.append(item)
    offset, limit = int(values["offset"]), int(values["limit"])
    page = projected[offset:offset + limit]
    next_offset = offset + len(page)
    filter_values = {name: values[name] for name in ("recognition", "category", "state", "search", "updatedAfter")}
    next_cursor = _encode_cursor(next_offset, _filter_key(filter_values)) if next_offset < len(projected) else None
    return {"dataVersion": 1, "items": page, "nextCursor": next_cursor}
