"""Versioned SQLite inventory and history storage."""

from __future__ import annotations

import json
import ipaddress
import os
from pathlib import Path
import sqlite3
import time
import uuid

from .models import Observation, is_locally_administered

DEFAULT_DATABASE = Path.home() / ".local" / "share" / "cyber-scout" / "cyber-scout.db"
SCHEMA_VERSION = 6
DEVICE_CATEGORIES = {
    "Computer", "Phone", "Tablet", "Server", "Router", "Switch", "Printer",
    "Television", "Smart home / IoT", "Gaming console", "Unknown",
}
RECOGNITION_STATES = {"recognized", "unrecognized", "ignored"}

MIGRATION_1 = """
CREATE TABLE devices (
    id TEXT PRIMARY KEY,
    primary_mac TEXT UNIQUE,
    user_name TEXT,
    category TEXT NOT NULL DEFAULT 'Unknown' CHECK (category IN (
        'Computer','Phone','Tablet','Server','Router','Switch','Printer',
        'Television','Smart home / IoT','Gaming console','Unknown'
    )),
    recognition TEXT NOT NULL DEFAULT 'unrecognized' CHECK (recognition IN (
        'recognized','unrecognized','ignored'
    )),
    notes TEXT NOT NULL DEFAULT '',
    manufacturer TEXT,
    first_observed INTEGER NOT NULL,
    last_observed INTEGER NOT NULL,
    last_active INTEGER,
    last_connectivity INTEGER,
    identification_confidence REAL NOT NULL DEFAULT 0.0,
    randomized_mac INTEGER NOT NULL DEFAULT 0 CHECK (randomized_mac IN (0,1)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE addresses (
    id INTEGER PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    family INTEGER NOT NULL CHECK (family IN (4,6)),
    address TEXT NOT NULL,
    interface TEXT NOT NULL,
    first_observed INTEGER NOT NULL,
    last_observed INTEGER NOT NULL,
    last_active INTEGER,
    last_state TEXT NOT NULL,
    UNIQUE(device_id, address, interface)
);

CREATE TABLE hostnames (
    id INTEGER PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    source TEXT NOT NULL,
    first_observed INTEGER NOT NULL,
    last_observed INTEGER NOT NULL,
    UNIQUE(device_id, hostname, source)
);

CREATE TABLE observations (
    id INTEGER PRIMARY KEY,
    device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
    observed_at INTEGER NOT NULL,
    source TEXT NOT NULL,
    interface TEXT NOT NULL,
    address TEXT,
    mac TEXT,
    state TEXT NOT NULL,
    active INTEGER NOT NULL CHECK (active IN (0,1)),
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE services (
    id INTEGER PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    address TEXT NOT NULL,
    protocol TEXT NOT NULL,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    service TEXT,
    source TEXT NOT NULL,
    first_observed INTEGER NOT NULL,
    last_observed INTEGER NOT NULL,
    UNIQUE(device_id, address, protocol, port, source)
);

CREATE TABLE events (
    id INTEGER PRIMARY KEY,
    device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
    occurred_at INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info',
    summary TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}',
    dedupe_key TEXT,
    acknowledged_at INTEGER,
    dismissed_at INTEGER
);

CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX idx_devices_last_observed ON devices(last_observed DESC);
CREATE INDEX idx_devices_recognition ON devices(recognition, last_observed DESC);
CREATE INDEX idx_addresses_address ON addresses(address, last_observed DESC);
CREATE INDEX idx_observations_time ON observations(observed_at DESC);
CREATE INDEX idx_observations_device_time ON observations(device_id, observed_at DESC);
CREATE INDEX idx_events_time ON events(occurred_at DESC);
CREATE INDEX idx_events_device_time ON events(device_id, occurred_at DESC);
CREATE INDEX idx_events_dedupe ON events(dedupe_key, occurred_at DESC);
CREATE INDEX idx_services_device ON services(device_id, last_observed DESC);
"""

MIGRATION_2 = """
CREATE TABLE diagnostic_jobs (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    address TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('ping','services','exposure')),
    status TEXT NOT NULL CHECK (status IN ('queued','running','completed','failed','cancelled')),
    progress INTEGER NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
    created_at INTEGER NOT NULL,
    started_at INTEGER,
    finished_at INTEGER,
    cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK (cancel_requested IN (0,1)),
    result_json TEXT,
    error TEXT
);
CREATE INDEX idx_diagnostic_jobs_status_created ON diagnostic_jobs(status, created_at);
CREATE INDEX idx_diagnostic_jobs_device_created ON diagnostic_jobs(device_id, created_at DESC);
"""

MIGRATION_3 = """
CREATE TABLE scan_jobs (
    id TEXT PRIMARY KEY,
    network TEXT NOT NULL,
    interface TEXT NOT NULL,
    trigger TEXT NOT NULL CHECK (trigger IN ('manual','scheduled')),
    status TEXT NOT NULL CHECK (status IN ('queued','running','completed','failed','cancelled')),
    progress INTEGER NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
    created_at INTEGER NOT NULL,
    started_at INTEGER,
    finished_at INTEGER,
    cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK (cancel_requested IN (0,1)),
    result_json TEXT,
    error TEXT
);
CREATE INDEX idx_scan_jobs_status_created ON scan_jobs(status, created_at);
CREATE INDEX idx_scan_jobs_created ON scan_jobs(created_at DESC);
"""

MIGRATION_4 = """
CREATE TABLE sensor_findings (
    id INTEGER PRIMARY KEY,
    sensor TEXT NOT NULL CHECK (sensor IN ('zeek','suricata')),
    external_id TEXT NOT NULL,
    record_type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('info','review','higher')),
    summary TEXT NOT NULL,
    first_observed INTEGER NOT NULL,
    last_observed INTEGER NOT NULL,
    occurrences INTEGER NOT NULL DEFAULT 1 CHECK (occurrences >= 1),
    source_ip TEXT,
    source_port INTEGER,
    destination_ip TEXT,
    destination_port INTEGER,
    protocol TEXT,
    device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
    details_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(sensor, external_id)
);
CREATE TABLE sensor_cursors (
    path TEXT PRIMARY KEY,
    sensor TEXT NOT NULL CHECK (sensor IN ('zeek','suricata')),
    inode INTEGER NOT NULL,
    offset INTEGER NOT NULL CHECK (offset >= 0),
    last_read INTEGER NOT NULL,
    records_read INTEGER NOT NULL DEFAULT 0,
    parse_errors INTEGER NOT NULL DEFAULT 0,
    error TEXT
);
CREATE INDEX idx_sensor_findings_last ON sensor_findings(last_observed DESC);
CREATE INDEX idx_sensor_findings_device ON sensor_findings(device_id,last_observed DESC);
CREATE INDEX idx_sensor_findings_severity ON sensor_findings(severity,last_observed DESC);
"""

MIGRATION_5 = """
CREATE TABLE authorization_decisions (
    id TEXT PRIMARY KEY,
    actor_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    capability TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    decision TEXT NOT NULL CHECK (decision IN ('allow','deny')),
    reason TEXT NOT NULL,
    request_context_json TEXT NOT NULL DEFAULT '{}',
    decided_at INTEGER NOT NULL
);
CREATE INDEX idx_authorization_decisions_time ON authorization_decisions(decided_at DESC);
CREATE INDEX idx_authorization_decisions_capability ON authorization_decisions(capability,decided_at DESC);
"""

MIGRATION_6 = """
CREATE TABLE identity_evidence (
    id INTEGER PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    evidence_type TEXT NOT NULL CHECK (evidence_type IN ('mac','hostname','manufacturer','classification')),
    value TEXT NOT NULL,
    source TEXT NOT NULL,
    confidence REAL NOT NULL CHECK (confidence BETWEEN 0.0 AND 1.0),
    first_observed INTEGER NOT NULL,
    last_observed INTEGER NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(device_id,evidence_type,value,source)
);
CREATE TABLE identity_conflicts (
    id INTEGER PRIMARY KEY,
    conflict_type TEXT NOT NULL CHECK (conflict_type IN ('address_reuse')),
    value TEXT NOT NULL,
    first_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    second_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    first_observed INTEGER NOT NULL,
    last_observed INTEGER NOT NULL,
    occurrences INTEGER NOT NULL DEFAULT 1,
    UNIQUE(conflict_type,value,first_device_id,second_device_id)
);
CREATE INDEX idx_identity_evidence_device ON identity_evidence(device_id,last_observed DESC);
CREATE INDEX idx_identity_conflicts_value ON identity_conflicts(value,last_observed DESC);
"""


class InventoryStore:
    def __init__(self, path: Path | str = DEFAULT_DATABASE) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            self.path.parent.chmod(0o700)
        except OSError:
            pass
        database_existed = self.path.exists() and self.path.stat().st_size > 0
        self.connection = sqlite3.connect(self.path, timeout=5.0)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA journal_mode = WAL")
        self.connection.execute("PRAGMA synchronous = NORMAL")
        self.connection.execute("PRAGMA busy_timeout = 5000")
        if database_existed:
            self.verify_integrity()
        self.migrate()
        self.verify_integrity()
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    def __enter__(self) -> "InventoryStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self.connection.close()

    def verify_integrity(self) -> None:
        row = self.connection.execute("PRAGMA quick_check").fetchone()
        result = str(row[0]) if row else "no result"
        if result != "ok":
            raise RuntimeError(f"Database integrity check failed: {result}")

    def create_backup(self, *, reason: str = "manual", keep: int = 5) -> Path:
        """Create a consistent SQLite backup without copying live WAL files."""
        safe_reason = "".join(character for character in reason if character.isalnum() or character in "-_")[:32]
        version = int(self.connection.execute("PRAGMA user_version").fetchone()[0])
        backup_directory = self.path.parent / "backups"
        backup_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        backup_directory.chmod(0o700)
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + f"-{time.time_ns() % 1_000_000_000:09d}"
        destination = backup_directory / f"{self.path.stem}-{safe_reason or 'manual'}-v{version}-{stamp}.db"
        temporary = destination.with_suffix(".tmp")
        backup_connection = sqlite3.connect(temporary)
        try:
            self.connection.backup(backup_connection)
        finally:
            backup_connection.close()
        temporary.chmod(0o600)
        os.replace(temporary, destination)
        backups = sorted(backup_directory.glob(f"{self.path.stem}-*.db"), key=lambda item: item.stat().st_mtime)
        for expired in backups[:-max(1, keep)]:
            expired.unlink()
        return destination

    def migrate(self) -> None:
        version = int(self.connection.execute("PRAGMA user_version").fetchone()[0])
        if version > SCHEMA_VERSION:
            raise RuntimeError(f"Database schema {version} is newer than supported {SCHEMA_VERSION}")
        backup = self.create_backup(reason="pre-migration") if 0 < version < SCHEMA_VERSION else None
        try:
            if version < 1:
                with self.connection:
                    self.connection.executescript(MIGRATION_1)
                    self.connection.execute("PRAGMA user_version = 1")
                version = 1
            if version < 2:
                with self.connection:
                    self.connection.executescript(MIGRATION_2)
                    self.connection.execute("PRAGMA user_version = 2")
                version = 2
            if version < 3:
                with self.connection:
                    self.connection.executescript(MIGRATION_3)
                    self.connection.execute("PRAGMA user_version = 3")
                version = 3
            if version < 4:
                with self.connection:
                    self.connection.executescript(MIGRATION_4)
                    self.connection.execute("PRAGMA user_version = 4")
                version = 4
            if version < 5:
                with self.connection:
                    self.connection.executescript(MIGRATION_5)
                    self.connection.execute("PRAGMA user_version = 5")
                version = 5
            if version < 6:
                with self.connection:
                    self.connection.executescript(MIGRATION_6)
                    self.connection.execute("PRAGMA user_version = 6")
        except (OSError, sqlite3.Error) as error:
            recovery = f" Restore the automatic backup at {backup}." if backup else ""
            raise RuntimeError(f"Database migration failed.{recovery}") from error

    def _create_device(self, observation: Observation) -> str:
        device_id = str(uuid.uuid4())
        randomized = is_locally_administered(observation.mac)
        confidence = 0.55 if randomized else 0.85
        now = observation.observed_at
        self.connection.execute(
            """INSERT INTO devices (
                id, primary_mac, first_observed, last_observed, last_active,
                identification_confidence, randomized_mac, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                device_id,
                observation.mac,
                now,
                now,
                now if observation.active else None,
                confidence,
                int(randomized),
                now,
                now,
            ),
        )
        self._record_event(
            device_id,
            now,
            "device.first_observed",
            "New device observed",
            {"source": observation.source, "address": observation.address},
            f"new-device:{device_id}",
        )
        return device_id

    def record_authorization_decision(
        self, capability: str, resource_type: str, *, resource_id: str | None = None,
        decision: str = "allow", reason: str = "policy.allowed", actor_type: str = "local_user",
        actor_id: str = "desktop-session", request_context: dict | None = None,
        decided_at: int | None = None,
    ) -> str:
        if decision not in {"allow", "deny"}:
            raise ValueError("Invalid authorization decision")
        for value in (capability, resource_type, reason, actor_type, actor_id):
            if not value or len(value) > 128:
                raise ValueError("Invalid authorization field")
        decision_id = str(uuid.uuid4())
        with self.connection:
            self.connection.execute(
                "INSERT INTO authorization_decisions(id,actor_type,actor_id,capability,resource_type,"
                "resource_id,decision,reason,request_context_json,decided_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (decision_id, actor_type, actor_id, capability, resource_type, resource_id,
                 decision, reason, json.dumps(request_context or {}, separators=(",", ":")),
                 int(decided_at if decided_at is not None else time.time())),
            )
        return decision_id

    def _record_event(
        self,
        device_id: str | None,
        occurred_at: int,
        event_type: str,
        summary: str,
        details: dict,
        dedupe_key: str | None,
        debounce_seconds: int = 3600,
    ) -> None:
        if dedupe_key:
            existing = self.connection.execute(
                "SELECT 1 FROM events WHERE dedupe_key = ? AND occurred_at >= ? LIMIT 1",
                (dedupe_key, occurred_at - debounce_seconds),
            ).fetchone()
            if existing:
                return
        self.connection.execute(
            """INSERT INTO events
               (device_id, occurred_at, event_type, summary, details_json, dedupe_key)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (device_id, occurred_at, event_type, summary, json.dumps(details, separators=(",", ":")), dedupe_key),
        )

    def _record_identity_evidence(self, device_id: str, evidence_type: str, value: str,
                                  source: str, confidence: float, observed_at: int,
                                  details: dict | None = None) -> None:
        self.connection.execute(
            """INSERT INTO identity_evidence
               (device_id,evidence_type,value,source,confidence,first_observed,last_observed,details_json)
               VALUES(?,?,?,?,?,?,?,?)
               ON CONFLICT(device_id,evidence_type,value,source) DO UPDATE SET
                 confidence=MAX(confidence,excluded.confidence),
                 last_observed=MAX(last_observed,excluded.last_observed),
                 details_json=excluded.details_json""",
            (device_id, evidence_type, value, source, max(0.0, min(float(confidence), 1.0)),
             observed_at, observed_at, json.dumps(details or {}, separators=(",", ":"), sort_keys=True)),
        )

    def ingest(self, observation: Observation) -> str | None:
        with self.connection:
            row = None
            if observation.mac:
                row = self.connection.execute(
                    "SELECT id FROM devices WHERE primary_mac = ?", (observation.mac,)
                ).fetchone()
            device_id = str(row["id"]) if row else None
            existed = device_id is not None
            if not device_id and observation.mac:
                device_id = self._create_device(observation)

            self.connection.execute(
                """INSERT INTO observations
                   (device_id, observed_at, source, interface, address, mac, state, active, metadata_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    device_id,
                    observation.observed_at,
                    observation.source,
                    observation.interface,
                    observation.address,
                    observation.mac,
                    observation.state,
                    int(observation.active),
                    json.dumps(observation.metadata, separators=(",", ":"), sort_keys=True),
                ),
            )
            if not device_id:
                return None

            if observation.mac:
                self._record_identity_evidence(
                    device_id, "mac", observation.mac, observation.source,
                    0.55 if is_locally_administered(observation.mac) else 0.85,
                    observation.observed_at, {"randomized": is_locally_administered(observation.mac)},
                )

            self.connection.execute(
                """UPDATE devices SET
                   last_observed = MAX(last_observed, ?),
                   last_active = CASE WHEN ? THEN MAX(COALESCE(last_active, 0), ?) ELSE last_active END,
                   updated_at = MAX(updated_at, ?)
                   WHERE id = ?""",
                (
                    observation.observed_at,
                    int(observation.active),
                    observation.observed_at,
                    observation.observed_at,
                    device_id,
                ),
            )

            if observation.address:
                conflicts = list(self.connection.execute(
                    "SELECT DISTINCT device_id FROM addresses WHERE address=? AND device_id<>?",
                    (observation.address, device_id),
                ))
                for conflict in conflicts:
                    first_id, second_id = sorted((str(conflict["device_id"]), device_id))
                    self.connection.execute(
                        """INSERT INTO identity_conflicts
                           (conflict_type,value,first_device_id,second_device_id,first_observed,last_observed)
                           VALUES('address_reuse',?,?,?,?,?)
                           ON CONFLICT(conflict_type,value,first_device_id,second_device_id) DO UPDATE SET
                             last_observed=MAX(last_observed,excluded.last_observed),occurrences=occurrences+1""",
                        (observation.address, first_id, second_id, observation.observed_at, observation.observed_at),
                    )
                    self._record_event(
                        device_id, observation.observed_at, "identity.address_conflict",
                        "Address was observed for more than one device",
                        {"address": observation.address, "otherDeviceId": str(conflict["device_id"])},
                        f"address-conflict:{observation.address}:{first_id}:{second_id}",
                    )
                prior = self.connection.execute(
                    "SELECT 1 FROM addresses WHERE device_id = ? AND address = ? AND interface = ?",
                    (device_id, observation.address, observation.interface),
                ).fetchone()
                self.connection.execute(
                    """INSERT INTO addresses
                       (device_id, family, address, interface, first_observed, last_observed, last_active, last_state)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(device_id, address, interface) DO UPDATE SET
                         last_observed = MAX(last_observed, excluded.last_observed),
                         last_active = CASE WHEN excluded.last_active IS NOT NULL
                           THEN MAX(COALESCE(last_active, 0), excluded.last_active) ELSE last_active END,
                         last_state = excluded.last_state""",
                    (
                        device_id,
                        observation.family,
                        observation.address,
                        observation.interface,
                        observation.observed_at,
                        observation.observed_at,
                        observation.observed_at if observation.active else None,
                        observation.state,
                    ),
                )
                if existed and not prior:
                    self._record_event(
                        device_id,
                        observation.observed_at,
                        "device.address_added",
                        "Device observed at a new address",
                        {"address": observation.address, "interface": observation.interface},
                        f"address:{device_id}:{observation.address}",
                    )

            if observation.hostname:
                self._record_identity_evidence(
                    device_id, "hostname", observation.hostname, observation.source, 0.65,
                    observation.observed_at,
                )
                prior_hostname = self.connection.execute(
                    "SELECT 1 FROM hostnames WHERE device_id = ? AND hostname = ? AND source = ?",
                    (device_id, observation.hostname, observation.source),
                ).fetchone()
                self.connection.execute(
                    """INSERT INTO hostnames
                       (device_id, hostname, source, first_observed, last_observed)
                       VALUES (?, ?, ?, ?, ?)
                       ON CONFLICT(device_id, hostname, source) DO UPDATE SET
                         last_observed = MAX(last_observed, excluded.last_observed)""",
                    (
                        device_id,
                        observation.hostname,
                        observation.source,
                        observation.observed_at,
                        observation.observed_at,
                    ),
                )
                if existed and not prior_hostname:
                    self._record_event(
                        device_id,
                        observation.observed_at,
                        "device.hostname_added",
                        "Device reported a new hostname",
                        {"hostname": observation.hostname, "source": observation.source},
                        f"hostname:{device_id}:{observation.hostname.lower()}",
                    )
            return device_id

    def ingest_many(self, observations: list[Observation]) -> dict[str, int]:
        assigned = 0
        unassigned = 0
        for observation in observations:
            if self.ingest(observation):
                assigned += 1
            else:
                unassigned += 1
        return {"observations": len(observations), "assigned": assigned, "unassigned": unassigned}

    def enrich_device_by_mac(
        self,
        mac: str,
        *,
        user_name: str | None = None,
        manufacturer: str | None = None,
        category: str | None = None,
    ) -> bool:
        assignments: list[str] = []
        values: list[object] = []
        if user_name:
            assignments.append("user_name = ?")
            values.append(user_name[:64])
        if manufacturer and manufacturer != "Unknown vendor":
            assignments.append("manufacturer = ?")
            values.append(manufacturer[:256])
        if category:
            assignments.append("category = CASE WHEN category = 'Unknown' THEN ? ELSE category END")
            values.append(category)
        if not assignments:
            return False
        observed_at = int(time.time())
        assignments.append("updated_at = ?")
        values.append(observed_at)
        values.append(mac.upper())
        with self.connection:
            cursor = self.connection.execute(
                f"UPDATE devices SET {', '.join(assignments)} WHERE primary_mac = ?",
                values,
            )
            if cursor.rowcount > 0:
                row = self.connection.execute(
                    "SELECT id FROM devices WHERE primary_mac = ?", (mac.upper(),)
                ).fetchone()
                if row and manufacturer and manufacturer != "Unknown vendor":
                    self._record_identity_evidence(
                        str(row["id"]), "manufacturer", manufacturer[:256],
                        "oui_database", 0.70, observed_at,
                    )
                if row and category:
                    self._record_identity_evidence(
                        str(row["id"]), "classification", category,
                        "name_vendor_heuristic", 0.50, observed_at,
                    )
        return cursor.rowcount > 0

    @staticmethod
    def _clean_text(value: str, *, maximum: int, field: str, allow_empty: bool = True) -> str:
        if not isinstance(value, str):
            raise ValueError(f"{field} must be text")
        cleaned = " ".join(value.replace("\x00", "").split()).strip()
        if not allow_empty and not cleaned:
            raise ValueError(f"{field} cannot be empty")
        if len(cleaned) > maximum:
            raise ValueError(f"{field} must be at most {maximum} characters")
        return cleaned

    def update_device(
        self,
        device_id: str,
        *,
        user_name: str | None = None,
        category: str | None = None,
        recognition: str | None = None,
        notes: str | None = None,
        occurred_at: int | None = None,
    ) -> dict:
        """Apply explicit user-managed metadata and record an auditable event."""
        if not isinstance(device_id, str) or len(device_id) > 64:
            raise ValueError("Invalid device ID")
        timestamp = int(occurred_at if occurred_at is not None else time.time())
        current = self.connection.execute(
            "SELECT user_name, category, recognition, notes FROM devices WHERE id = ?", (device_id,)
        ).fetchone()
        if not current:
            raise KeyError("Device not found")
        changes: dict[str, object] = {}
        if user_name is not None:
            changes["user_name"] = self._clean_text(user_name, maximum=64, field="Device name") or None
        if category is not None:
            if category not in DEVICE_CATEGORIES:
                raise ValueError("Invalid device category")
            changes["category"] = category
        if recognition is not None:
            if recognition not in RECOGNITION_STATES:
                raise ValueError("Invalid recognition state")
            changes["recognition"] = recognition
        if notes is not None:
            changes["notes"] = self._clean_text(notes, maximum=2000, field="Notes")
        changed = {name: value for name, value in changes.items() if current[name] != value}
        if changed:
            assignments = ", ".join(f"{name} = ?" for name in changed)
            with self.connection:
                self.connection.execute(
                    f"UPDATE devices SET {assignments}, updated_at = ? WHERE id = ?",
                    (*changed.values(), timestamp, device_id),
                )
                self._record_event(
                    device_id,
                    timestamp,
                    "device.user_updated",
                    "Device details updated",
                    {"fields": sorted(changed)},
                    None,
                )
        return self.get_device(device_id)

    def get_device(self, device_id: str) -> dict:
        row = self.connection.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
        if not row:
            raise KeyError("Device not found")
        result = dict(row)
        result["addresses"] = [
            dict(item) for item in self.connection.execute(
                "SELECT family, address, interface, first_observed, last_observed, last_active, last_state "
                "FROM addresses WHERE device_id = ? ORDER BY last_observed DESC", (device_id,)
            )
        ]
        result["hostnames"] = [
            dict(item) for item in self.connection.execute(
                "SELECT hostname, source, first_observed, last_observed FROM hostnames "
                "WHERE device_id = ? ORDER BY last_observed DESC", (device_id,)
            )
        ]
        result["identity_evidence"] = []
        for item in self.connection.execute(
            "SELECT evidence_type,value,source,confidence,first_observed,last_observed,details_json "
            "FROM identity_evidence WHERE device_id=? ORDER BY last_observed DESC", (device_id,)
        ):
            evidence = dict(item)
            evidence["details"] = json.loads(evidence.pop("details_json"))
            result["identity_evidence"].append(evidence)
        result["identity_conflicts"] = [
            dict(item) for item in self.connection.execute(
                "SELECT conflict_type,value,first_device_id,second_device_id,first_observed,last_observed,occurrences "
                "FROM identity_conflicts WHERE first_device_id=? OR second_device_id=? ORDER BY last_observed DESC",
                (device_id, device_id),
            )
        ]
        return result

    def get_device_report(self, device_id: str) -> dict:
        """Return the persisted evidence used by detail and export views."""
        result = self.get_device(device_id)
        result["services"] = [
            dict(item) for item in self.connection.execute(
                "SELECT address,protocol,port,service,source,first_observed,last_observed "
                "FROM services WHERE device_id=? ORDER BY last_observed DESC,port",
                (device_id,),
            )
        ]
        result["diagnostics"] = self.list_diagnostic_jobs(device_id=device_id, limit=50)
        result["events"] = self.list_events(device_id=device_id, limit=100)
        return result

    def get_device_by_mac(self, mac: str) -> dict | None:
        row = self.connection.execute("SELECT id FROM devices WHERE primary_mac = ?", (mac.upper(),)).fetchone()
        return self.get_device(str(row["id"])) if row else None

    def list_devices(
        self,
        *,
        search: str = "",
        recognition: str | None = None,
        category: str | None = None,
        limit: int = 250,
        offset: int = 0,
        networks: list[str] | None = None,
    ) -> list[dict]:
        if recognition is not None and recognition not in RECOGNITION_STATES:
            raise ValueError("Invalid recognition state")
        if category is not None and category not in DEVICE_CATEGORIES:
            raise ValueError("Invalid device category")
        limit = max(1, min(int(limit), 1000))
        offset = max(0, int(offset))
        clauses, values = [], []
        if recognition:
            clauses.append("d.recognition = ?")
            values.append(recognition)
        if category:
            clauses.append("d.category = ?")
            values.append(category)
        if search:
            term = f"%{self._clean_text(search, maximum=128, field='Search')}%"
            clauses.append("(COALESCE(d.user_name, '') LIKE ? OR COALESCE(d.primary_mac, '') LIKE ? "
                           "OR EXISTS (SELECT 1 FROM addresses a WHERE a.device_id=d.id AND a.address LIKE ?) "
                           "OR EXISTS (SELECT 1 FROM hostnames h WHERE h.device_id=d.id AND h.hostname LIKE ?))")
            values.extend([term, term, term, term])
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        rows = list(self.connection.execute(
            "SELECT d.* FROM devices d" + where + " ORDER BY d.last_observed DESC, d.id LIMIT ? OFFSET ?",
            (*values, 1000 if networks is not None else limit, 0 if networks is not None else offset),
        ))
        if networks is not None:
            scopes = [ipaddress.ip_network(value, strict=True) for value in networks]
            visible = set()
            for row in self.connection.execute("SELECT device_id,address FROM addresses"):
                try:
                    address = ipaddress.ip_address(row["address"])
                except ValueError:
                    continue
                if isinstance(address, ipaddress.IPv4Address) and any(address in scope for scope in scopes):
                    visible.add(str(row["device_id"]))
            rows = [row for row in rows if str(row["id"]) in visible][offset:offset + limit]
        return [dict(row) for row in rows]

    def counts_for_networks(self, networks: list[str], now: int | None = None) -> dict[str, int]:
        timestamp = int(now if now is not None else time.time())
        devices = self.list_devices(networks=networks, limit=1000)
        return {
            "total": len(devices),
            "recently_active": sum((item["last_active"] or 0) >= timestamp - 900 for item in devices),
            "new_24h": sum(item["first_observed"] >= timestamp - 86400 for item in devices),
            "unrecognized": sum(item["recognition"] == "unrecognized" for item in devices),
        }

    def list_events(
        self,
        *,
        since: int = 0,
        until: int | None = None,
        device_id: str | None = None,
        limit: int = 250,
    ) -> list[dict]:
        clauses, values = ["occurred_at >= ?"], [int(since)]
        if until is not None:
            clauses.append("occurred_at <= ?")
            values.append(int(until))
        if device_id:
            clauses.append("device_id = ?")
            values.append(device_id)
        rows = self.connection.execute(
            "SELECT * FROM events WHERE " + " AND ".join(clauses) +
            " ORDER BY occurred_at DESC, id DESC LIMIT ?",
            (*values, max(1, min(int(limit), 1000))),
        )
        result = []
        for row in rows:
            item = dict(row)
            try:
                item["details"] = json.loads(item.pop("details_json"))
            except (json.JSONDecodeError, TypeError):
                item["details"] = {}
            result.append(item)
        return result

    def set_event_state(self, event_id: int, action: str, now: int | None = None) -> dict:
        """Acknowledge, dismiss, or restore an event without changing its evidence."""
        if action not in {"acknowledge", "dismiss", "restore"}:
            raise ValueError("Invalid event action")
        timestamp = int(now if now is not None else time.time())
        row = self.connection.execute("SELECT id FROM events WHERE id = ?", (int(event_id),)).fetchone()
        if not row:
            raise KeyError("Event not found")
        values = {
            "acknowledge": (timestamp, None),
            "dismiss": (None, timestamp),
            "restore": (None, None),
        }[action]
        with self.connection:
            self.connection.execute(
                "UPDATE events SET acknowledged_at = ?, dismissed_at = ? WHERE id = ?",
                (*values, int(event_id)),
            )
        row = self.connection.execute("SELECT * FROM events WHERE id = ?", (int(event_id),)).fetchone()
        item = dict(row)
        try:
            item["details"] = json.loads(item.pop("details_json"))
        except (json.JSONDecodeError, TypeError):
            item["details"] = {}
        return item

    def change_summary(self, since: int, until: int | None = None) -> dict:
        end = int(until if until is not None else time.time())
        counts = self.connection.execute(
            "SELECT event_type, COUNT(*) AS count FROM events WHERE occurred_at BETWEEN ? AND ? "
            "GROUP BY event_type ORDER BY event_type", (int(since), end)
        )
        return {
            "since": int(since),
            "until": end,
            "counts": {row["event_type"]: int(row["count"]) for row in counts},
            "events": self.list_events(since=int(since), until=end, limit=100),
        }

    def prune(self, retention_days: int, now: int | None = None) -> dict[str, int]:
        if not 1 <= int(retention_days) <= 3650:
            raise ValueError("Retention must be between 1 and 3650 days")
        cutoff = int(now if now is not None else time.time()) - int(retention_days) * 86400
        removed: dict[str, int] = {}
        with self.connection:
            for table, column in (("observations", "observed_at"), ("events", "occurred_at")):
                cursor = self.connection.execute(f"DELETE FROM {table} WHERE {column} < ?", (cutoff,))
                removed[table] = cursor.rowcount
            cursor = self.connection.execute("DELETE FROM sensor_findings WHERE last_observed < ?", (cutoff,))
            removed["sensor_findings"] = cursor.rowcount
        return removed

    def record_sensor_finding(self, finding: dict) -> dict:
        sensor = str(finding.get("sensor", ""))
        if sensor not in {"zeek", "suricata"}:
            raise ValueError("Invalid sensor")
        external_id = self._clean_text(str(finding.get("external_id", "")), maximum=256,
                                       field="Sensor ID", allow_empty=False)
        record_type = self._clean_text(str(finding.get("record_type", "")), maximum=64,
                                       field="Record type", allow_empty=False)
        severity = str(finding.get("severity", "info"))
        if severity not in {"info", "review", "higher"}:
            raise ValueError("Invalid sensor severity")
        summary = self._clean_text(str(finding.get("summary", "")), maximum=512,
                                   field="Summary", allow_empty=False)
        observed_at = int(finding.get("observed_at") or time.time())
        source_ip = finding.get("source_ip")
        destination_ip = finding.get("destination_ip")
        for value in (source_ip, destination_ip):
            if value is not None:
                ipaddress.ip_address(str(value))
        source_port = int(finding["source_port"]) if finding.get("source_port") is not None else None
        destination_port = int(finding["destination_port"]) if finding.get("destination_port") is not None else None
        if any(value is not None and not 0 <= value <= 65535 for value in (source_port, destination_port)):
            raise ValueError("Invalid sensor port")
        protocol = str(finding.get("protocol") or "").lower()[:16] or None
        details = finding.get("details") if isinstance(finding.get("details"), dict) else {}
        details_json = json.dumps(details, separators=(",", ":"), ensure_ascii=False)
        if len(details_json.encode()) > 16384:
            raise ValueError("Sensor details are too large")
        device_row = None
        for address in (source_ip, destination_ip):
            if address:
                device_row = self.connection.execute(
                    "SELECT device_id FROM addresses WHERE address=? ORDER BY last_observed DESC LIMIT 1",
                    (str(address),),
                ).fetchone()
                if device_row:
                    break
        device_id = str(device_row["device_id"]) if device_row else None
        existed = self.connection.execute(
            "SELECT id FROM sensor_findings WHERE sensor=? AND external_id=?", (sensor, external_id)
        ).fetchone()
        with self.connection:
            self.connection.execute(
                """INSERT INTO sensor_findings
                   (sensor,external_id,record_type,severity,summary,first_observed,last_observed,
                    source_ip,source_port,destination_ip,destination_port,protocol,device_id,details_json)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(sensor,external_id) DO UPDATE SET
                     severity=excluded.severity,summary=excluded.summary,
                     last_observed=MAX(last_observed,excluded.last_observed),
                     occurrences=occurrences+1,device_id=COALESCE(device_id,excluded.device_id),
                     details_json=excluded.details_json""",
                (sensor, external_id, record_type, severity, summary, observed_at, observed_at,
                 source_ip, source_port, destination_ip, destination_port, protocol, device_id, details_json),
            )
            if not existed and record_type in {"alert", "notice"}:
                self._record_event(
                    device_id, observed_at, f"sensor.{sensor}.{record_type}", summary, details,
                    f"sensor:{sensor}:{external_id}", debounce_seconds=315360000,
                )
        row = self.connection.execute(
            "SELECT * FROM sensor_findings WHERE sensor=? AND external_id=?", (sensor, external_id)
        ).fetchone()
        return self._decode_sensor_finding(row)

    @staticmethod
    def _decode_sensor_finding(row: sqlite3.Row) -> dict:
        item = dict(row)
        try:
            item["details"] = json.loads(item.pop("details_json"))
        except (json.JSONDecodeError, TypeError):
            item["details"] = {}
        return item

    def list_sensor_findings(self, *, since: int = 0, limit: int = 250) -> list[dict]:
        rows = self.connection.execute(
            "SELECT * FROM sensor_findings WHERE last_observed>=? ORDER BY last_observed DESC,id DESC LIMIT ?",
            (int(since), max(1, min(int(limit), 1000))),
        )
        return [self._decode_sensor_finding(row) for row in rows]

    def get_sensor_cursor(self, path: str) -> dict | None:
        row = self.connection.execute("SELECT * FROM sensor_cursors WHERE path=?", (path,)).fetchone()
        return dict(row) if row else None

    def update_sensor_cursor(self, path: str, sensor: str, inode: int, offset: int, *,
                             records_read: int = 0, parse_errors: int = 0,
                             error: str | None = None, now: int | None = None) -> None:
        if sensor not in {"zeek", "suricata"}:
            raise ValueError("Invalid sensor")
        timestamp = int(now if now is not None else time.time())
        with self.connection:
            self.connection.execute(
                """INSERT INTO sensor_cursors(path,sensor,inode,offset,last_read,records_read,parse_errors,error)
                   VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET sensor=excluded.sensor,
                   inode=excluded.inode,offset=excluded.offset,last_read=excluded.last_read,
                   records_read=records_read+excluded.records_read,
                   parse_errors=parse_errors+excluded.parse_errors,error=excluded.error""",
                (path, sensor, int(inode), max(0, int(offset)), timestamp, max(0, int(records_read)),
                 max(0, int(parse_errors)), str(error)[:512] if error else None),
            )

    def list_sensor_status(self) -> list[dict]:
        return [dict(row) for row in self.connection.execute(
            "SELECT * FROM sensor_cursors ORDER BY sensor,path"
        )]

    def keep_only_networks(self, networks: list[str]) -> dict[str, int]:
        """Destructively remove inventory evidence outside approved IPv4 LANs."""
        allowed = [ipaddress.ip_network(value, strict=True) for value in networks]
        if not allowed or any(not isinstance(item, ipaddress.IPv4Network) or not item.is_private for item in allowed):
            raise ValueError("At least one private IPv4 network is required")
        address_rows = list(self.connection.execute("SELECT id,device_id,address FROM addresses"))
        remove_address_ids = []
        for row in address_rows:
            try:
                address = ipaddress.ip_address(row["address"])
            except ValueError:
                remove_address_ids.append(int(row["id"]))
                continue
            if not isinstance(address, ipaddress.IPv4Address) or not any(address in network for network in allowed):
                remove_address_ids.append(int(row["id"]))
        observation_rows = list(self.connection.execute("SELECT id,address FROM observations WHERE address IS NOT NULL"))
        remove_observation_ids = []
        for row in observation_rows:
            try:
                address = ipaddress.ip_address(row["address"])
            except ValueError:
                remove_observation_ids.append(int(row["id"]))
                continue
            if not isinstance(address, ipaddress.IPv4Address) or not any(address in network for network in allowed):
                remove_observation_ids.append(int(row["id"]))
        with self.connection:
            if remove_address_ids:
                self.connection.executemany("DELETE FROM addresses WHERE id=?", ((item,) for item in remove_address_ids))
            if remove_observation_ids:
                self.connection.executemany("DELETE FROM observations WHERE id=?", ((item,) for item in remove_observation_ids))
            orphan_rows = list(self.connection.execute(
                "SELECT id FROM devices WHERE NOT EXISTS (SELECT 1 FROM addresses WHERE addresses.device_id=devices.id)"
            ))
            orphan_ids = [str(row["id"]) for row in orphan_rows]
            if orphan_ids:
                self.connection.executemany("DELETE FROM events WHERE device_id=?", ((item,) for item in orphan_ids))
                self.connection.executemany("DELETE FROM devices WHERE id=?", ((item,) for item in orphan_ids))
            self.connection.execute(
                """UPDATE devices SET
                   first_observed=(SELECT MIN(first_observed) FROM addresses WHERE device_id=devices.id),
                   last_observed=(SELECT MAX(last_observed) FROM addresses WHERE device_id=devices.id),
                   last_active=(SELECT MAX(last_active) FROM addresses WHERE device_id=devices.id)
                   WHERE EXISTS (SELECT 1 FROM addresses WHERE addresses.device_id=devices.id)"""
            )
        return {
            "addresses": len(remove_address_ids),
            "observations": len(remove_observation_ids),
            "devices": len(orphan_ids),
        }

    def record_services_for_address(
        self,
        address: str,
        services: list[dict],
        *,
        source: str,
        observed_at: int | None = None,
    ) -> int:
        timestamp = int(observed_at if observed_at is not None else time.time())
        row = self.connection.execute(
            "SELECT device_id FROM addresses WHERE address = ? ORDER BY last_observed DESC LIMIT 1", (address,)
        ).fetchone()
        if not row:
            return 0
        device_id = str(row["device_id"])
        recorded = 0
        with self.connection:
            for item in services:
                protocol = str(item.get("protocol", "tcp")).lower()
                port = int(item["port"])
                service = self._clean_text(str(item.get("service") or "unknown"), maximum=128, field="Service")
                if protocol not in {"tcp", "udp"} or not 1 <= port <= 65535:
                    raise ValueError("Invalid observed service")
                existed = self.connection.execute(
                    "SELECT 1 FROM services WHERE device_id=? AND address=? AND protocol=? AND port=? AND source=?",
                    (device_id, address, protocol, port, source),
                ).fetchone()
                self.connection.execute(
                    """INSERT INTO services
                       (device_id,address,protocol,port,service,source,first_observed,last_observed)
                       VALUES (?,?,?,?,?,?,?,?)
                       ON CONFLICT(device_id,address,protocol,port,source) DO UPDATE SET
                         service=excluded.service,last_observed=MAX(last_observed,excluded.last_observed)""",
                    (device_id, address, protocol, port, service, source, timestamp, timestamp),
                )
                recorded += 1
                if not existed:
                    self._record_event(
                        device_id, timestamp, "device.service_added", "New network service observed",
                        {"address": address, "protocol": protocol, "port": port, "service": service, "source": source},
                        f"service:{device_id}:{protocol}:{port}",
                    )
        return recorded

    def queue_diagnostic(self, device_id: str, address: str, kind: str, now: int | None = None) -> dict:
        if kind not in {"ping", "services", "exposure"}:
            raise ValueError("Unsupported diagnostic kind")
        device = self.get_device(device_id)
        if address not in {item["address"] for item in device["addresses"]}:
            raise ValueError("Diagnostic address does not belong to this device")
        existing = self.connection.execute(
            "SELECT id FROM diagnostic_jobs WHERE device_id=? AND address=? AND kind=? "
            "AND status IN ('queued','running') ORDER BY created_at LIMIT 1",
            (device_id, address, kind),
        ).fetchone()
        if existing:
            return self.get_diagnostic_job(str(existing["id"]))
        timestamp = int(now if now is not None else time.time())
        job_id = str(uuid.uuid4())
        with self.connection:
            self.connection.execute(
                "INSERT INTO diagnostic_jobs(id,device_id,address,kind,status,created_at) VALUES(?,?,?,?,?,?)",
                (job_id, device_id, address, kind, "queued", timestamp),
            )
        return self.get_diagnostic_job(job_id)

    def get_diagnostic_job(self, job_id: str) -> dict:
        row = self.connection.execute("SELECT * FROM diagnostic_jobs WHERE id=?", (job_id,)).fetchone()
        if not row:
            raise KeyError("Diagnostic job not found")
        result = dict(row)
        raw = result.pop("result_json")
        try:
            result["result"] = json.loads(raw) if raw else None
        except (json.JSONDecodeError, TypeError):
            result["result"] = None
        result["cancel_requested"] = bool(result["cancel_requested"])
        return result

    def list_diagnostic_jobs(self, device_id: str | None = None, limit: int = 100) -> list[dict]:
        if device_id:
            rows = self.connection.execute(
                "SELECT id FROM diagnostic_jobs WHERE device_id=? ORDER BY created_at DESC LIMIT ?",
                (device_id, max(1, min(int(limit), 500))),
            )
        else:
            rows = self.connection.execute(
                "SELECT id FROM diagnostic_jobs ORDER BY created_at DESC LIMIT ?",
                (max(1, min(int(limit), 500)),),
            )
        return [self.get_diagnostic_job(str(row["id"])) for row in rows]

    def request_diagnostic_cancel(self, job_id: str, now: int | None = None) -> dict:
        timestamp = int(now if now is not None else time.time())
        with self.connection:
            cursor = self.connection.execute(
                "UPDATE diagnostic_jobs SET cancel_requested=1, "
                "status=CASE WHEN status='queued' THEN 'cancelled' ELSE status END, "
                "finished_at=CASE WHEN status='queued' THEN ? ELSE finished_at END "
                "WHERE id=? AND status IN ('queued','running')",
                (timestamp, job_id),
            )
        if cursor.rowcount == 0:
            return self.get_diagnostic_job(job_id)
        return self.get_diagnostic_job(job_id)

    def claim_next_diagnostic(self, now: int | None = None) -> dict | None:
        timestamp = int(now if now is not None else time.time())
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute(
                "SELECT id FROM diagnostic_jobs WHERE status='queued' AND cancel_requested=0 "
                "ORDER BY created_at, id LIMIT 1"
            ).fetchone()
            if not row:
                self.connection.commit()
                return None
            self.connection.execute(
                "UPDATE diagnostic_jobs SET status='running',started_at=?,progress=5 WHERE id=?",
                (timestamp, row["id"]),
            )
            self.connection.commit()
        except BaseException:
            self.connection.rollback()
            raise
        return self.get_diagnostic_job(str(row["id"]))

    def diagnostic_cancel_requested(self, job_id: str) -> bool:
        row = self.connection.execute(
            "SELECT cancel_requested FROM diagnostic_jobs WHERE id=?", (job_id,)
        ).fetchone()
        return bool(row and row["cancel_requested"])

    def update_diagnostic_progress(self, job_id: str, progress: int) -> None:
        value = max(5, min(int(progress), 95))
        with self.connection:
            self.connection.execute(
                "UPDATE diagnostic_jobs SET progress=? WHERE id=? AND status='running'", (value, job_id)
            )

    def record_connectivity_success(self, device_id: str, observed_at: int | None = None) -> None:
        timestamp = int(observed_at if observed_at is not None else time.time())
        with self.connection:
            self.connection.execute(
                "UPDATE devices SET last_connectivity=MAX(COALESCE(last_connectivity,0),?),updated_at=MAX(updated_at,?) WHERE id=?",
                (timestamp, timestamp, device_id),
            )

    def finish_diagnostic(
        self,
        job_id: str,
        status: str,
        *,
        result: dict | None = None,
        error: str | None = None,
        now: int | None = None,
    ) -> dict:
        if status not in {"completed", "failed", "cancelled"}:
            raise ValueError("Invalid terminal diagnostic status")
        timestamp = int(now if now is not None else time.time())
        with self.connection:
            self.connection.execute(
                "UPDATE diagnostic_jobs SET status=?,progress=?,finished_at=?,result_json=?,error=? WHERE id=?",
                (
                    status, 100 if status == "completed" else 0, timestamp,
                    json.dumps(result, separators=(",", ":")) if result is not None else None,
                    error[:512] if error else None, job_id,
                ),
            )
            job = self.get_diagnostic_job(job_id)
            self._record_event(
                job["device_id"], timestamp, f"diagnostic.{status}",
                f"{job['kind'].capitalize()} diagnostic {status}",
                {"jobId": job_id, "kind": job["kind"], "address": job["address"]}, None,
            )
        return self.get_diagnostic_job(job_id)

    def queue_scan(
        self, network: str, interface: str, *, trigger: str = "manual", now: int | None = None
    ) -> dict:
        parsed = ipaddress.ip_network(network, strict=True)
        if parsed.version != 4 or parsed.num_addresses > 256 or not (parsed.is_private or parsed.is_link_local):
            raise ValueError("Scan network must be a private local IPv4 range of /24 or smaller")
        if not interface or len(interface) > 64 or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-" for ch in interface):
            raise ValueError("Invalid scan interface")
        if trigger not in {"manual", "scheduled"}:
            raise ValueError("Invalid scan trigger")
        existing = self.connection.execute(
            "SELECT id FROM scan_jobs WHERE status IN ('queued','running') ORDER BY created_at LIMIT 1"
        ).fetchone()
        if existing:
            return self.get_scan_job(str(existing["id"]))
        timestamp = int(now if now is not None else time.time())
        job_id = str(uuid.uuid4())
        with self.connection:
            self.connection.execute(
                "INSERT INTO scan_jobs(id,network,interface,trigger,status,created_at) VALUES(?,?,?,?,?,?)",
                (job_id, str(parsed), interface, trigger, "queued", timestamp),
            )
        return self.get_scan_job(job_id)

    def get_scan_job(self, job_id: str) -> dict:
        row = self.connection.execute("SELECT * FROM scan_jobs WHERE id=?", (job_id,)).fetchone()
        if not row:
            raise KeyError("Scan job not found")
        result = dict(row)
        raw = result.pop("result_json")
        try:
            result["result"] = json.loads(raw) if raw else None
        except (json.JSONDecodeError, TypeError):
            result["result"] = None
        result["cancel_requested"] = bool(result["cancel_requested"])
        return result

    def request_scan_cancel(self, job_id: str, now: int | None = None) -> dict:
        timestamp = int(now if now is not None else time.time())
        with self.connection:
            self.connection.execute(
                "UPDATE scan_jobs SET cancel_requested=1,"
                "status=CASE WHEN status='queued' THEN 'cancelled' ELSE status END,"
                "finished_at=CASE WHEN status='queued' THEN ? ELSE finished_at END "
                "WHERE id=? AND status IN ('queued','running')", (timestamp, job_id),
            )
        return self.get_scan_job(job_id)

    def claim_next_scan(self, now: int | None = None) -> dict | None:
        timestamp = int(now if now is not None else time.time())
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute(
                "SELECT id FROM scan_jobs WHERE status='queued' AND cancel_requested=0 ORDER BY created_at,id LIMIT 1"
            ).fetchone()
            if not row:
                self.connection.commit()
                return None
            self.connection.execute(
                "UPDATE scan_jobs SET status='running',started_at=?,progress=5 WHERE id=?",
                (timestamp, row["id"]),
            )
            self.connection.commit()
        except BaseException:
            self.connection.rollback()
            raise
        return self.get_scan_job(str(row["id"]))

    def scan_cancel_requested(self, job_id: str) -> bool:
        row = self.connection.execute("SELECT cancel_requested FROM scan_jobs WHERE id=?", (job_id,)).fetchone()
        return bool(row and row["cancel_requested"])

    def update_scan_progress(self, job_id: str, progress: int) -> None:
        with self.connection:
            self.connection.execute(
                "UPDATE scan_jobs SET progress=? WHERE id=? AND status='running'",
                (max(5, min(int(progress), 95)), job_id),
            )

    def finish_scan(
        self, job_id: str, status: str, *, result: dict | None = None,
        error: str | None = None, now: int | None = None,
    ) -> dict:
        if status not in {"completed", "failed", "cancelled"}:
            raise ValueError("Invalid terminal scan status")
        timestamp = int(now if now is not None else time.time())
        with self.connection:
            self.connection.execute(
                "UPDATE scan_jobs SET status=?,progress=?,finished_at=?,result_json=?,error=? WHERE id=?",
                (status, 100 if status == "completed" else 0, timestamp,
                 json.dumps(result, separators=(",", ":")) if result is not None else None,
                 error[:512] if error else None, job_id),
            )
            job = self.get_scan_job(job_id)
            self._record_event(
                None, timestamp, f"scan.{status}", f"Active discovery {status}",
                {"jobId": job_id, "network": job["network"], "trigger": job["trigger"]}, None,
            )
        return self.get_scan_job(job_id)

    def latest_scheduled_scan_time(self, network: str) -> int | None:
        row = self.connection.execute(
            "SELECT MAX(created_at) AS created_at FROM scan_jobs WHERE trigger='scheduled' AND network=?",
            (network,),
        ).fetchone()
        return int(row["created_at"]) if row and row["created_at"] is not None else None

    def counts(self, now: int | None = None) -> dict[str, int]:
        timestamp = int(now if now is not None else time.time())
        row = self.connection.execute(
            """SELECT
                 COUNT(*) AS total,
                 SUM(CASE WHEN last_active >= ? THEN 1 ELSE 0 END) AS recently_active,
                 SUM(CASE WHEN first_observed >= ? THEN 1 ELSE 0 END) AS new_24h,
                 SUM(CASE WHEN recognition = 'unrecognized' THEN 1 ELSE 0 END) AS unrecognized
               FROM devices""",
            (timestamp - 900, timestamp - 86400),
        ).fetchone()
        return {key: int(row[key] or 0) for key in row.keys()}
