"""Offline integrity, backup, and recovery commands for Cyber Scout data."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import sqlite3

from .database import DEFAULT_DATABASE, InventoryStore, SCHEMA_VERSION


def inspect_database(path: Path) -> dict:
    if not path.exists():
        raise ValueError(f"Database does not exist: {path}")
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        integrity = str(connection.execute("PRAGMA quick_check").fetchone()[0])
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    finally:
        connection.close()
    if integrity != "ok":
        raise ValueError(f"Database integrity check failed: {integrity}")
    if version > SCHEMA_VERSION:
        raise ValueError(f"Database schema {version} is newer than supported {SCHEMA_VERSION}")
    return {"path": str(path), "integrity": integrity, "schemaVersion": version, "bytes": path.stat().st_size}


def restore_database(database: Path, backup: Path) -> dict:
    source = inspect_database(backup)
    database.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    rollback = None
    if database.exists():
        try:
            inspect_database(database)
        except (OSError, sqlite3.Error, ValueError):
            backup_directory = database.parent / "backups"
            backup_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            rollback = backup_directory / f"{database.stem}-corrupt-pre-restore-{os.getpid()}.db"
            shutil.copyfile(database, rollback)
            rollback.chmod(0o600)
        else:
            with InventoryStore(database) as store:
                rollback = store.create_backup(reason="pre-restore")
    temporary = database.with_suffix(".restore.tmp")
    try:
        shutil.copyfile(backup, temporary)
        temporary.chmod(0o600)
        os.replace(temporary, database)
        for suffix in ("-wal", "-shm"):
            try:
                Path(str(database) + suffix).unlink()
            except FileNotFoundError:
                pass
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    restored = inspect_database(database)
    return {"restored": restored, "source": source, "rollbackBackup": str(rollback) if rollback else None}


def main() -> int:
    parser = argparse.ArgumentParser(description="Cyber Scout database maintenance")
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("verify")
    commands.add_parser("backup")
    restore = commands.add_parser("restore")
    restore.add_argument("backup", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "verify":
            result = inspect_database(args.database)
        elif args.command == "backup":
            with InventoryStore(args.database) as store:
                destination = store.create_backup(reason="manual")
            result = inspect_database(destination)
        else:
            result = restore_database(args.database, args.backup)
        print(json.dumps({"ok": True, "result": result}, separators=(",", ":")))
        return 0
    except (OSError, RuntimeError, sqlite3.Error, ValueError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
