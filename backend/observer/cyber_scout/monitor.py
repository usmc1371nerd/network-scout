"""Single-instance unprivileged passive observation loop."""

from __future__ import annotations

import argparse
import fcntl
import json
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path

from .config import ConfigManager
from .database import DEFAULT_DATABASE, InventoryStore
from .discovery import NeighborEventAdapter, PassiveDiscoveryManager
from .runtime import runtime_logger
from .scheduling import approved_local_scan_targets
from .sensors import SensorLogIngestor

DEFAULT_LOCK = Path.home() / ".cache" / "cyber-scout" / "passive-monitor.lock"


def enqueue_due_scheduled_scans(store: InventoryStore, config, now: int | None = None) -> int:
    timestamp = int(now if now is not None else time.time())
    queued = 0
    for interface, network in approved_local_scan_targets(config):
        last = store.latest_scheduled_scan_time(network)
        if last is not None and timestamp - last < config.scheduled_scan_minutes * 60:
            continue
        store.queue_scan(network, interface, trigger="scheduled", now=timestamp)
        queued += 1
    if queued:
        subprocess.Popen(
            [sys.executable, "-B", "-m", "cyber_scout.jobs", "worker"],
            cwd=Path(__file__).parent.parent,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True, close_fds=True,
        )
    return queued


def run(*, once: bool = False, config_path: str | None = None, database_path: str | None = None) -> int:
    config_manager = ConfigManager(config_path) if config_path else ConfigManager()
    config = config_manager.load()
    logger = runtime_logger("monitor")

    def emit(value: dict) -> None:
        print(json.dumps(value, separators=(",", ":")), flush=True)
        logger.info(json.dumps(value, separators=(",", ":")))

    lock_path = DEFAULT_LOCK
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with lock_path.open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            emit({"status": "already_running"})
            return 2
        stopping = False

        def stop(_signum: int, _frame: object) -> None:
            nonlocal stopping
            stopping = True

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        with InventoryStore(database_path or DEFAULT_DATABASE) as store:
            manager = PassiveDiscoveryManager(store)
            result = manager.observe_once()
            result["sensors"] = SensorLogIngestor(store).ingest_configured(config)
            result["retention"] = store.prune(config.retention_days)
            result["scheduledScansQueued"] = enqueue_due_scheduled_scans(store, config)
            emit(result)
            if once:
                return 0

            process: subprocess.Popen[str] | None = None
            selector = selectors.DefaultSelector()
            next_snapshot = time.monotonic() + config.passive_interval_seconds
            next_restart = 0.0
            try:
                while not stopping:
                    now = time.monotonic()
                    if process is None and now >= next_restart:
                        try:
                            process = subprocess.Popen(
                                NeighborEventAdapter.command,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL,
                                text=True,
                                bufsize=1,
                                shell=False,
                            )
                            if process.stdout is not None:
                                selector.register(process.stdout, selectors.EVENT_READ)
                        except OSError as error:
                            emit({"source": "neighbor_event", "error": str(error)[:256]})
                            process = None
                            next_restart = now + 30

                    timeout = max(0.0, min(0.5, next_snapshot - now))
                    for key, _mask in selector.select(timeout):
                        line = key.fileobj.readline()
                        if line:
                            observation = NeighborEventAdapter.parse_line(line, int(time.time()))
                            if observation:
                                device_id = store.ingest(observation)
                                emit({
                                    "source": "neighbor_event", "observedAt": observation.observed_at,
                                    "assigned": bool(device_id), "state": observation.state,
                                })
                        elif process is not None:
                            selector.unregister(key.fileobj)
                            process.wait(timeout=1)
                            process = None
                            next_restart = time.monotonic() + 30

                    if time.monotonic() >= next_snapshot:
                        config = config_manager.load()
                        result = manager.observe_once()
                        result["sensors"] = SensorLogIngestor(store).ingest_configured(config)
                        result["retention"] = store.prune(config.retention_days)
                        result["scheduledScansQueued"] = enqueue_due_scheduled_scans(store, config)
                        emit(result)
                        next_snapshot = time.monotonic() + config.passive_interval_seconds
            finally:
                selector.close()
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=2)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Cyber Scout passive LAN observer")
    parser.add_argument("--once", action="store_true", help="observe once and exit")
    parser.add_argument("--config", help="alternate configuration file")
    parser.add_argument("--database", help="alternate database file")
    args = parser.parse_args()
    return run(once=args.once, config_path=args.config, database_path=args.database)


if __name__ == "__main__":
    raise SystemExit(main())
