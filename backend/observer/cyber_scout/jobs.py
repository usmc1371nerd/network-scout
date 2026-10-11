"""Bounded asynchronous diagnostic worker with cooperative cancellation."""

from __future__ import annotations

import fcntl
import json
from pathlib import Path
import re
import subprocess
import sys
import time

from .database import DEFAULT_DATABASE, InventoryStore
from .config import ConfigManager
from .diagnostics import explain_open_port, summarize_findings
from .discovery import PassiveDiscoveryManager
from .runtime import runtime_logger

WORKER_LOCK = Path.home() / ".cache" / "cyber-scout" / "diagnostic-worker.lock"
SAFETY_PORTS = {
    21: ("FTP", "higher"), 22: ("SSH", "review"), 23: ("Telnet", "higher"),
    25: ("SMTP", "review"), 53: ("DNS", "review"), 80: ("HTTP", "review"),
    111: ("RPC", "higher"), 135: ("MS RPC", "higher"), 139: ("NetBIOS", "higher"),
    443: ("HTTPS", "review"), 445: ("SMB", "higher"), 554: ("RTSP", "review"),
    631: ("Printing", "review"), 1433: ("SQL Server", "higher"),
    3306: ("MySQL", "higher"), 3389: ("Remote Desktop", "higher"),
    5432: ("PostgreSQL", "higher"), 5900: ("VNC", "higher"),
    8080: ("HTTP alternate", "review"), 8443: ("HTTPS alternate", "review"),
}


def command_for(job: dict) -> tuple[list[str], int]:
    address, kind = job["address"], job["kind"]
    if kind == "ping":
        return ["ping", "-n", "-c", "4", "-W", "1", address], 8
    if kind == "services":
        return ["nmap", "-sT", "-n", "--top-ports", "20", "--host-timeout", "8s", address], 12
    if kind == "exposure":
        ports = ",".join(str(port) for port in SAFETY_PORTS)
        return ["nmap", "-sT", "-Pn", "-n", "--max-retries", "1", "--host-timeout", "10s", "-p", ports, address], 14
    raise ValueError("Unsupported diagnostic kind")


def parse_result(kind: str, output: str, returncode: int) -> dict:
    if kind == "ping":
        summary = re.search(r"(\d+) packets transmitted, (\d+) received.*?(\d+(?:\.\d+)?)% packet loss", output)
        timing = re.search(r"= [\d.]+/([\d.]+)/[\d.]+/[\d.]+ ms", output)
        if summary:
            text = f"The device answered {summary.group(2)} of {summary.group(1)} connectivity checks with {summary.group(3)}% packet loss."
        else:
            text = "The device did not answer the connectivity test. Some devices block these requests, so this does not necessarily mean the device is disconnected."
        if timing:
            text += f" Average round-trip latency was {timing.group(1)} ms."
        return {"ok": returncode == 0, "summary": text, "technicalDetails": {"returnCode": returncode}}

    matches = list(re.finditer(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)", output, re.M))
    services = [{"port": int(match.group(1)), "protocol": match.group(2), "service": match.group(3)} for match in matches]
    if kind == "services":
        text = ("Reachable services: " + ", ".join(f"{x['port']}/{x['protocol']} {x['service']}" for x in services)) if services else (
            "No common TCP services accepted a connection. Filtering or timeout can hide a service, so this is not proof that none exist."
        )
        return {"ok": returncode == 0, "summary": text, "services": services, "technicalDetails": {"returnCode": returncode}}

    findings = []
    for service in services:
        if service["port"] in SAFETY_PORTS:
            label, level = SAFETY_PORTS[service["port"]]
            findings.append(explain_open_port(service["port"], label, level))
    return {
        "ok": returncode == 0,
        "summary": summarize_findings(findings),
        "findings": findings,
        "services": services,
        "technicalDetails": {"returnCode": returncode},
    }


def execute_job(store: InventoryStore, job: dict) -> None:
    command, timeout = command_for(job)
    try:
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, shell=False,
        )
    except OSError as error:
        store.finish_diagnostic(job["id"], "failed", error=f"Diagnostic tool unavailable: {error}")
        return
    deadline = time.monotonic() + timeout
    started = time.monotonic()
    next_progress = started
    cancelled = False
    timed_out = False
    while process.poll() is None:
        if store.diagnostic_cancel_requested(job["id"]):
            cancelled = True
            process.terminate()
            break
        if time.monotonic() >= deadline:
            timed_out = True
            process.terminate()
            break
        if time.monotonic() >= next_progress:
            elapsed = time.monotonic() - started
            store.update_diagnostic_progress(job["id"], 10 + int(80 * elapsed / timeout))
            next_progress = time.monotonic() + 1
        time.sleep(0.1)
    try:
        output, _ = process.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        output, _ = process.communicate(timeout=2)
    output = output[:262144]
    if cancelled:
        store.finish_diagnostic(job["id"], "cancelled", error="Cancelled by user")
        return
    if timed_out:
        store.finish_diagnostic(job["id"], "failed", error="Diagnostic timed out; no offline conclusion was made")
        return
    result = parse_result(job["kind"], output, int(process.returncode or 0))
    if job["kind"] == "ping" and result["ok"]:
        store.record_connectivity_success(job["device_id"])
    if job["kind"] in {"services", "exposure"} and result.get("services"):
        store.record_services_for_address(job["address"], result["services"], source=f"diagnostic_{job['kind']}")
    status = "completed" if result["ok"] or job["kind"] == "ping" else "failed"
    store.finish_diagnostic(
        job["id"], status, result=result if status == "completed" else None,
        error=None if status == "completed" else "Diagnostic tool returned an error; no conclusion was recorded",
    )


def scan_command(job: dict) -> tuple[list[str], int]:
    config = ConfigManager().load()
    timeout = max(15, min(120, config.active_timeout_seconds * 5))
    return [
        "nmap", "-sn", "-n", "--max-retries", "1",
        "--host-timeout", f"{config.active_timeout_seconds}s",
        "--max-rate", str(config.active_rate_limit), job["network"],
    ], timeout


def execute_scan(store: InventoryStore, job: dict) -> None:
    command, timeout = scan_command(job)
    try:
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, shell=False,
        )
    except OSError as error:
        store.finish_scan(job["id"], "failed", error=f"Nmap unavailable: {error}")
        return
    started = time.monotonic()
    deadline = started + timeout
    next_progress = started
    cancelled = timed_out = False
    while process.poll() is None:
        if store.scan_cancel_requested(job["id"]):
            cancelled = True
            process.terminate()
            break
        now = time.monotonic()
        if now >= deadline:
            timed_out = True
            process.terminate()
            break
        if now >= next_progress:
            store.update_scan_progress(job["id"], 10 + int(80 * (now - started) / timeout))
            next_progress = now + 1
        time.sleep(0.1)
    try:
        output, _ = process.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        output, _ = process.communicate(timeout=2)
    output = output[:524288]
    if cancelled:
        store.finish_scan(job["id"], "cancelled", error="Cancelled by user")
        return
    if timed_out:
        store.finish_scan(job["id"], "failed", error="Discovery timed out; devices were not marked offline")
        return
    if process.returncode != 0:
        store.finish_scan(job["id"], "failed", error="Nmap discovery failed; no offline conclusion was made")
        return
    addresses = []
    for match in re.finditer(r"^Nmap scan report for ([0-9.]+)$", output, re.M):
        addresses.append(match.group(1))
    reconciliation = PassiveDiscoveryManager(store).observe_once()
    store.finish_scan(job["id"], "completed", result={
        "summary": f"Discovery observed {len(addresses)} responding IPv4 addresses. Devices that did not respond may still be connected.",
        "addresses": addresses,
        "reconciliation": reconciliation,
    })


def run_worker(database_path: str | Path = DEFAULT_DATABASE) -> int:
    logger = runtime_logger("worker")
    WORKER_LOCK.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with WORKER_LOCK.open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            logger.info("worker already running")
            return 0
        with InventoryStore(database_path) as store:
            logger.info("worker started")
            while True:
                job = store.claim_next_diagnostic()
                if job:
                    logger.info("diagnostic started id=%s kind=%s", job["id"], job["kind"])
                    execute_job(store, job)
                    logger.info("diagnostic finished id=%s", job["id"])
                    continue
                scan = store.claim_next_scan()
                if scan:
                    logger.info("scan started id=%s trigger=%s", scan["id"], scan["trigger"])
                    execute_scan(store, scan)
                    logger.info("scan finished id=%s", scan["id"])
                    continue
                logger.info("worker stopped")
                return 0


def main() -> int:
    if len(sys.argv) not in {2, 3} or sys.argv[1] != "worker":
        print(json.dumps({"error": "Usage: python -m cyber_scout.jobs worker [database]"}))
        return 2
    return run_worker(sys.argv[2] if len(sys.argv) == 3 else DEFAULT_DATABASE)


if __name__ == "__main__":
    raise SystemExit(main())
