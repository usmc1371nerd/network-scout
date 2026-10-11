from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import threading
import urllib.error
import urllib.request
from urllib.parse import quote
from http.server import ThreadingHTTPServer

from cyber_scout.config import ConfigManager, CyberScoutConfig
from cyber_scout.database import InventoryStore, SCHEMA_VERSION
from cyber_scout.discovery import NeighborEventAdapter, NeighborTableAdapter
from cyber_scout.diagnostics import explain_open_port, summarize_findings
from cyber_scout.dashboard import dashboard_snapshot, make_handler
from cyber_scout.api_v1 import ApiValidationError, inventory_devices, parse_inventory_query
from cyber_scout.jobs import command_for, parse_result
from cyber_scout.maintenance import inspect_database, restore_database
from cyber_scout import __version__, jobs
from cyber_scout.runtime import runtime_logger
from cyber_scout.scheduling import approved_local_scan_targets
from cyber_scout.models import Observation, is_locally_administered, normalize_mac
from cyber_scout.scope import current_ipv4_scopes
from cyber_scout.security import allowed_authority, allowed_origin, load_or_create_session_secret, token_matches
from cyber_scout.sensors import SensorLogIngestor, parse_suricata_eve, parse_zeek_json


def test_mac_normalization_and_randomized_detection() -> None:
    assert normalize_mac("aa-bb-cc-dd-ee-ff") == "AA:BB:CC:DD:EE:FF"
    assert normalize_mac("not-a-mac") is None
    assert is_locally_administered("02:00:00:00:00:01")
    assert not is_locally_administered("00:11:22:33:44:55")


def test_package_and_plugin_versions_match() -> None:
    manifest = json.loads((Path(__file__).parent.parent / "manifest.json").read_text())
    assert __version__ == manifest["version"]


def test_exact_mac_deduplicates_and_records_ip_change(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        first = Observation("neighbor_table", "eth0", "192.168.1.10", "00:11:22:33:44:55", observed_at=100)
        second = Observation("neighbor_table", "eth0", "192.168.1.20", "00:11:22:33:44:55", observed_at=200)
        assert store.ingest(first) == store.ingest(second)
        assert store.connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1
        assert store.connection.execute("SELECT COUNT(*) FROM addresses").fetchone()[0] == 2
        assert store.connection.execute(
            "SELECT COUNT(*) FROM events WHERE event_type = 'device.address_added'"
        ).fetchone()[0] == 1


def test_address_without_mac_is_not_merged_into_device(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        observation = Observation("mdns", "eth0", "192.168.1.30", hostname="speaker.local", observed_at=100)
        assert store.ingest(observation) is None
        assert store.connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 0
        assert store.connection.execute("SELECT COUNT(*) FROM observations").fetchone()[0] == 1


def test_identity_evidence_records_source_and_conservative_confidence(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        device_id = store.ingest(Observation(
            "neighbor_table", "wlan0", "192.168.1.30", "02:00:00:00:00:01",
            hostname="phone.local", observed_at=100,
        ))
        report = store.get_device(device_id)
        evidence = {item["evidence_type"]: item for item in report["identity_evidence"]}
        assert evidence["mac"]["source"] == "neighbor_table"
        assert evidence["mac"]["confidence"] == 0.55
        assert evidence["mac"]["details"] == {"randomized": True}
        assert evidence["hostname"]["value"] == "phone.local"
        assert evidence["hostname"]["confidence"] == 0.65


def test_address_reuse_records_conflict_without_merging_devices(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        first = store.ingest(Observation(
            "neighbor_table", "eth0", "192.168.1.40", "00:11:22:33:44:55", observed_at=100,
        ))
        second = store.ingest(Observation(
            "neighbor_table", "eth0", "192.168.1.40", "00:11:22:33:44:66", observed_at=200,
        ))
        store.ingest(Observation(
            "neighbor_table", "eth0", "192.168.1.40", "00:11:22:33:44:66", observed_at=300,
        ))
        assert first != second
        assert store.connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 2
        conflict = store.get_device(second)["identity_conflicts"][0]
        assert conflict["value"] == "192.168.1.40"
        assert conflict["occurrences"] == 2


def test_enrichment_records_inference_sources(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        device_id = store.ingest(Observation(
            "neighbor_table", "eth0", "192.168.1.50", "00:11:22:33:44:55", observed_at=100,
        ))
        assert store.enrich_device_by_mac(
            "00:11:22:33:44:55", manufacturer="Example Corp", category="Computer",
        )
        evidence = {(item["evidence_type"], item["source"]): item
                    for item in store.get_device(device_id)["identity_evidence"]}
        assert evidence[("manufacturer", "oui_database")]["confidence"] == 0.70
        assert evidence[("classification", "name_vendor_heuristic")]["confidence"] == 0.50


def test_stale_neighbor_is_observed_but_not_active(tmp_path) -> None:
    rows = [{"dst": "192.168.1.40", "dev": "eth0", "lladdr": "00:11:22:33:44:66", "state": ["STALE"]}]
    observations = NeighborTableAdapter.parse(rows, 123)
    assert len(observations) == 1
    assert not observations[0].active
    with InventoryStore(tmp_path / "inventory.db") as store:
        device_id = store.ingest(observations[0])
        row = store.connection.execute("SELECT last_observed, last_active FROM devices WHERE id = ?", (device_id,)).fetchone()
        assert row["last_observed"] == 123
        assert row["last_active"] is None


def test_failed_neighbor_is_not_treated_as_device() -> None:
    rows = [{"dst": "192.168.1.50", "dev": "eth0", "state": ["FAILED"]}]
    assert NeighborTableAdapter.parse(rows, 123) == []


def test_neighbor_event_parser_handles_activity_and_unsafe_states() -> None:
    observed = NeighborEventAdapter.parse_line(
        "192.168.1.44 dev wlp1s0 lladdr aa:bb:cc:dd:ee:ff REACHABLE", 123
    )
    assert observed is not None
    assert observed.source == "neighbor_event"
    assert observed.active
    assert observed.mac == "AA:BB:CC:DD:EE:FF"
    assert NeighborEventAdapter.parse_line(
        "Deleted 192.168.1.44 dev wlp1s0 lladdr aa:bb:cc:dd:ee:ff STALE", 123
    ) is None
    assert NeighborEventAdapter.parse_line(
        "192.168.1.44 dev wlp1s0 lladdr aa:bb:cc:dd:ee:ff FAILED", 123
    ) is None


def test_schema_migration_is_idempotent(tmp_path) -> None:
    path = tmp_path / "inventory.db"
    with InventoryStore(path):
        pass
    with InventoryStore(path) as store:
        version = store.connection.execute("PRAGMA user_version").fetchone()[0]
        assert version == SCHEMA_VERSION
        assert path.stat().st_mode & 0o777 == 0o600


def test_dashboard_session_secret_is_private_and_stable(tmp_path) -> None:
    path = tmp_path / "state" / "dashboard-session"
    first = load_or_create_session_secret(path)
    second = load_or_create_session_secret(path)
    assert first == second
    assert len(first) >= 43
    assert path.stat().st_mode & 0o077 == 0
    assert token_matches(first, second)
    assert not token_matches("wrong", second)


def test_dashboard_authority_and_origin_are_exact() -> None:
    assert allowed_authority("127.0.0.1:8765", 8765)
    assert allowed_authority("[::1]:8765", 8765)
    assert not allowed_authority("attacker.example:8765", 8765)
    assert allowed_origin("http://127.0.0.1:8765", 8765)
    assert not allowed_origin("https://attacker.example", 8765)


def test_authorization_decision_is_persisted(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        decision_id = store.record_authorization_decision(
            "settings.write", "settings", request_context={"origin": "http://127.0.0.1:8765"},
            decided_at=123,
        )
        row = store.connection.execute(
            "SELECT * FROM authorization_decisions WHERE id=?", (decision_id,)
        ).fetchone()
        assert row["decision"] == "allow"
        assert row["capability"] == "settings.write"


def test_dashboard_api_requires_session_and_exact_authority(tmp_path) -> None:
    token = "test-session-token-that-is-long-enough-for-authentication"
    handler = make_handler(tmp_path / "inventory.db", tmp_path / "config.json", session_token=token)
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/api/session"
    try:
        try:
            urllib.request.urlopen(url)
            assert False, "unauthenticated request unexpectedly succeeded"
        except urllib.error.HTTPError as error:
            assert error.code == 401
        request = urllib.request.Request(url, headers={"X-Cyber-Scout-Token": token})
        with urllib.request.urlopen(request) as response:
            payload = json.loads(response.read())
        assert "csrfToken" not in payload
        bad_host = urllib.request.Request(
            url, headers={"Host": f"attacker.example:{server.server_port}", "X-Cyber-Scout-Token": token}
        )
        try:
            urllib.request.urlopen(bad_host)
            assert False, "invalid authority unexpectedly succeeded"
        except urllib.error.HTTPError as error:
            assert error.code == 421
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_v1_inventory_projection_is_authenticated_bounded_and_preserves_ids(tmp_path) -> None:
    token = "test-session-token-that-is-long-enough-for-authentication"
    database = tmp_path / "inventory.db"
    with InventoryStore(database) as store:
        first_id = store.ingest(Observation(
            "neighbor_table", "eth0", "192.168.1.20", "00:11:22:33:44:55",
            hostname="printer.local", observed_at=int(__import__("time").time()),
        ))
        store.update_device(first_id, user_name="<img src=x onerror=alert(1)>", category="Printer")
        store.ingest(Observation(
            "neighbor_table", "eth0", "192.168.1.30", "00:11:22:33:44:66", observed_at=100,
        ))
    handler = make_handler(database, tmp_path / "config.json", session_token=token)
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/api/v1/inventory/devices?limit=1"
    try:
        try:
            urllib.request.urlopen(url)
            assert False, "unauthenticated inventory read unexpectedly succeeded"
        except urllib.error.HTTPError as error:
            assert error.code == 401
            assert json.loads(error.read())["error"]["code"] == "authentication_required"
        request = urllib.request.Request(url, headers={"X-Network-Scout-Token": token})
        with urllib.request.urlopen(request) as response:
            first_page = json.loads(response.read())
        assert len(first_page["items"]) == 1
        assert first_page["nextCursor"]
        assert first_page["items"][0]["id"] == first_id
        assert first_page["items"][0]["displayName"] == "<img src=x onerror=alert(1)>"
        next_url = url + "&cursor=" + quote(first_page["nextCursor"])
        with urllib.request.urlopen(urllib.request.Request(
            next_url, headers={"X-Network-Scout-Token": token}
        )) as response:
            second_page = json.loads(response.read())
        assert len(second_page["items"]) == 1
        assert second_page["items"][0]["id"] != first_id
        bad_host = urllib.request.Request(
            url, headers={"Host": f"attacker.example:{server.server_port}", "X-Network-Scout-Token": token}
        )
        try:
            urllib.request.urlopen(bad_host)
            assert False, "invalid authority unexpectedly succeeded"
        except urllib.error.HTTPError as error:
            assert error.code == 421
            assert json.loads(error.read())["error"]["code"] == "invalid_authority"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_v1_inventory_rejects_invalid_pagination_and_cursor_mismatch(tmp_path) -> None:
    for query, field in (({"limit": ["0"]}, "limit"), ({"limit": ["251"]}, "limit"),
                         ({"limit": ["nope"]}, "limit"), ({"limit": ["1", "2"]}, "limit"),
                         ({"extra": ["1"]}, "extra")):
        try:
            parse_inventory_query(query)
        except ApiValidationError as error:
            assert error.field == field
        else:
            raise AssertionError("invalid query unexpectedly accepted")
    with InventoryStore(tmp_path / "inventory.db") as store:
        device_id = store.ingest(Observation(
            "neighbor_table", "eth0", "192.168.1.20", "00:11:22:33:44:55", observed_at=100,
        ))
        first = inventory_devices(store, {"limit": ["1"]}, now=200)
        assert first["items"][0]["id"] == device_id
        if first["nextCursor"]:
            try:
                inventory_devices(store, {"limit": ["1"], "search": ["different"],
                                          "cursor": [first["nextCursor"]]}, now=200)
            except ApiValidationError as error:
                assert error.code == "invalid_cursor"
            else:
                raise AssertionError("cursor from different filters unexpectedly accepted")


def test_consistent_backup_and_validated_restore(tmp_path) -> None:
    path = tmp_path / "inventory.db"
    with InventoryStore(path) as store:
        store.ingest(Observation(
            "neighbor_table", "eth0", "192.168.1.20", "00:11:22:33:44:55", observed_at=100,
        ))
        backup = store.create_backup(reason="test")
        store.ingest(Observation(
            "neighbor_table", "eth0", "192.168.1.30", "00:11:22:33:44:66", observed_at=200,
        ))
    assert inspect_database(backup)["integrity"] == "ok"
    result = restore_database(path, backup)
    assert result["rollbackBackup"]
    with InventoryStore(path) as restored:
        assert restored.connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1


def test_corrupt_database_is_rejected_before_migration(tmp_path) -> None:
    path = tmp_path / "inventory.db"
    path.write_bytes(b"not sqlite")
    try:
        InventoryStore(path)
    except (RuntimeError, sqlite3.DatabaseError):
        pass
    else:
        raise AssertionError("corrupt database should be rejected")


def test_restore_replaces_corrupt_database_and_preserves_it(tmp_path) -> None:
    database = tmp_path / "inventory.db"
    source = tmp_path / "known-good.db"
    with InventoryStore(source) as store:
        store.ingest(Observation(
            "neighbor_table", "eth0", "10.0.0.20", "00:11:22:33:44:55", observed_at=100,
        ))
    database.write_bytes(b"corrupt inventory")
    result = restore_database(database, source)
    rollback = Path(result["rollbackBackup"])
    assert rollback.read_bytes() == b"corrupt inventory"
    assert inspect_database(database)["integrity"] == "ok"


def test_runtime_logs_are_json_and_rotate(tmp_path) -> None:
    logger = runtime_logger("rotation-test", tmp_path, max_bytes=256, backup_count=2)
    for index in range(20):
        logger.info("bounded event %s %s", index, "x" * 80)
    for handler in logger.handlers:
        handler.flush()
        handler.close()
    logger.handlers.clear()
    logs = sorted(tmp_path.glob("rotation-test.jsonl*"))
    assert 2 <= len(logs) <= 3
    for line in logs[0].read_text().splitlines():
        payload = json.loads(line)
        assert payload["component"] == "cyber_scout.rotation-test"
        assert payload["level"] == "info"
    assert (tmp_path / "rotation-test.jsonl").stat().st_mode & 0o777 == 0o600


def test_user_service_templates_apply_security_and_resource_limits() -> None:
    root = Path(__file__).parent.parent
    for template in (root / "packaging" / "systemd").glob("*.service.in"):
        content = template.read_text()
        assert "NoNewPrivileges=yes" in content
        assert "ProtectSystem=strict" in content
        assert "MemoryMax=" in content
        assert "CPUQuota=" in content
        assert "LimitNOFILE=" in content
        assert "UMask=0077" in content


def test_newer_schema_is_rejected(tmp_path) -> None:
    path = tmp_path / "inventory.db"
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA user_version = 99")
    connection.close()
    try:
        InventoryStore(path)
    except RuntimeError as error:
        assert "newer than supported" in str(error)
    else:
        raise AssertionError("newer schema should be rejected")


def test_configuration_is_local_only_and_active_scanning_defaults_off(tmp_path) -> None:
    manager = ConfigManager(tmp_path / "config.json")
    default = manager.load()
    assert not default.active_discovery_enabled
    assert default.approved_networks == ()
    assert not default.allows_target("192.168.1.10")

    config = CyberScoutConfig(approved_networks=("192.168.1.0/24", "fe80::/64"))
    manager.save(config)
    loaded = manager.load()
    assert loaded.allows_target("192.168.1.10")
    assert loaded.allows_target("fe80::1")
    assert not loaded.allows_target("8.8.8.8")
    assert manager.path.stat().st_mode & 0o777 == 0o600


def test_public_scan_network_is_rejected() -> None:
    try:
        CyberScoutConfig.from_mapping({"approved_networks": ["8.8.8.0/24"]})
    except ValueError as error:
        assert "private or link-local" in str(error)
    else:
        raise AssertionError("public scan range should be rejected")


def test_enrichment_preserves_user_category(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        observation = Observation("neighbor_table", "eth0", "192.168.1.1", "00:11:22:33:44:55", observed_at=100)
        device_id = store.ingest(observation)
        assert store.enrich_device_by_mac(
            "00:11:22:33:44:55", user_name="Gateway", manufacturer="Example", category="Router"
        )
        store.connection.execute("UPDATE devices SET category = 'Server' WHERE id = ?", (device_id,))
        store.connection.commit()
        store.enrich_device_by_mac("00:11:22:33:44:55", category="Router")
        row = store.connection.execute(
            "SELECT user_name, manufacturer, category FROM devices WHERE id = ?", (device_id,)
        ).fetchone()
        assert tuple(row) == ("Gateway", "Example", "Server")


def test_device_management_and_change_queries(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        device_id = store.ingest(
            Observation("neighbor_table", "eth0", "192.168.1.20", "00:11:22:33:44:55", observed_at=100)
        )
        updated = store.update_device(
            device_id, user_name=" Office   computer ", category="Computer",
            recognition="recognized", notes="Trusted workstation", occurred_at=200,
        )
        assert updated["user_name"] == "Office computer"
        assert updated["recognition"] == "recognized"
        assert store.list_devices(search="office", recognition="recognized")[0]["id"] == device_id
        summary = store.change_summary(0, 300)
        assert summary["counts"]["device.first_observed"] == 1
        assert summary["counts"]["device.user_updated"] == 1
        assert store.get_device_by_mac("00:11:22:33:44:55")["id"] == device_id


def test_invalid_device_management_values_are_rejected(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        device_id = store.ingest(
            Observation("neighbor_table", "eth0", "192.168.1.20", "00:11:22:33:44:55", observed_at=100)
        )
        for field, value in (("category", "Laptop"), ("recognition", "evil")):
            try:
                store.update_device(device_id, **{field: value})
            except ValueError:
                pass
            else:
                raise AssertionError(f"invalid {field} should be rejected")


def test_notes_are_sanitized_and_bounded(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        device_id = store.ingest(
            Observation("neighbor_table", "eth0", "192.168.1.20", "00:11:22:33:44:55", observed_at=100)
        )
        assert store.update_device(device_id, notes="  Office\n workstation  ")["notes"] == "Office workstation"
        try:
            store.update_device(device_id, notes="x" * 2001)
        except ValueError as error:
            assert "2000" in str(error)
        else:
            raise AssertionError("oversized notes should be rejected")


def test_retention_prunes_history_not_inventory(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        store.ingest(Observation("neighbor_table", "eth0", "192.168.1.20", "00:11:22:33:44:55", observed_at=100))
        removed = store.prune(1, now=200000)
        assert removed["observations"] == 1
        assert removed["events"] == 1
        assert store.connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1


def test_service_history_and_event_deduplication(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        store.ingest(Observation("neighbor_table", "eth0", "192.168.1.20", "00:11:22:33:44:55", observed_at=100))
        services = [{"port": 22, "protocol": "tcp", "service": "SSH"}]
        assert store.record_services_for_address("192.168.1.20", services, source="test", observed_at=200) == 1
        assert store.record_services_for_address("192.168.1.20", services, source="test", observed_at=300) == 1
        assert store.connection.execute("SELECT COUNT(*) FROM services").fetchone()[0] == 1
        assert store.connection.execute("SELECT COUNT(*) FROM events WHERE event_type='device.service_added'").fetchone()[0] == 1


def test_plain_english_port_explanation_separates_evidence_and_advice() -> None:
    finding = explain_open_port(23, "Telnet", "higher")
    assert "accepted a connection" in finding["observation"]
    assert "without encryption" in finding["meaning"]
    assert finding["technicalDetails"] == {"protocol": "tcp", "port": 23, "service": "Telnet", "state": "open"}
    assert "not confirmation" in summarize_findings([finding])


def test_diagnostic_queue_deduplicates_and_cancels(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        device_id = store.ingest(
            Observation("neighbor_table", "eth0", "192.168.1.20", "00:11:22:33:44:55", observed_at=100)
        )
        first = store.queue_diagnostic(device_id, "192.168.1.20", "exposure", now=200)
        second = store.queue_diagnostic(device_id, "192.168.1.20", "exposure", now=201)
        assert first["id"] == second["id"]
        assert store.claim_next_diagnostic(now=202)["status"] == "running"
        assert store.request_diagnostic_cancel(first["id"], now=203)["cancel_requested"]
        assert store.diagnostic_cancel_requested(first["id"])
        finished = store.finish_diagnostic(first["id"], "cancelled", error="Cancelled", now=204)
        assert finished["status"] == "cancelled"


def test_diagnostic_queue_rejects_wrong_device_address(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        device_id = store.ingest(
            Observation("neighbor_table", "eth0", "192.168.1.20", "00:11:22:33:44:55", observed_at=100)
        )
        try:
            store.queue_diagnostic(device_id, "192.168.1.99", "ping")
        except ValueError as error:
            assert "does not belong" in str(error)
        else:
            raise AssertionError("cross-device target should be rejected")


def test_diagnostic_command_and_result_parsing_are_bounded() -> None:
    job = {"kind": "services", "address": "192.168.1.20"}
    command, timeout = command_for(job)
    assert command[-1] == "192.168.1.20"
    assert command[:3] == ["nmap", "-sT", "-n"]
    assert timeout <= 14
    result = parse_result("services", "22/tcp open ssh\n80/tcp open http\n", 0)
    assert result["services"][0] == {"port": 22, "protocol": "tcp", "service": "ssh"}


def test_worker_completes_mocked_ping_and_records_connectivity(tmp_path, monkeypatch) -> None:
    class FakeProcess:
        returncode = 0
        def poll(self):
            return 0
        def communicate(self, timeout=None):
            return ("4 packets transmitted, 4 received, 0% packet loss\nrtt min/avg/max/mdev = 1.0/2.0/3.0/0.1 ms\n", None)

    monkeypatch.setattr(jobs.subprocess, "Popen", lambda *args, **kwargs: FakeProcess())
    with InventoryStore(tmp_path / "inventory.db") as store:
        device_id = store.ingest(
            Observation("neighbor_table", "eth0", "192.168.1.20", "00:11:22:33:44:55", observed_at=100)
        )
        queued = store.queue_diagnostic(device_id, "192.168.1.20", "ping", now=200)
        claimed = store.claim_next_diagnostic(now=201)
        jobs.execute_job(store, claimed)
        completed = store.get_diagnostic_job(queued["id"])
        assert completed["status"] == "completed"
        assert "answered 4 of 4" in completed["result"]["summary"]
        assert store.get_device(device_id)["last_connectivity"] is not None


def test_scan_queue_is_local_bounded_and_deduplicated(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        first = store.queue_scan("192.168.1.0/24", "eth0", now=100)
        second = store.queue_scan("192.168.1.0/24", "eth0", now=101)
        assert first["id"] == second["id"]
        assert store.claim_next_scan(now=102)["status"] == "running"
        assert store.request_scan_cancel(first["id"], now=103)["cancel_requested"]
        assert store.scan_cancel_requested(first["id"])
        assert store.finish_scan(first["id"], "cancelled", now=104)["status"] == "cancelled"
        for network in ("8.8.8.0/24", "192.168.0.0/16"):
            try:
                store.queue_scan(network, "eth0")
            except ValueError:
                pass
            else:
                raise AssertionError("unsafe scan network should be rejected")


def test_worker_completes_mocked_discovery_without_offline_claims(tmp_path, monkeypatch) -> None:
    class FakeProcess:
        returncode = 0
        def poll(self):
            return 0
        def communicate(self, timeout=None):
            return ("Nmap scan report for 192.168.1.1\nNmap scan report for 192.168.1.20\n", None)

    monkeypatch.setattr(jobs.subprocess, "Popen", lambda *args, **kwargs: FakeProcess())
    monkeypatch.setattr(jobs.PassiveDiscoveryManager, "observe_once", lambda self: {"observations": 0, "errors": []})
    with InventoryStore(tmp_path / "inventory.db") as store:
        queued = store.queue_scan("192.168.1.0/24", "eth0", now=100)
        claimed = store.claim_next_scan(now=101)
        jobs.execute_scan(store, claimed)
        completed = store.get_scan_job(queued["id"])
        assert completed["status"] == "completed"
        assert completed["result"]["addresses"] == ["192.168.1.1", "192.168.1.20"]
        assert "may still be connected" in completed["result"]["summary"]


def test_scheduled_scans_require_all_authorization_gates() -> None:
    calls = []
    def runner(command, timeout):
        calls.append(command)
        if "route" in command:
            return 0, '[{"dev":"eth0"}]', ""
        return 0, '[{"addr_info":[{"family":"inet","scope":"global","local":"192.168.1.20"}]}]', ""

    disabled = CyberScoutConfig(
        active_discovery_enabled=False, scheduled_scan_minutes=60,
        approved_networks=("192.168.1.0/24",),
    )
    assert approved_local_scan_targets(disabled, runner) == []
    assert calls == []
    enabled = CyberScoutConfig(
        active_discovery_enabled=True, scheduled_scan_minutes=60,
        approved_networks=("192.168.1.0/24", "10.0.0.0/24"),
    )
    assert approved_local_scan_targets(enabled, runner) == [("eth0", "192.168.1.0/24")]


def test_configuration_rejects_type_confusion() -> None:
    for data in (
        {"active_discovery_enabled": 1},
        {"retention_days": True},
        {"approved_networks": "192.168.1.0/24"},
    ):
        try:
            CyberScoutConfig.from_mapping(data)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid configuration type should be rejected")


def test_sensor_paths_must_be_absolute() -> None:
    try:
        CyberScoutConfig.from_mapping({"zeek_log_directory": "relative/zeek"})
    except ValueError as error:
        assert "absolute" in str(error)
    else:
        raise AssertionError("relative sensor paths should be rejected")


def test_dashboard_snapshot_uses_persisted_inventory(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        device_id = store.ingest(Observation(
            "neighbor_table", "eth0", "192.168.1.20", "00:11:22:33:44:55",
            state="REACHABLE", observed_at=1_000, active=True,
        ))
        store.update_device(device_id, recognition="recognized", occurred_at=1_001)
        snapshot = dashboard_snapshot(store, now=1_100, networks=["192.168.1.0/24"])
        assert snapshot["counts"] == {
            "total": 1, "recently_active": 1, "new_24h": 1, "unrecognized": 0,
        }
        assert snapshot["changes24h"]["device.first_observed"] == 1


def test_device_report_contains_only_persisted_evidence(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        device_id = store.ingest(Observation(
            "neighbor_table", "eth0", "192.168.1.20", "00:11:22:33:44:55",
            observed_at=1_000,
        ))
        store.record_services_for_address(
            "192.168.1.20", [{"protocol": "tcp", "port": 22, "service": "ssh"}],
            source="test_fixture", observed_at=1_010,
        )
        store.queue_diagnostic(device_id, "192.168.1.20", "ping", now=1_020)
        report = store.get_device_report(device_id)
        assert report["addresses"][0]["address"] == "192.168.1.20"
        assert report["services"][0]["port"] == 22
        assert report["services"][0]["source"] == "test_fixture"
        assert report["diagnostics"][0]["status"] == "queued"
        assert any(event["event_type"] == "device.service_added" for event in report["events"])


def test_keep_only_networks_removes_old_addresses_and_orphan_devices(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        retained = store.ingest(Observation(
            "neighbor_table", "eth0", "10.10.10.20", "00:11:22:33:44:55", observed_at=200,
        ))
        store.ingest(Observation(
            "neighbor_table", "wlan0", "192.168.1.20", "00:11:22:33:44:55", observed_at=100,
        ))
        removed = store.ingest(Observation(
            "neighbor_table", "wlan0", "192.168.1.30", "00:11:22:33:44:66", observed_at=100,
        ))
        result = store.keep_only_networks(["10.10.10.0/24", "10.24.27.0/24"])
        assert result["addresses"] == 2
        assert result["devices"] == 1
        assert store.get_device(retained)["addresses"][0]["address"] == "10.10.10.20"
        try:
            store.get_device(removed)
        except KeyError:
            pass
        else:
            raise AssertionError("device with only historical addresses should be removed")


def test_current_scope_follows_attached_private_interfaces() -> None:
    responses = {
        ("ip", "-j", "address", "show"): '[{"ifname":"eth0","flags":["UP"],"addr_info":[{"family":"inet","scope":"global","local":"10.2.3.4","prefixlen":24}]},{"ifname":"lo","flags":["UP"],"addr_info":[{"family":"inet","scope":"host","local":"127.0.0.1","prefixlen":8}]}]',
        ("ip", "-j", "route", "show", "default"): '[{"dev":"eth0","gateway":"10.2.3.1"}]',
    }
    scopes = current_ipv4_scopes(lambda command: responses[tuple(command)])
    assert scopes == [{
        "interface": "eth0", "address": "10.2.3.4",
        "network": "10.2.3.0/24", "gateway": "10.2.3.1",
    }]


def test_network_scoped_inventory_hides_previous_network(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        current = store.ingest(Observation("neighbor_table", "eth0", "10.2.3.20", "00:11:22:33:44:55"))
        store.ingest(Observation("neighbor_table", "wlan0", "192.168.9.20", "00:11:22:33:44:66"))
        visible = store.list_devices(networks=["10.2.3.0/24"])
        assert [item["id"] for item in visible] == [current]


def test_empty_current_scope_does_not_show_historical_devices(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        store.ingest(Observation("neighbor_table", "eth0", "10.2.3.20", "00:11:22:33:44:55"))
        assert store.list_devices(networks=[]) == []
        assert len(store.list_devices(networks=None)) == 1


def test_event_acknowledge_dismiss_and_restore(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        store.ingest(Observation(
            "neighbor_table", "eth0", "10.2.3.20", "00:11:22:33:44:55", observed_at=100,
        ))
        event_id = store.list_events()[0]["id"]
        acknowledged = store.set_event_state(event_id, "acknowledge", now=200)
        assert acknowledged["acknowledged_at"] == 200
        assert acknowledged["dismissed_at"] is None
        dismissed = store.set_event_state(event_id, "dismiss", now=300)
        assert dismissed["acknowledged_at"] is None
        assert dismissed["dismissed_at"] == 300
        restored = store.set_event_state(event_id, "restore", now=400)
        assert restored["acknowledged_at"] is None
        assert restored["dismissed_at"] is None


def test_dashboard_period_and_history_are_explicit(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        store.ingest(Observation(
            "neighbor_table", "eth0", "10.2.3.20", "00:11:22:33:44:55", observed_at=100,
        ))
        current = dashboard_snapshot(store, now=200, networks=[], period="7d")
        history = dashboard_snapshot(store, now=200, networks=[], period="7d", include_history=True)
        assert current["counts"]["total"] == 0
        assert history["counts"]["total"] == 1
        assert history["period"] == "7d"


def test_zeek_json_parser_keeps_metadata_not_payload() -> None:
    finding = parse_zeek_json({
        "ts": 1_700_000_000.5, "uid": "C1", "id.orig_h": "192.168.1.20",
        "id.orig_p": 50123, "id.resp_h": "192.168.1.1", "id.resp_p": 443,
        "proto": "tcp", "service": "ssl", "conn_state": "SF",
        "payload": "must-not-be-stored",
    })
    assert finding["record_type"] == "connection"
    assert finding["external_id"] == "connection:C1"
    assert finding["details"]["service"] == "ssl"
    assert "payload" not in json.dumps(finding)


def test_suricata_alert_parser_is_bounded_and_payload_free() -> None:
    finding = parse_suricata_eve({
        "timestamp": "2026-10-09T20:00:00+00:00", "event_type": "alert", "flow_id": 42,
        "src_ip": "192.168.1.20", "src_port": 51515, "dest_ip": "192.168.1.1",
        "dest_port": 53, "proto": "UDP",
        "alert": {"signature_id": 1001, "signature": "Test alert", "severity": 1,
                  "category": "Test", "action": "allowed"},
        "payload_printable": "must-not-be-stored",
    })
    assert finding["severity"] == "higher"
    assert finding["summary"] == "Test alert"
    assert finding["details"]["action"] == "allowed"
    assert "payload" not in json.dumps(finding)


def test_sensor_ingestion_tracks_cursor_and_deduplicates_alerts(tmp_path) -> None:
    path = tmp_path / "eve.json"
    alert = {
        "timestamp": "2026-10-09T20:00:00+00:00", "event_type": "alert", "flow_id": 42,
        "src_ip": "192.168.1.20", "src_port": 51515, "dest_ip": "192.168.1.1",
        "dest_port": 53, "proto": "UDP",
        "alert": {"signature_id": 1001, "signature": "Test alert", "severity": 2},
    }
    path.write_text(json.dumps(alert) + "\n" + json.dumps(alert) + "\n")
    with InventoryStore(tmp_path / "inventory.db") as store:
        store.ingest(Observation(
            "neighbor_table", "eth0", "192.168.1.20", "00:11:22:33:44:55", observed_at=100,
        ))
        ingestor = SensorLogIngestor(store)
        first = ingestor.ingest_file(path, "suricata", parse_suricata_eve)
        second = ingestor.ingest_file(path, "suricata", parse_suricata_eve)
        findings = store.list_sensor_findings()
        assert first["records"] == 2
        assert first["duplicates"] == 1
        assert second["records"] == 0
        assert findings[0]["occurrences"] == 2
        assert findings[0]["device_id"] is not None
        assert store.list_sensor_status()[0]["records_read"] == 2
        assert sum(event["event_type"] == "sensor.suricata.alert" for event in store.list_events()) == 1


def test_sensor_ingestion_waits_for_complete_json_line(tmp_path) -> None:
    path = tmp_path / "conn.log"
    item = {"ts": 100, "uid": "C1", "id.orig_h": "10.0.0.2", "id.resp_h": "10.0.0.1"}
    encoded = json.dumps(item)
    path.write_text(encoded)
    with InventoryStore(tmp_path / "inventory.db") as store:
        ingestor = SensorLogIngestor(store)
        assert ingestor.ingest_file(path, "zeek", parse_zeek_json)["records"] == 0
        path.write_text(encoded + "\n")
        assert ingestor.ingest_file(path, "zeek", parse_zeek_json)["records"] == 1


def test_sensor_ingestion_recovers_after_log_rotation(tmp_path) -> None:
    path = tmp_path / "conn.log"
    first = {"ts": 100, "uid": "C1", "id.orig_h": "10.0.0.2", "id.resp_h": "10.0.0.1"}
    second = {"ts": 200, "uid": "C2", "id.orig_h": "10.0.0.3", "id.resp_h": "10.0.0.1"}
    path.write_text(json.dumps(first) + "\n")
    with InventoryStore(tmp_path / "inventory.db") as store:
        ingestor = SensorLogIngestor(store)
        assert ingestor.ingest_file(path, "zeek", parse_zeek_json)["records"] == 1
        replacement = tmp_path / "conn.log.new"
        replacement.write_text(json.dumps(second) + "\n")
        replacement.replace(path)
        assert ingestor.ingest_file(path, "zeek", parse_zeek_json)["records"] == 1
        assert {item["external_id"] for item in store.list_sensor_findings()} == {
            "connection:C1", "connection:C2",
        }


def test_sensor_retention_removes_old_findings(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        store.record_sensor_finding({
            "sensor": "zeek", "external_id": "notice:1", "record_type": "notice",
            "severity": "review", "summary": "Old notice", "observed_at": 100,
        })
        removed = store.prune(1, now=200000)
        assert removed["sensor_findings"] == 1
