# Cyber Scout operations guide

## Installation

Install the Omarchy plugin through the supported plugin command:

```bash
omarchy plugin add https://github.com/usmc1371nerd/omarchy-cyber-scout-widget.git --enable
```

The bar widget works without a background service. It invokes bounded commands
as the logged-in user and opens the dashboard on loopback only when requested.
The widget supplies an owner-private dashboard session capability in the URL
fragment; the fragment is removed from browser history before API requests.
Opening the bare dashboard URL does not grant inventory access.

### Optional passive monitor service

Review both templates under `packaging/systemd/` before installation. They use
user services, resource limits, a restrictive umask, read-only home isolation,
and narrow writable runtime directories. Installation is never automatic.

After explicit approval, run:

```bash
./packaging/manage-user-services.sh --install
systemctl --user status cyber-scout-monitor.service
```

The dashboard service is installed but not enabled. The widget can launch the
dashboard on demand, or the user may explicitly enable it with:

```bash
systemctl --user enable --now cyber-scout-dashboard.service
```

## Configuration

Configuration is stored at `~/.config/cyber-scout/config.json` with mode `0600`.
The dashboard settings page is the preferred editor. Important defaults are:

- active discovery disabled;
- scheduled scans disabled;
- no approved scan networks;
- external WAN lookup disabled;
- 90-day event and observation retention.

Approved scan ranges must be private or link-local. Scheduled discovery also
requires a nonzero interval and an approved range containing an address that is
currently assigned to the selected interface.

Optional deep monitoring accepts an absolute Zeek JSON log directory and/or an
absolute Suricata EVE JSON path. Zeek must emit JSON records in `conn.log` and
`notice.log`; traditional tab-separated Zeek logs are intentionally rejected.
The configured files must be readable by the logged-in user. Saving paths in
the dashboard is picked up by a running monitor on its next passive interval.
No sensor is installed or granted capture privileges by Cyber Scout.

Enabling external WAN lookup permits an HTTPS request to `ipwho.is` for public
IP and provider enrichment. It remains disabled unless the user explicitly
opts in.

To test configured sources once without enabling a persistent service:

```bash
python3 -B -m cyber_scout.monitor --once
```

The command's `sensors` object reports records, ignored record types, parsing
errors, and path errors. The dashboard then shows source status and findings.

## Logs and resource limits

Long-lived components write JSON-lines logs to
`~/.local/state/cyber-scout/`. Each component is limited to 1 MiB plus three
rotated files. User-service templates additionally limit file descriptors,
tasks, memory, and CPU. Inspect service enforcement with:

```bash
systemctl --user show cyber-scout-monitor.service \
  -p MemoryMax -p CPUQuotaPerSecUSec -p TasksMax -p LimitNOFILE
```

## Database verification and recovery

The SQLite database is `~/.local/share/cyber-scout/cyber-scout.db`. Existing
databases are integrity-checked before and after schema migration. A consistent
backup is created automatically before upgrading an older schema. At most five
automatic/manual backups are retained under the adjacent `backups/` directory.

```bash
python3 -B -m cyber_scout.maintenance verify
python3 -B -m cyber_scout.maintenance backup
```

Stop Cyber Scout processes before restoring. A restore validates the source
first and creates a rollback backup of the current database:

```bash
systemctl --user stop cyber-scout-monitor.service cyber-scout-dashboard.service
python3 -B -m cyber_scout.maintenance restore /path/to/known-good.db
```

## Testing and release verification

```bash
python3 -B -m py_compile scanner.py cyber_scout/*.py
python3 -B -m pytest -q -p no:cacheprovider tests
git diff --check
```

Release archives are built only from a clean committed tree:

```bash
./packaging/build-release.sh
sha256sum -c dist/*.sha256
```

## Rollback

1. Stop optional services if installed.
2. Check out the previous known-good Git tag or commit.
3. Restore a compatible database backup if the previous release cannot read the
   current schema. Never point older code at a newer schema without restoring.
4. Run the full validation commands above.
5. Start services and inspect their status and JSON logs.

Remove optional services without deleting data:

```bash
./packaging/manage-user-services.sh --remove
```

To remove the plugin itself, use Omarchy's plugin management command only after
backing up the database. Runtime data is deliberately not deleted by the
service-removal script.
