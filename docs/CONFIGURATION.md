# Configuration and Scheduling

Driftwatch keeps configuration deliberately small:

- process-level environment variables for the data directory and dashboard bind address
- persisted local settings in SQLite for scan scope, exclusions, LLM placeholders, and background scheduling

## Environment variables

`AppConfig.from_env()` reads these variables at process start:

| Variable | Purpose | Default |
| --- | --- | --- |
| `DRIFTWATCH_HOME` | Directory for the SQLite database and local state | `~/.driftwatch` |
| `DRIFTWATCH_HOST` | Default bind host for `driftwatch serve` when `--host` is not passed | `127.0.0.1` |
| `DRIFTWATCH_PORT` | Default port for `driftwatch serve` when `--port` is not passed | `8484` |

Backward-compatible fallbacks remain available for older installs:

- `SENTINELDESK_HOME`
- `SENTINELDESK_HOST`
- `SENTINELDESK_PORT`

Examples:

```bash
export DRIFTWATCH_HOME="$HOME/.driftwatch-lab"
export DRIFTWATCH_HOST="127.0.0.1"
export DRIFTWATCH_PORT="8484"
driftwatch serve
```

```bash
DRIFTWATCH_HOME=/tmp/driftwatch-demo driftwatch demo-data
DRIFTWATCH_HOME=/tmp/driftwatch-demo driftwatch serve --demo-data
```

CLI flags override environment defaults:

```bash
DRIFTWATCH_HOST=127.0.0.1 DRIFTWATCH_PORT=8484 driftwatch serve --host 0.0.0.0 --port 9000
```

## Local settings

The Settings page stores values in the local SQLite database:

- `scan_directories`
- `scan_exclusions`
- `schedule_interval_minutes`
- `llm_provider`
- `llm_model`
- `enrichment_provider`
- `enrichment_api_key`
- `response_actions_enabled`

These are host-local settings, not a multi-user configuration model.

## External enrichment

Driftwatch can optionally validate extracted observables from findings against external feeds.

Current provider options:

- `none`
- `threatfox`
- `virustotal`
- `nvd_kev`

Behavior:

- enrichment is opt-in and disabled by default
- IOC enrichment runs on demand from the Findings page
- software vulnerability enrichment runs on demand from the Software page
- extracted observables can include IPs, domains, URLs, and hashes
- software enrichment sends package or application names and versions
- results are stored locally as evidence entries with record type `external_enrichment`
- external enrichment is supplemental analyst context, not proof of compromise

If you enable an external provider, Driftwatch sends matched observables to that provider. Review [SECURITY.md](../SECURITY.md) before enabling this on sensitive systems.

Default scan scope is OS-specific:

- Linux: scan directories `/tmp`, `/var/www`, `/etc/systemd/system`; exclusions `/proc`, `/sys`, `/snap`
- macOS: scan directories `/tmp`, `~/Library/LaunchAgents`, `/Library/LaunchDaemons`; exclusion `~/Library/Caches`
- Windows: scan directories `%USERPROFILE%`, `%PROGRAMDATA%`; exclusion `C:\Windows\SoftwareDistribution`

## Scheduling modes

Driftwatch currently has two separate scheduling paths.

### 1. CLI loop scheduling

`driftwatch scan --interval-minutes N --count M` runs scans in the foreground CLI process.

Example:

```bash
driftwatch scan --interval-minutes 30 --count 4
```

Behavior:

- waits `N` minutes between scans
- stops after `M` scans when `--count` is greater than zero
- exits when the foreground process exits

This is the simplest option for ad hoc repeated scans.

### 2. Dashboard background scheduling

The Settings page exposes `schedule_interval_minutes`. When this value is above zero and `driftwatch serve` is running, the dashboard process starts a lightweight background thread that triggers scans on that interval.

Behavior:

- scheduling only runs while the `driftwatch serve` process is alive
- the scheduler polls settings every 15 seconds
- intervals are in minutes
- `0` disables background scheduling
- this is an MVP convenience scheduler, not a hardened job runner

Recommended usage:

1. Start the dashboard.
2. Open `/settings`.
3. Set a non-zero schedule interval.
4. Keep the dashboard process running.

If you need durable or host-managed scheduling, use your OS scheduler around `driftwatch scan` instead of relying on the in-process thread.

## Scan-on-start

`driftwatch serve --scan-on-start` performs one immediate scan before the web server begins accepting requests.

This is separate from background scheduling:

- `--scan-on-start` gives you one scan immediately
- `schedule_interval_minutes` controls future scans while the dashboard stays up

## Safety notes

- `127.0.0.1` is the safest default bind address for local-only use
- `0.0.0.0` exposes the dashboard on all interfaces and should only be used intentionally
- response actions remain disabled in the current MVP
