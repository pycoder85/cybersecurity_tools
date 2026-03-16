# Driftwatch

Driftwatch is a local-first defensive host security auditing agent for Linux, macOS, and Windows. It collects host telemetry, evaluates deterministic rules, stores results in SQLite, and serves a localhost dashboard for scan history, findings, software inventory, evidence, and baseline drift review.

This project is intentionally defensive in scope:

- No exploitation
- No privilege escalation
- No credential access features
- No persistence deployment
- No automatic remediation by default

## MVP features

- Cross-platform Python agent with modular collectors
- CLI for scans, scheduled scans, baseline creation/diff, dashboard serving, and demo data
- FastAPI + Jinja local dashboard bound to `127.0.0.1` by default
- Overview and scan-history graphs for severity distribution and scan trends
- SQLite persistence for hosts, scans, findings, evidence, baselines, and settings
- Deterministic rules across process, network, persistence, filesystem, and baseline-drift categories
- Cross-platform software inventory collection with latest-inventory review in the dashboard
- Optional LLM explanation abstraction with a safe no-op provider today
- Demo data mode for immediate UI preview

## Repo preview

Live UI preview is available with `driftwatch serve --demo-data`. The repo now includes actual dashboard screenshots:

![Driftwatch overview preview](driftwatch-overview-preview.png)
![Driftwatch findings preview](driftwatch-findings-preview.png)

## Project structure

```text
driftwatch/
  app/
    api/
    collectors/
      linux/
      macos/
      windows/
    core/
    models/
    rules/
    services/
    static/
    templates/
scripts/
tests/
docs/
```

## Quick start

### 1. Create a virtual environment

Linux and macOS:

```bash
./scripts/bootstrap.sh
```

Windows PowerShell:

```powershell
.\scripts\bootstrap.ps1
```

### 2. Seed demo data and launch the dashboard

```bash
driftwatch demo-data
driftwatch serve --demo-data
```

Then open `http://127.0.0.1:8484`.

To bind the dashboard on all interfaces for LAN testing:

```bash
driftwatch serve --demo-data --host 0.0.0.0 --port 8484
```

This is not the default and should be treated as less safe than localhost-only access.

### 3. Run a real local scan

```bash
driftwatch scan
driftwatch serve --scan-on-start
```

### 4. Run the containerized demo

```bash
docker compose up --build
```

Then open `http://127.0.0.1:8484`.

The compose workflow stores local state in a named Docker volume and starts the dashboard with idempotent demo data seeding.

## Configuration

Driftwatch uses a small configuration surface:

- environment variables for the data directory and default dashboard bind address
- persisted local settings for scan directories, exclusions, LLM placeholders, and dashboard-side scheduling

Supported environment variables:

- `DRIFTWATCH_HOME`
- `DRIFTWATCH_HOST`
- `DRIFTWATCH_PORT`

Older `SENTINELDESK_*` environment variables still work as compatibility fallbacks.

Examples:

```bash
export DRIFTWATCH_HOME="$HOME/.driftwatch-lab"
export DRIFTWATCH_HOST="127.0.0.1"
export DRIFTWATCH_PORT="8484"
driftwatch serve
```

CLI flags still take precedence:

```bash
driftwatch serve --host 0.0.0.0 --port 9000
```

For full configuration and scheduling details, see [docs/CONFIGURATION.md](docs/CONFIGURATION.md).
For common local setup issues, see [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

## CLI

```bash
driftwatch scan
driftwatch scan --interval-minutes 30 --count 4
driftwatch serve --scan-on-start
driftwatch baseline create
driftwatch baseline diff
driftwatch export findings --format json --output findings.json
driftwatch export scans --format csv --output scans.csv
driftwatch demo-data
```

## Exports

Driftwatch can export stored results from the local SQLite database:

```bash
driftwatch export findings --format json --output findings.json
driftwatch export findings --format csv --output findings.csv
driftwatch export findings --format csv --severity high --status open --output high-open-findings.csv
driftwatch export scans --format json --output scans.json
driftwatch export scans --format csv --status completed --os-family linux --output scans.csv
driftwatch export evidence --format json --collector-name demo.seed --output evidence.json
```

Use `--output -` to write the export to stdout instead of a file.
The findings export supports `--severity`, `--category`, and `--status`. The scan export supports `--status` and `--os-family`.
The evidence export supports `--collector-name`, `--record-type`, `--scan-id`, and `--finding-id`.

The dashboard also exposes direct download actions for:

- findings JSON and CSV
- scan-history JSON and CSV
- evidence JSON and CSV
- page snapshots for overview, findings, scans, software, and evidence

## External enrichment

Driftwatch can optionally validate findings and software inventory against external feeds. The current implementation supports an opt-in on-demand enrichment workflow with:

- `none`
- `threatfox`
- `virustotal`
- `nvd_kev`

ThreatFox and VirusTotal are used for IOC-style finding observables such as IPs, domains, URLs, and hashes. `nvd_kev` is used from the Software page to match collected package names and versions against NVD CVE results and CISA KEV entries. Enrichment stores results locally as evidence and is intended as analyst context rather than proof of compromise. Configuration details live in [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

## Dashboard pages

- Overview: totals, severity counts, latest scan, host context, severity graph, and recent scan trend graph
- Findings: filter by severity, category, and status; analyst notes; and status workflow
- Scan history: timestamped runs with summaries, trend graph, and severity composition bars
- Software: latest collected package/application inventory with on-demand NVD/KEV validation
- Evidence: raw collector and finding evidence
- Settings: scan paths, exclusions, schedule, optional LLM placeholders
- Rule coverage: implemented rules per operating system

## Defensive detection coverage

### Linux

- Kernel-like process name misuse
- Temp-path process execution
- Outbound SSH burst review
- Cron and systemd inventory
- Package inventory via `dpkg-query` or `rpm` where available
- `authorized_keys` review
- Recent changes under web roots and startup locations
- Deleted-but-running executable checks
- Listening and established connection collection

### macOS

- LaunchAgents and LaunchDaemons inventory
- Application inventory via `system_profiler`
- LoginItems collection where feasible
- Temp and cache process execution checks
- Shell profile and startup path review
- `authorized_keys` review
- Sensitive startup path modification checks

### Windows

- Process and parent relationship collection
- Run and RunOnce registry key inventory
- Startup folder inspection
- Scheduled task inventory
- Service inventory
- Installed software inventory from uninstall registry keys
- Suspicious PowerShell flag detection
- Temp directory executable review
- Startup-related AppData path checks

## Baselines

Driftwatch stores known-good startup and key material locally and can diff new scans against that baseline:

```bash
driftwatch baseline create
driftwatch baseline diff
```

Baseline drift becomes a finding category in regular scans.

## Scheduled scanning

Driftwatch supports two scheduling modes:

- `driftwatch scan --interval-minutes 30 --count 4` for a foreground CLI loop
- dashboard-side scheduling through the Settings page via `schedule_interval_minutes`

The dashboard scheduler only runs while `driftwatch serve` is running. It is intentionally lightweight and should not be treated as a hardened system scheduler. Operational details and examples are documented in [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

## Security and Scope

Driftwatch is defensive-only and intended for hosts you own or are explicitly authorized to inspect. It does not implement exploitation, privilege escalation, credential theft, persistence deployment, remote control, or destructive remediation workflows.

For deployment guidance, intended use boundaries, and disclosure expectations, see [SECURITY.md](SECURITY.md).

## Troubleshooting

Common setup and runtime issues are documented in [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md), including:

- Python 3.11 bootstrap problems
- missing dependency errors such as `psutil`
- port conflicts
- empty dashboards
- scheduler expectations
- Docker demo reset steps

## LLM integration

The core product does not require an LLM. Deterministic rules remain primary. The current implementation includes a pluggable explanation interface and a UI button that returns a safe deterministic explanation stub.

Planned providers:

- `none`
- local model backend
- API-backed provider

## Analyst workflow

Driftwatch now supports lightweight local analyst workflow directly in the findings view:

- change finding status between `open`, `investigating`, and `resolved`
- add analyst notes to preserve triage context
- show recurring finding signatures with first-seen and previous-seen context
- keep notes and status local in SQLite with the rest of the host evidence

## Testing

```bash
pytest
```

## Screenshots / preview

The repository includes real screenshot previews in the project root:

- `driftwatch-overview-preview.png`
- `driftwatch-findings-preview.png`

You can also generate a live local preview immediately with:

```bash
driftwatch serve --demo-data
```

## Future hardening TODOs

See [docs/TODO.md](docs/TODO.md).

## Project status

See [STATUS.md](STATUS.md) for the current implementation state, verified commands, known caveats, and suggested next steps when resuming work.

## License

MIT placeholder. See [LICENSE](LICENSE).
