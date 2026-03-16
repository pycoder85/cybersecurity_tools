# Troubleshooting

## Python version problems

Driftwatch requires Python 3.11 or newer.

Typical symptom:

- `Expected python3.11 on PATH`
- install or bootstrap failures on older interpreters

Fix:

- Linux/macOS: set `PYTHON_BIN` before running `./scripts/bootstrap.sh`
- Windows: set `PYTHON_BIN` before running `.\scripts\bootstrap.ps1`

Examples:

```bash
PYTHON_BIN=python3.11 ./scripts/bootstrap.sh
```

```powershell
$env:PYTHON_BIN = "py -3.11"
.\scripts\bootstrap.ps1
```

## Missing dependencies in manual environments

Typical symptom:

- `ModuleNotFoundError: No module named 'psutil'`

Fix:

- activate `.venv`
- reinstall the editable package and dev dependencies

```bash
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

## Dashboard does not start on the expected address

Driftwatch reads these defaults at process start:

- `DRIFTWATCH_HOST`
- `DRIFTWATCH_PORT`

CLI flags override them:

```bash
driftwatch serve --host 0.0.0.0 --port 9000
```

If the process still binds to an unexpected address, confirm you are not exporting stale `SENTINELDESK_*` variables.

## Port already in use

Typical symptom:

- bind failure on port `8484`

Fix:

- stop the other process using that port
- or run Driftwatch on another port

```bash
driftwatch serve --port 8585
```

## Dashboard is empty

The UI only shows stored results.

Use one of:

```bash
driftwatch demo-data
driftwatch serve --demo-data
```

or:

```bash
driftwatch scan
driftwatch serve --scan-on-start
```

## Repeated demo starts should not duplicate rows

Current behavior:

- demo-data seeding is idempotent for the same database
- restarting the Docker demo or rerunning `driftwatch serve --demo-data` should not keep appending duplicate demo rows

If you want a fresh demo dataset, remove the database inside `DRIFTWATCH_HOME` and start again.

## Scheduled scans are not running

The built-in scheduler only runs while `driftwatch serve` is running.

Check:

- `schedule_interval_minutes` is above `0`
- the dashboard process is still alive
- you are not expecting it to survive a process restart like a system scheduler

For durable automation, prefer cron, systemd timers, Windows Task Scheduler, or another OS-native scheduler that calls `driftwatch scan`.

## Docker demo workflow

Start the one-command demo:

```bash
docker compose up --build
```

Then open `http://127.0.0.1:8484`.

To reset the persistent demo data volume:

```bash
docker compose down -v
```
