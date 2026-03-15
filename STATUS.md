# Driftwatch Status

## Current state

Driftwatch is at MVP stage and runs end-to-end locally:

- CLI commands exist for scan, serve, baseline create/diff, and demo data
- CLI export commands exist for findings and scans in JSON or CSV
- Export filters exist for findings and scans, and the dashboard now exposes download buttons
- Findings support analyst notes and status transitions in the dashboard
- FastAPI dashboard is working with Jinja templates and dark-theme styling
- SQLite persistence is implemented for hosts, scans, findings, evidence, baselines, and settings
- Deterministic rules are implemented for process, network, persistence, filesystem, and baseline drift coverage
- Overview and scan-history graphs are implemented without a heavyweight frontend stack
- Bootstrap helper scripts exist for Linux/macOS and PowerShell
- Demo data mode is working for immediate UI preview
- Tests currently pass

## Verified commands

Commands verified during implementation:

```bash
python3 -m pytest
.venv/bin/driftwatch --help
.venv/bin/driftwatch scan
.venv/bin/driftwatch export findings --format json --output findings.json
.venv/bin/driftwatch export findings --format csv --severity high --status open --output high-open-findings.csv
.venv/bin/driftwatch serve --demo-data --host 0.0.0.0 --port 8484
```

Typical local usage:

```bash
source .venv/bin/activate
driftwatch scan
driftwatch serve --scan-on-start
```

## Environment notes

- The working local environment is `.venv`
- On this host, prefer the installed CLI `driftwatch` after activating `.venv`
- Do not rely on `python -m driftwatch.app` here because the venv interpreter links were mixed when the environment was created
- Primary environment variables are:
  - `DRIFTWATCH_HOME`
  - `DRIFTWATCH_HOST`
  - `DRIFTWATCH_PORT`
- Backward-compatibility fallbacks for old `SENTINELDESK_*` variables still exist in config

## Implemented UI

- Overview page
  - total findings
  - severity counters
  - host context
  - severity distribution graph
  - recent scan trend graph
- Findings page
  - filters by severity, category, status
  - evidence details
  - explain-this-finding button with deterministic stubbed enrichment
  - status workflow for open, investigating, resolved
  - analyst note creation and note history
  - download buttons for filtered JSON and CSV export
- Scan history page
  - filters by status and OS family
  - scan table
  - findings-over-time graph
  - stacked severity composition bars
  - download buttons for filtered JSON and CSV export
- Evidence page
- Settings page
- Rule coverage page

## Important files

- Core CLI: [driftwatch/app/cli.py](/home/cadmin/cybersecurity_tools/driftwatch/app/cli.py)
- API server: [driftwatch/app/api/server.py](/home/cadmin/cybersecurity_tools/driftwatch/app/api/server.py)
- Scanner pipeline: [driftwatch/app/services/scanner.py](/home/cadmin/cybersecurity_tools/driftwatch/app/services/scanner.py)
- Reporting and graph data: [driftwatch/app/services/reporting.py](/home/cadmin/cybersecurity_tools/driftwatch/app/services/reporting.py)
- Templates: [driftwatch/app/templates](/home/cadmin/cybersecurity_tools/driftwatch/app/templates)
- Styles: [driftwatch/app/static/styles.css](/home/cadmin/cybersecurity_tools/driftwatch/app/static/styles.css)
- Tests: [tests](/home/cadmin/cybersecurity_tools/tests)

## Known caveats

- Collector depth is still MVP-level and intentionally conservative
- Windows and macOS coverage exists, but Linux has had the most real execution testing so far
- Scheduled scanning is simple background polling, not a hardened job system
- LLM integration is only a pluggable stub right now
- Export/report packaging is not implemented yet
- Export exists for findings and scans, but filtering and bundled report generation are not implemented yet
- Export filtering exists, but bundled evidence/report packaging is not implemented yet
- Analyst notes exist, but there is no per-user auth or audit-trail model yet
- No migration system exists yet; schema is created via SQLAlchemy metadata
- Binding to `0.0.0.0` works, but remote exposure is less safe than localhost-only use

## Recommended next steps

Short-term release polish:

1. Add real screenshots to the repository.
2. Add config documentation for env vars and scheduled scanning.
3. Add tests around baseline drift, reporting graph helpers, and export filters.
4. Add richer dashboard actions such as evidence export and snapshot downloads.
5. Add an explicit security/scope section for public GitHub release.

Next product improvements:

1. Improve deduplication across repeated scans.
2. Expand Windows and macOS collectors.
3. Add packaged release artifacts.
4. Add richer export/report bundles with filters and snapshots.
5. Add per-user analyst identity and audit history for notes/status changes.

## Resume checklist

When resuming work after context loss:

1. Activate the environment: `source .venv/bin/activate`
2. Run tests: `python3 -m pytest`
3. Start the app with demo data if needed: `driftwatch serve --demo-data`
4. Review [README.md](/home/cadmin/cybersecurity_tools/README.md), [STATUS.md](/home/cadmin/cybersecurity_tools/STATUS.md), and [docs/TODO.md](/home/cadmin/cybersecurity_tools/docs/TODO.md)
5. Continue from the “Recommended next steps” section above
