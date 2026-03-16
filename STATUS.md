# Driftwatch Status

## Current state

Driftwatch is at MVP stage and runs end-to-end locally:

- CLI commands exist for scan, serve, baseline create/diff, and demo data
- CLI export commands exist for findings, scans, and evidence in JSON or CSV
- Export filters exist for findings, scans, and evidence, and the dashboard now exposes download buttons
- Findings support analyst notes and status transitions in the dashboard
- Findings now show recurrence metadata and “seen before” indicators across local scan history
- FastAPI dashboard is working with Jinja templates and dark-theme styling
- Repository screenshots are included for the overview and findings views
- SQLite persistence is implemented for hosts, scans, findings, evidence, baselines, and settings
- Deterministic rules are implemented for process, network, persistence, filesystem, and baseline drift coverage
- Windows persistence collection now captures richer scheduled-task and service metadata, including task authors/run-as context and service image paths/start modes where available
- Overview and scan-history graphs are implemented without a heavyweight frontend stack
- Dashboard snapshot downloads exist for overview, findings, scans, software, and evidence views
- Bootstrap helper scripts exist for Linux/macOS and PowerShell
- Containerized one-command demo workflow exists via [docker-compose.yml](/home/cadmin/cybersecurity_tools/docker-compose.yml)
- Demo data mode is working for immediate UI preview
- Demo data seeding is idempotent for an existing database
- Opt-in external enrichment now exists for findings, with ThreatFox and VirusTotal provider support stored as local evidence
- Cross-platform software inventory collection now exists for Linux, macOS, and Windows, with a dedicated dashboard page
- Opt-in software validation now exists via NVD and CISA KEV feed enrichment stored as local evidence
- Tests now cover export filters, reporting graph helpers, and baseline drift behavior
- Tests now cover Windows collector parsing for scheduled tasks and services
- Tests now cover enrichment observable extraction, provider integration paths, and software collector parsing
- Public release scope and security guidance now exists in [SECURITY.md](/home/cadmin/cybersecurity_tools/SECURITY.md)
- Troubleshooting guidance now exists in [docs/TROUBLESHOOTING.md](/home/cadmin/cybersecurity_tools/docs/TROUBLESHOOTING.md)
- Tests currently pass

## Verified commands

Commands verified during implementation:

```bash
python3 -m pytest
.venv/bin/driftwatch --help
.venv/bin/driftwatch scan
.venv/bin/driftwatch export findings --format json --output findings.json
.venv/bin/driftwatch export findings --format csv --severity high --status open --output high-open-findings.csv
.venv/bin/driftwatch export evidence --format json --collector-name demo.seed --output evidence.json
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
- Configuration and scheduling guidance now lives in [docs/CONFIGURATION.md](/home/cadmin/cybersecurity_tools/docs/CONFIGURATION.md)
- Public release scope guidance lives in [SECURITY.md](/home/cadmin/cybersecurity_tools/SECURITY.md)
- Local setup and runtime troubleshooting lives in [docs/TROUBLESHOOTING.md](/home/cadmin/cybersecurity_tools/docs/TROUBLESHOOTING.md)
- External enrichment is opt-in and should be reviewed as controlled data egress

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
  - recurrence strip with first-seen, previous-seen, and occurrence count
  - download buttons for filtered JSON and CSV export
- Scan history page
  - filters by status and OS family
  - scan table
  - findings-over-time graph
  - stacked severity composition bars
  - download buttons for filtered JSON and CSV export
- Software page
  - latest collected software inventory view
  - name filter
  - on-demand feed validation for package or application records
  - page snapshot download
- Evidence page
  - filters by collector, record type, scan ID, and finding ID
  - download buttons for filtered JSON and CSV export
  - page snapshot download
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
- Export filtering and dashboard snapshot download exist, but bundled evidence/report packaging is not implemented yet
- Analyst notes exist, but there is no per-user auth or audit-trail model yet
- Deduplication is signature-based and heuristic, not a full canonical finding identity model yet
- No migration system exists yet; schema is created via SQLAlchemy metadata
- Binding to `0.0.0.0` works, but remote exposure is less safe than localhost-only use
- NVD keyword matching is heuristic package-name/version enrichment, not authoritative SBOM-grade product matching

## Recommended next steps

Short-term release polish:

1. Improve software-to-CVE matching quality with stronger product normalization and version parsing.
2. Add richer packaged export/report bundles with evidence snapshots.
3. Add command examples and screenshots for more non-Linux flows.
4. Add higher-signal release notes for first-time users.
5. Add native packaged release artifacts beyond the Docker demo workflow.

Next product improvements:

1. Deepen Windows and macOS collectors beyond the current inventory and persistence set.
2. Add packaged release artifacts.
3. Add richer export/report bundles with filters and snapshots.
4. Add per-user analyst identity and audit history for notes/status changes.
5. Add stronger dedup signatures and suppress/merge controls for recurring findings.

## Resume checklist

When resuming work after context loss:

1. Activate the environment: `source .venv/bin/activate`
2. Run tests: `python3 -m pytest`
3. Start the app with demo data if needed: `driftwatch serve --demo-data`
4. Review [README.md](/home/cadmin/cybersecurity_tools/README.md), [STATUS.md](/home/cadmin/cybersecurity_tools/STATUS.md), and [docs/TODO.md](/home/cadmin/cybersecurity_tools/docs/TODO.md)
5. Review [docs/CONFIGURATION.md](/home/cadmin/cybersecurity_tools/docs/CONFIGURATION.md) for env vars and scheduling behavior
6. Continue from the “Recommended next steps” section above
