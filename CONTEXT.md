# Driftwatch Context

## Vision
Driftwatch is a local-first, defensive, cross-platform host security auditing agent for learning and lab use. It helps users inspect their own machines for suspicious activity and understand what was found through a local web dashboard.

## Product principles
- Defensive only
- Local-first
- Transparent evidence
- Deterministic detection first
- LLM optional and secondary
- Cross-platform by design
- GitHub-friendly and easy to run

## Supported platforms
- Linux
- macOS
- Windows

## Main capabilities
- Run local host scans
- Store findings in SQLite
- Render a localhost dashboard
- Show scan history and evidence
- Explain findings in plain language
- Baseline known-good state and detect drift

## Initial detection focus
### Linux
- Fake kernel-like process names under non-root users
- Processes from /tmp, /dev/shm, /var/tmp
- Outbound SSH burst detection
- Cron inspection
- systemd service/timer inspection
- authorized_keys inspection
- recent webroot changes
- temp executable discovery

### macOS
- LaunchAgents and LaunchDaemons inspection
- suspicious temp executables
- startup shell profile inspection
- suspicious network connections
- authorized_keys inspection
- recent changes in persistence-related paths

### Windows
- Run and RunOnce keys
- Startup folder inspection
- scheduled tasks
- suspicious PowerShell patterns
- temp executable discovery
- services inspection
- suspicious outbound connections

## UI goals
- Modern dark dashboard
- Severity badges
- Evidence drill-down
- Rule coverage page
- Learning-oriented wording
- Easy filter/search

## Technical preferences
- Python 3.11+
- FastAPI
- SQLite
- SQLAlchemy
- psutil
- Jinja first unless React clearly adds value
- localhost only by default

## Safety
- No offensive capability
- No automatic destructive response by default
- Any response actions must be opt-in and clearly separated from detection

## Future roadmap
- local LLM explanation layer
- baseline drift reporting
- signed rule packs
- central multi-host collector mode
- packaging for pip and Docker
