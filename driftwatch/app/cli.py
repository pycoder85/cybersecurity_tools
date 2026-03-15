from __future__ import annotations

import argparse
import json
import sys
import time

import uvicorn

from driftwatch.app.api.server import create_app
from driftwatch.app.core.config import AppConfig
from driftwatch.app.services.database import init_database, session_scope
from driftwatch.app.services.demo import seed_demo_data


def _cmd_scan(args: argparse.Namespace, config: AppConfig) -> int:
    from driftwatch.app.services.scanner import run_scan

    iterations = args.count if args.count > 0 else 1
    completed = 0
    while True:
        result = run_scan(config)
        print(json.dumps(result, indent=2, default=str))
        completed += 1
        if args.interval_minutes <= 0:
            break
        if args.count > 0 and completed >= iterations:
            break
        time.sleep(args.interval_minutes * 60)
    return 0


def _cmd_serve(args: argparse.Namespace, config: AppConfig) -> int:
    from driftwatch.app.services.scanner import run_scan
    from driftwatch.app.services.scheduler import ScanScheduler

    init_database(config.database_url)
    if args.demo_data:
        seed_demo_data(config)
    if args.scan_on_start:
        run_scan(config)
    scheduler = ScanScheduler(config)
    scheduler.start()
    try:
        uvicorn.run(create_app(config), host=args.host, port=args.port, log_level="info")
    finally:
        scheduler.stop()
    return 0


def _cmd_baseline_create(args: argparse.Namespace, config: AppConfig) -> int:
    from driftwatch.app.services.baseline import create_baseline
    from driftwatch.app.services.scanner import collect_snapshot

    snapshot, _ = collect_snapshot(config)
    init_database(config.database_url)
    with session_scope(config.database_url) as session:
        from driftwatch.app.services.scanner import _get_or_create_host

        host = _get_or_create_host(session, snapshot["host"])
        count = create_baseline(session, host.id, snapshot)
    print(json.dumps({"host": snapshot["host"]["hostname"], "baseline_items": count}, indent=2))
    return 0


def _cmd_baseline_diff(args: argparse.Namespace, config: AppConfig) -> int:
    from driftwatch.app.services.baseline import diff_baseline
    from driftwatch.app.services.scanner import collect_snapshot

    snapshot, _ = collect_snapshot(config)
    init_database(config.database_url)
    with session_scope(config.database_url) as session:
        from driftwatch.app.services.scanner import _get_or_create_host

        host = _get_or_create_host(session, snapshot["host"])
        drift = diff_baseline(session, host.id, snapshot)
    print(json.dumps({"host": snapshot["host"]["hostname"], "drift": drift}, indent=2))
    return 0


def _cmd_demo_data(args: argparse.Namespace, config: AppConfig) -> int:
    seed_demo_data(config)
    print(json.dumps({"database_url": config.database_url, "status": "demo data seeded"}, indent=2))
    return 0


def _cmd_export(args: argparse.Namespace, config: AppConfig) -> int:
    from driftwatch.app.services.exporting import export_findings, export_scans

    init_database(config.database_url)
    with session_scope(config.database_url) as session:
        if args.export_target == "findings":
            count = export_findings(
                session,
                args.output,
                args.format,
                severity=getattr(args, "severity", None),
                category=getattr(args, "category", None),
                status=getattr(args, "status", None),
            )
        else:
            count = export_scans(
                session,
                args.output,
                args.format,
                status=getattr(args, "status", None),
                os_family=getattr(args, "os_family", None),
            )
    destination = args.output or "stdout"
    summary = json.dumps(
        {
            "exported": args.export_target,
            "format": args.format,
            "rows": count,
            "destination": destination,
        },
        indent=2,
    )
    print(
        summary,
        file=sys.stderr if destination == "stdout" or destination == "-" else sys.stdout,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="driftwatch", description="Local-first defensive host auditing dashboard")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Run a host scan")
    scan_parser.add_argument("--interval-minutes", type=int, default=0, help="Repeat scans on an interval")
    scan_parser.add_argument("--count", type=int, default=1, help="Number of scans to run when scheduling")

    serve_parser = subparsers.add_parser("serve", help="Run the local dashboard")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8484)
    serve_parser.add_argument("--scan-on-start", action="store_true")
    serve_parser.add_argument("--demo-data", action="store_true")

    baseline_parser = subparsers.add_parser("baseline", help="Baseline operations")
    baseline_subparsers = baseline_parser.add_subparsers(dest="baseline_command", required=True)
    baseline_subparsers.add_parser("create", help="Create or refresh the local baseline")
    baseline_subparsers.add_parser("diff", help="Diff the current host state against baseline")

    export_parser = subparsers.add_parser("export", help="Export stored findings or scans")
    export_subparsers = export_parser.add_subparsers(dest="export_target", required=True)
    export_findings_parser = export_subparsers.add_parser("findings", help="Export findings")
    export_findings_parser.add_argument("--format", choices=["json", "csv"], default="json")
    export_findings_parser.add_argument("--output", default=None, help="Output file path, or '-' for stdout")
    export_findings_parser.add_argument("--severity", default=None, help="Filter findings by severity")
    export_findings_parser.add_argument("--category", default=None, help="Filter findings by category")
    export_findings_parser.add_argument("--status", default=None, help="Filter findings by status")
    export_scans_parser = export_subparsers.add_parser("scans", help="Export scans")
    export_scans_parser.add_argument("--format", choices=["json", "csv"], default="json")
    export_scans_parser.add_argument("--output", default=None, help="Output file path, or '-' for stdout")
    export_scans_parser.add_argument("--status", default=None, help="Filter scans by status")
    export_scans_parser.add_argument("--os-family", default=None, help="Filter scans by operating system family")

    subparsers.add_parser("demo-data", help="Seed the local database with demo content")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = AppConfig.from_env()
    if args.command == "scan":
        return _cmd_scan(args, config)
    if args.command == "serve":
        return _cmd_serve(args, config)
    if args.command == "baseline" and args.baseline_command == "create":
        return _cmd_baseline_create(args, config)
    if args.command == "baseline" and args.baseline_command == "diff":
        return _cmd_baseline_diff(args, config)
    if args.command == "export":
        return _cmd_export(args, config)
    if args.command == "demo-data":
        return _cmd_demo_data(args, config)
    parser.print_help()
    return 1
