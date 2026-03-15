from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from driftwatch.app.core.config import AppConfig
from driftwatch.app.rules.engine import rule_coverage
from driftwatch.app.services.casework import ALLOWED_FINDING_STATUSES, add_finding_note, update_finding_status
from driftwatch.app.services.database import init_database, session_scope
from driftwatch.app.services.exporting import filtered_findings, filtered_scans, render_export_payload
from driftwatch.app.services.llm import get_explainer
from driftwatch.app.services.reporting import (
    count_findings,
    finding_categories,
    line_chart_points,
    latest_host,
    latest_scan,
    list_evidence,
    list_findings,
    list_scans,
    list_scans_filtered,
    max_scan_total,
    recent_scan_activity,
    scan_os_families,
    scan_statuses,
    severity_distribution,
)
from driftwatch.app.services.settings import get_settings, update_settings_from_form


def create_app(config: AppConfig | None = None) -> FastAPI:
    config = config or AppConfig.from_env()
    init_database(config.database_url)
    app = FastAPI(title=config.dashboard_title)
    base_dir = Path(__file__).resolve().parent.parent
    templates = Jinja2Templates(directory=str(base_dir / "templates"))
    app.mount("/static", StaticFiles(directory=str(base_dir / "static")), name="static")
    app.state.config = config
    app.state.templates = templates

    @app.get("/", response_class=HTMLResponse)
    def overview(request: Request):
        with session_scope(config.database_url) as session:
            counts = count_findings(session)
            activity = recent_scan_activity(session)
            context = {
                "request": request,
                "page": "overview",
                "host": latest_host(session),
                "latest_scan": latest_scan(session),
                "counts": counts,
                "severity_chart": severity_distribution(counts),
                "scan_activity": activity,
                "scan_line_points": line_chart_points(activity),
                "scan_max_total": max_scan_total(activity),
            }
            return templates.TemplateResponse(request, "overview.html", context)

    @app.get("/findings", response_class=HTMLResponse)
    def findings(request: Request, severity: str | None = None, category: str | None = None, status: str | None = None):
        with session_scope(config.database_url) as session:
            redirect_to = str(request.url.path)
            if request.url.query:
                redirect_to = f"{redirect_to}?{request.url.query}"
            context = {
                "request": request,
                "page": "findings",
                "findings": list_findings(session, severity, category, status),
                "severity": severity or "",
                "category": category or "",
                "status": status or "",
                "categories": finding_categories(session),
                "finding_statuses": sorted(ALLOWED_FINDING_STATUSES),
                "redirect_to": redirect_to,
            }
            return templates.TemplateResponse(request, "findings.html", context)

    @app.get("/scans", response_class=HTMLResponse)
    def scans(request: Request, status: str | None = None, os_family: str | None = None):
        with session_scope(config.database_url) as session:
            activity = recent_scan_activity(session, limit=16)
            return templates.TemplateResponse(
                request,
                "scans.html",
                {
                    "request": request,
                    "page": "scans",
                    "scans": list_scans_filtered(session, status=status, os_family=os_family),
                    "scan_activity": activity,
                    "scan_line_points": line_chart_points(activity),
                    "scan_max_total": max_scan_total(activity),
                    "status": status or "",
                    "os_family": os_family or "",
                    "scan_statuses": scan_statuses(session),
                    "scan_os_families": scan_os_families(session),
                },
            )

    @app.get("/evidence", response_class=HTMLResponse)
    def evidence(request: Request):
        with session_scope(config.database_url) as session:
            return templates.TemplateResponse(
                request,
                "evidence.html",
                {"request": request, "page": "evidence", "evidence": list_evidence(session)},
            )

    @app.get("/settings", response_class=HTMLResponse)
    def settings(request: Request, saved: int = 0):
        with session_scope(config.database_url) as session:
            return templates.TemplateResponse(
                request,
                "settings.html",
                {
                    "request": request,
                    "page": "settings",
                    "settings": get_settings(session),
                    "saved": bool(saved),
                },
            )

    @app.post("/settings")
    async def save_settings(
        scan_directories: str = Form(""),
        scan_exclusions: str = Form(""),
        schedule_interval_minutes: int = Form(0),
        llm_provider: str = Form("none"),
        llm_model: str = Form(""),
    ):
        with session_scope(config.database_url) as session:
            update_settings_from_form(
                session,
                {
                    "scan_directories": scan_directories,
                    "scan_exclusions": scan_exclusions,
                    "schedule_interval_minutes": str(schedule_interval_minutes),
                    "llm_provider": llm_provider,
                    "llm_model": llm_model,
                },
            )
        return RedirectResponse(url="/settings?saved=1", status_code=303)

    @app.get("/coverage", response_class=HTMLResponse)
    def coverage(request: Request):
        return templates.TemplateResponse(
            request,
            "coverage.html",
            {"request": request, "page": "coverage", "coverage": rule_coverage()},
        )

    @app.post("/api/findings/{finding_id}/explain")
    def explain_finding(finding_id: str):
        from driftwatch.app.models.entities import Finding

        with session_scope(config.database_url) as session:
            finding = session.get(Finding, finding_id)
            if finding is None:
                return JSONResponse({"error": "finding not found"}, status_code=404)
            settings = get_settings(session)
            explainer = get_explainer(str(settings.get("llm_provider", "none")))
            explanation = explainer.explain(finding)
            finding.explanation = explanation
            return {"finding_id": finding.id, "explanation": explanation, "provider": getattr(explainer, "provider", "none")}

    @app.post("/api/findings/{finding_id}/status")
    def set_finding_status(
        finding_id: str,
        status: str = Form(...),
        redirect_to: str = Form("/findings"),
    ):
        with session_scope(config.database_url) as session:
            try:
                finding = update_finding_status(session, finding_id, status)
            except ValueError as exc:
                return JSONResponse({"error": str(exc)}, status_code=400)
            if finding is None:
                return JSONResponse({"error": "finding not found"}, status_code=404)
        return RedirectResponse(url=redirect_to or "/findings", status_code=303)

    @app.post("/api/findings/{finding_id}/notes")
    def create_finding_note(
        finding_id: str,
        note_text: str = Form(...),
        author: str = Form("local-analyst"),
        redirect_to: str = Form("/findings"),
    ):
        with session_scope(config.database_url) as session:
            try:
                note = add_finding_note(session, finding_id, note_text=note_text, author=author)
            except ValueError as exc:
                return JSONResponse({"error": str(exc)}, status_code=400)
            if note is None:
                return JSONResponse({"error": "finding not found"}, status_code=404)
        return RedirectResponse(url=redirect_to or "/findings", status_code=303)

    @app.get("/api/summary")
    def summary():
        with session_scope(config.database_url) as session:
            host = latest_host(session)
            scan = latest_scan(session)
            return {
                "host": {
                    "hostname": host.hostname if host else None,
                    "os_family": host.os_family if host else None,
                    "os_version": host.os_version if host else None,
                },
                "latest_scan_id": scan.id if scan else None,
                "finding_counts": count_findings(session),
            }

    @app.get("/api/export/findings")
    def export_findings_api(
        format: str = "json",
        severity: str | None = None,
        category: str | None = None,
        status: str | None = None,
    ):
        export_format = "csv" if format == "csv" else "json"
        with session_scope(config.database_url) as session:
            findings = filtered_findings(session, severity=severity, category=category, status=status)
            payload = render_export_payload("findings", export_format, findings=findings)
        media_type = "text/csv; charset=utf-8" if export_format == "csv" else "application/json"
        filename = f"driftwatch-findings.{export_format}"
        return Response(
            content=payload,
            media_type=media_type,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.get("/api/export/scans")
    def export_scans_api(
        format: str = "json",
        status: str | None = None,
        os_family: str | None = None,
    ):
        export_format = "csv" if format == "csv" else "json"
        with session_scope(config.database_url) as session:
            scans = filtered_scans(session, status=status, os_family=os_family)
            payload = render_export_payload("scans", export_format, scans=scans)
        media_type = "text/csv; charset=utf-8" if export_format == "csv" else "application/json"
        filename = f"driftwatch-scans.{export_format}"
        return Response(
            content=payload,
            media_type=media_type,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    return app
