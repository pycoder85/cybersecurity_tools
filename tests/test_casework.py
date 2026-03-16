from pathlib import Path

from driftwatch.app.api.server import create_app
from driftwatch.app.core.config import AppConfig
from driftwatch.app.models.entities import Evidence
from driftwatch.app.services.database import session_scope
from driftwatch.app.services.demo import seed_demo_data


def build_test_config(tmp_path: Path) -> AppConfig:
    return AppConfig(data_dir=tmp_path, database_url=f"sqlite:///{tmp_path / 'test.db'}")


def route_for(app, path: str):
    return next(route for route in app.router.routes if getattr(route, "path", None) == path)


def test_status_update_endpoint_persists_change(tmp_path):
    config = build_test_config(tmp_path)
    seed_demo_data(config)
    app = create_app(config)

    from driftwatch.app.models.entities import Finding

    with session_scope(config.database_url) as session:
        finding = session.query(Finding).first()
        finding_id = finding.id

    status_route = route_for(app, "/api/findings/{finding_id}/status")
    response = status_route.endpoint(finding_id, status="investigating", redirect_to="/findings")

    assert response.status_code == 303

    with session_scope(config.database_url) as session:
        finding = session.get(Finding, finding_id)
        assert finding.status == "investigating"


def test_note_endpoint_creates_analyst_note(tmp_path):
    config = build_test_config(tmp_path)
    seed_demo_data(config)
    app = create_app(config)

    from driftwatch.app.models.entities import Finding

    with session_scope(config.database_url) as session:
        finding = session.query(Finding).first()
        finding_id = finding.id

    note_route = route_for(app, "/api/findings/{finding_id}/notes")
    response = note_route.endpoint(
        finding_id,
        note_text="Validated against maintenance window. Leave investigating until owner confirms.",
        author="tier1-analyst",
        redirect_to="/findings",
    )

    assert response.status_code == 303

    with session_scope(config.database_url) as session:
        finding = session.get(Finding, finding_id)
        assert finding.notes
        assert finding.notes[0].author == "tier1-analyst"
        assert "maintenance window" in finding.notes[0].note_text


def test_enrichment_endpoint_persists_external_enrichment_evidence(tmp_path, monkeypatch):
    config = build_test_config(tmp_path)
    seed_demo_data(config)
    app = create_app(config)

    from driftwatch.app.models.entities import Finding

    with session_scope(config.database_url) as session:
        finding = session.query(Finding).first()
        finding_id = finding.id

    class FakeEnricher:
        provider = "threatfox"

        def enrich_finding(self, finding):
            return {
                "provider": "threatfox",
                "status": "ok",
                "message": "Checked 1 observable(s); 1 produced ThreatFox match result(s).",
                "observables": [{"type": "ip", "value": "198.51.100.10", "source": "raddr"}],
                "results": [{"status": "match", "observable": {"type": "ip", "value": "198.51.100.10", "source": "raddr"}}],
            }

    monkeypatch.setattr("driftwatch.app.api.server.get_enricher", lambda provider, api_key="": FakeEnricher())

    enrich_route = route_for(app, "/api/findings/{finding_id}/enrich")
    payload = enrich_route.endpoint(finding_id)

    assert payload["provider"] == "threatfox"
    assert payload["status"] == "ok"

    with session_scope(config.database_url) as session:
        entries = session.query(Evidence).filter(Evidence.finding_id == finding_id, Evidence.record_type == "external_enrichment").all()
        assert entries
        assert entries[0].collector_name == "enrichment.threatfox"
        assert entries[0].payload_json["status"] == "ok"


def test_software_enrichment_endpoint_persists_external_enrichment_evidence(tmp_path, monkeypatch):
    config = build_test_config(tmp_path)
    seed_demo_data(config)
    app = create_app(config)

    from driftwatch.app.models.entities import Evidence, Scan

    with session_scope(config.database_url) as session:
        scan = session.query(Scan).first()
        session.add(
            Evidence(
                host_id=scan.host_id,
                scan_id=scan.id,
                finding_id=None,
                collector_name="software",
                record_type="collector_result",
                payload_json={
                    "records": [
                        {
                            "name": "openssl",
                            "version": "3.0.2",
                            "publisher": "OpenSSL Project",
                            "hash": "software-record-1",
                        }
                    ]
                },
            )
        )

    class FakeEnricher:
        provider = "nvd_kev"

        def enrich_software(self, record):
            return {
                "provider": "nvd_kev",
                "status": "match",
                "message": "Checked software inventory record against NVD; found 1 CVE candidate(s), 1 present in CISA KEV.",
                "record": record,
                "results": [{"cve_id": "CVE-2024-0001", "kev": {"listed": True}}],
            }

    monkeypatch.setattr("driftwatch.app.api.server.get_enricher", lambda provider, api_key="": FakeEnricher())

    enrich_route = route_for(app, "/api/software/enrich")
    payload = enrich_route.endpoint(record_hash="software-record-1")

    assert payload["provider"] == "nvd_kev"
    assert payload["status"] == "match"

    with session_scope(config.database_url) as session:
        entries = session.query(Evidence).filter(Evidence.record_type == "external_enrichment").all()
        assert any(entry.payload_json.get("target") == "software" for entry in entries)
