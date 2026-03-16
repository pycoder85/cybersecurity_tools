import json

from driftwatch.app.models.entities import Finding
from driftwatch.app.services.enrichment import (
    NvdKevEnricher,
    ThreatFoxEnricher,
    VirusTotalEnricher,
    _virustotal_path_for_observable,
    _virustotal_url_id,
    extract_observables,
    get_enricher,
)


def test_extract_observables_finds_ips_domains_urls_and_hashes():
    evidence = {
        "raddr": "198.51.100.8:443",
        "command": "powershell -enc AAA https://evil.example/path",
        "nested": ["example.org", "44d88612fea8a8f36de82e1278abb02f", "a" * 64],
    }

    observables = extract_observables(evidence)
    pairs = {(item.type, item.value) for item in observables}

    assert ("ip", "198.51.100.8") in pairs
    assert ("url", "https://evil.example/path") in pairs
    assert ("domain", "evil.example") in pairs
    assert ("domain", "example.org") in pairs
    assert ("md5", "44d88612fea8a8f36de82e1278abb02f") in pairs
    assert ("sha256", "a" * 64) in pairs


def test_threatfox_enricher_returns_matches_from_provider(monkeypatch):
    finding = Finding(
        host_id="host-1",
        scan_id="scan-1",
        category="Network anomalies",
        severity="medium",
        title="Test finding",
        description="Test",
        evidence_json={"raddr": "198.51.100.8:443"},
        rule_name="outbound_ssh_burst",
        source_module="rules.network",
        os_family="linux",
    )

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps({"query_status": "ok", "data": [{"ioc": "198.51.100.8", "threat_type": "c2"}]}).encode("utf-8")

    monkeypatch.setattr("driftwatch.app.services.enrichment.request.urlopen", lambda *args, **kwargs: FakeResponse())

    payload = ThreatFoxEnricher().enrich_finding(finding)

    assert payload["provider"] == "threatfox"
    assert payload["status"] == "ok"
    assert payload["results"][0]["status"] == "match"
    assert payload["results"][0]["matches"][0]["ioc"] == "198.51.100.8"


def test_noop_enricher_is_default():
    enricher = get_enricher("none")
    finding = Finding(
        host_id="host-1",
        scan_id="scan-1",
        category="Suspicious processes",
        severity="high",
        title="Test finding",
        description="Test",
        evidence_json={"raddr": "198.51.100.8:443"},
        rule_name="suspicious_temp_process",
        source_module="rules.processes",
        os_family="linux",
    )

    payload = enricher.enrich_finding(finding)

    assert payload["status"] == "disabled"
    assert payload["observables"]


def test_virustotal_helpers_build_expected_paths():
    observables = extract_observables(
        {
            "raddr": "198.51.100.8:443",
            "url": "https://example.test/path?a=1",
            "sha256": "a" * 64,
        }
    )
    mapping = {item.type: item for item in observables if item.type in {"ip", "url", "sha256"}}

    assert _virustotal_path_for_observable(mapping["ip"]) == "/ip_addresses/198.51.100.8"
    assert _virustotal_path_for_observable(mapping["sha256"]) == f"/files/{'a' * 64}"
    assert _virustotal_path_for_observable(mapping["url"]) == f"/urls/{_virustotal_url_id('https://example.test/path?a=1')}"


def test_virustotal_enricher_uses_api_key_and_returns_summary(monkeypatch):
    finding = Finding(
        host_id="host-1",
        scan_id="scan-1",
        category="Network anomalies",
        severity="medium",
        title="Test finding",
        description="Test",
        evidence_json={"raddr": "198.51.100.8:443"},
        rule_name="outbound_ssh_burst",
        source_module="rules.network",
        os_family="linux",
    )
    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps(
                {
                    "data": {
                        "id": "198.51.100.8",
                        "type": "ip_address",
                        "attributes": {
                            "reputation": -10,
                            "last_analysis_stats": {"malicious": 2, "undetected": 90},
                            "last_analysis_date": 1710000000,
                        },
                    }
                }
            ).encode("utf-8")

    def fake_urlopen(req, timeout=15):
        captured["url"] = req.full_url
        captured["api_key"] = req.headers.get("x-apikey") or req.headers.get("X-apikey")
        return FakeResponse()

    monkeypatch.setattr("driftwatch.app.services.enrichment.request.urlopen", fake_urlopen)

    payload = VirusTotalEnricher(api_key="vt-secret").enrich_finding(finding)

    assert captured["url"].endswith("/ip_addresses/198.51.100.8")
    assert captured["api_key"] == "vt-secret"
    assert payload["provider"] == "virustotal"
    assert payload["results"][0]["status"] == "match"
    assert payload["results"][0]["matches"][0]["reputation"] == -10


def test_nvd_kev_enricher_returns_cve_and_kev_matches(monkeypatch):
    captured = []

    class FakeResponse:
        def __init__(self, payload):
            self.payload = payload

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps(self.payload).encode("utf-8")

    def fake_urlopen(req, timeout=20):
        captured.append(req.full_url)
        if "services.nvd.nist.gov" in req.full_url:
            return FakeResponse(
                {
                    "vulnerabilities": [
                        {
                            "cve": {
                                "id": "CVE-2024-0001",
                                "published": "2024-01-01T00:00:00.000",
                                "lastModified": "2024-01-02T00:00:00.000",
                                "descriptions": [{"lang": "en", "value": "Demo package vulnerability"}],
                                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
                            }
                        }
                    ]
                }
            )
        return FakeResponse(
            {
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2024-0001",
                        "dateAdded": "2024-02-01",
                        "dueDate": "2024-02-21",
                        "requiredAction": "Apply mitigations per vendor guidance",
                        "knownRansomwareCampaignUse": "Known",
                    }
                ]
            }
        )

    monkeypatch.setattr("driftwatch.app.services.enrichment.request.urlopen", fake_urlopen)

    payload = NvdKevEnricher().enrich_software(
        {
            "name": "openssl",
            "version": "3.0.2",
            "publisher": "OpenSSL Project",
            "hash": "software-1",
        }
    )

    assert any("services.nvd.nist.gov" in url for url in captured)
    assert any("known_exploited_vulnerabilities.json" in url for url in captured)
    assert payload["provider"] == "nvd_kev"
    assert payload["status"] == "match"
    assert payload["results"][0]["cve_id"] == "CVE-2024-0001"
    assert payload["results"][0]["kev"]["listed"] is True
    assert payload["results"][0]["cvss_score"] == 9.8


def test_get_enricher_returns_nvd_kev_provider():
    enricher = get_enricher("nvd_kev")

    assert enricher.provider == "nvd_kev"
