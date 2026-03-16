from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib import error, parse, request

from driftwatch.app.models.entities import Finding


URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
DOMAIN_RE = re.compile(
    r"\b(?=.{1,253}\b)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}\b"
)


@dataclass(slots=True)
class Observable:
    type: str
    value: str
    source: str


def _serialize_observable(observable: Observable) -> dict[str, str]:
    return {"type": observable.type, "value": observable.value, "source": observable.source}


def _serialize_software_record(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": str(record.get("name") or ""),
        "version": str(record.get("version") or ""),
        "publisher": str(record.get("publisher") or ""),
        "architecture": str(record.get("architecture") or ""),
        "install_location": str(record.get("install_location") or ""),
        "hash": str(record.get("hash") or ""),
    }


class NoOpEnricher:
    provider = "none"

    def enrich_finding(self, finding: Finding) -> dict[str, Any]:
        observables = [_serialize_observable(observable) for observable in extract_observables(finding.evidence_json)]
        return {
            "provider": self.provider,
            "status": "disabled",
            "message": "External enrichment is disabled. Set an enrichment provider in Settings to validate observables with external feeds.",
            "observables": observables,
            "results": [],
        }

    def enrich_software(self, record: dict[str, Any]) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "status": "disabled",
            "message": "External enrichment is disabled. Set an enrichment provider in Settings to validate software inventory with external feeds.",
            "record": _serialize_software_record(record),
            "results": [],
        }


class ThreatFoxEnricher:
    provider = "threatfox"
    api_url = "https://threatfox-api.abuse.ch/api/v1/"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key.strip()

    def enrich_finding(self, finding: Finding) -> dict[str, Any]:
        observables = extract_observables(finding.evidence_json)
        results: list[dict[str, Any]] = []
        for observable in observables:
            results.append(self._lookup(observable))
        match_count = sum(1 for item in results if item.get("status") == "match")
        return {
            "provider": self.provider,
            "status": "ok",
            "message": f"Checked {len(observables)} observable(s); {match_count} produced ThreatFox match result(s).",
            "observables": [_serialize_observable(observable) for observable in observables],
            "results": results,
        }

    def enrich_software(self, record: dict[str, Any]) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "status": "unsupported",
            "message": "ThreatFox enrichment supports IOC observables, not software inventory records.",
            "record": _serialize_software_record(record),
            "results": [],
        }

    def _lookup(self, observable: Observable) -> dict[str, Any]:
        if observable.type in {"ip", "domain", "url"}:
            payload = {
                "query": "search_ioc",
                "search_term": observable.value,
                "exact_match": True,
            }
        elif observable.type in {"md5", "sha1", "sha256"}:
            payload = {
                "query": "search_hash",
                "hash": observable.value,
            }
        else:
            return {
                "observable": _serialize_observable(observable),
                "status": "unsupported",
                "message": f"Observable type {observable.type} is not supported by ThreatFox lookup.",
                "matches": [],
            }
        try:
            response_json = self._post_json(payload)
        except RuntimeError as exc:
            return {
                "observable": _serialize_observable(observable),
                "status": "error",
                "message": str(exc),
                "matches": [],
            }
        query_status = str(response_json.get("query_status") or "").lower()
        data = response_json.get("data") or []
        return {
            "observable": _serialize_observable(observable),
            "status": "match" if data and query_status.startswith("ok") else "no_match",
            "query_status": query_status,
            "matches": data[:10],
        }

    def _post_json(self, payload: dict[str, Any]) -> dict[str, Any]:
        data = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Auth-Key"] = self.api_key
        req = request.Request(self.api_url, data=data, headers=headers, method="POST")
        try:
            with request.urlopen(req, timeout=15) as response:
                body = response.read().decode("utf-8")
        except error.URLError as exc:
            raise RuntimeError(f"ThreatFox lookup failed: {exc.reason}") from exc
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise RuntimeError("ThreatFox lookup returned invalid JSON.") from exc


def get_enricher(provider: str, api_key: str = ""):
    if provider == "threatfox":
        return ThreatFoxEnricher(api_key=api_key)
    if provider == "virustotal":
        return VirusTotalEnricher(api_key=api_key)
    if provider == "nvd_kev":
        return NvdKevEnricher(api_key=api_key)
    return NoOpEnricher()


class VirusTotalEnricher:
    provider = "virustotal"
    api_base = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key.strip()

    def enrich_finding(self, finding: Finding) -> dict[str, Any]:
        observables = extract_observables(finding.evidence_json)
        if not self.api_key:
            return {
                "provider": self.provider,
                "status": "disabled",
                "message": "VirusTotal enrichment requires an API key in Settings.",
                "observables": [_serialize_observable(observable) for observable in observables],
                "results": [],
            }
        results: list[dict[str, Any]] = []
        for observable in observables:
            results.append(self._lookup(observable))
        match_count = sum(1 for item in results if item.get("status") == "match")
        return {
            "provider": self.provider,
            "status": "ok",
            "message": f"Checked {len(observables)} observable(s); {match_count} produced VirusTotal match result(s).",
            "observables": [_serialize_observable(observable) for observable in observables],
            "results": results,
        }

    def enrich_software(self, record: dict[str, Any]) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "status": "unsupported",
            "message": "VirusTotal enrichment supports hashes, IPs, domains, and URLs, not package-version inventory matching.",
            "record": _serialize_software_record(record),
            "results": [],
        }

    def _lookup(self, observable: Observable) -> dict[str, Any]:
        path = _virustotal_path_for_observable(observable)
        if not path:
            return {
                "observable": _serialize_observable(observable),
                "status": "unsupported",
                "message": f"Observable type {observable.type} is not supported by VirusTotal lookup.",
                "matches": [],
            }
        try:
            response_json = self._get_json(path)
        except RuntimeError as exc:
            return {
                "observable": _serialize_observable(observable),
                "status": "error",
                "message": str(exc),
                "matches": [],
            }
        data = response_json.get("data") or {}
        attributes = data.get("attributes") or {}
        summary = {
            "id": data.get("id"),
            "type": data.get("type"),
            "reputation": attributes.get("reputation"),
            "last_analysis_stats": attributes.get("last_analysis_stats"),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "categories": attributes.get("categories"),
            "meaningful_name": attributes.get("meaningful_name"),
        }
        return {
            "observable": _serialize_observable(observable),
            "status": "match" if data else "no_match",
            "matches": [summary] if data else [],
        }

    def _get_json(self, path: str) -> dict[str, Any]:
        req = request.Request(
            f"{self.api_base}{path}",
            headers={"x-apikey": self.api_key},
            method="GET",
        )
        try:
            with request.urlopen(req, timeout=15) as response:
                body = response.read().decode("utf-8")
        except error.HTTPError as exc:
            if exc.code == 404:
                return {}
            raise RuntimeError(f"VirusTotal lookup failed with HTTP {exc.code}.") from exc
        except error.URLError as exc:
            raise RuntimeError(f"VirusTotal lookup failed: {exc.reason}") from exc
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise RuntimeError("VirusTotal lookup returned invalid JSON.") from exc


class NvdKevEnricher:
    provider = "nvd_kev"
    nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key.strip()

    def enrich_finding(self, finding: Finding) -> dict[str, Any]:
        observables = [_serialize_observable(observable) for observable in extract_observables(finding.evidence_json)]
        return {
            "provider": self.provider,
            "status": "unsupported",
            "message": "NVD and CISA KEV enrichment is intended for software inventory records, not IOC-style finding observables.",
            "observables": observables,
            "results": [],
        }

    def enrich_software(self, record: dict[str, Any]) -> dict[str, Any]:
        software = _serialize_software_record(record)
        query = " ".join(part for part in [software["name"], software["version"]] if part).strip()
        if not query:
            return {
                "provider": self.provider,
                "status": "error",
                "message": "Software enrichment requires a package name.",
                "record": software,
                "results": [],
            }
        try:
            nvd_results = self._get_nvd_results(query)
            kev_map = self._get_kev_map()
        except RuntimeError as exc:
            return {
                "provider": self.provider,
                "status": "error",
                "message": str(exc),
                "record": software,
                "results": [],
            }
        results: list[dict[str, Any]] = []
        kev_matches = 0
        for item in nvd_results:
            cve = item.get("cve") or {}
            cve_id = str(cve.get("id") or "")
            kev = kev_map.get(cve_id, {})
            if kev:
                kev_matches += 1
            results.append(
                {
                    "cve_id": cve_id,
                    "description": _english_description(cve),
                    "cvss_score": _best_cvss_score((cve.get("metrics") or {})),
                    "published": cve.get("published"),
                    "last_modified": cve.get("lastModified"),
                    "kev": {
                        "listed": bool(kev),
                        "date_added": kev.get("dateAdded"),
                        "due_date": kev.get("dueDate"),
                        "required_action": kev.get("requiredAction"),
                        "known_ransomware_campaign_use": kev.get("knownRansomwareCampaignUse"),
                    },
                }
            )
        return {
            "provider": self.provider,
            "status": "match" if results else "no_match",
            "message": f"Checked software inventory record against NVD; found {len(results)} CVE candidate(s), {kev_matches} present in CISA KEV.",
            "record": software,
            "results": results[:20],
        }

    def _get_nvd_results(self, query: str) -> list[dict[str, Any]]:
        params = parse.urlencode({"keywordSearch": query, "resultsPerPage": 10})
        req = request.Request(self.nvd_api_url + "?" + params, headers=self._headers(), method="GET")
        response_json = self._load_json(req, not_found_returns={})
        return list(response_json.get("vulnerabilities") or [])

    def _get_kev_map(self) -> dict[str, dict[str, Any]]:
        req = request.Request(self.kev_url, headers=self._headers(), method="GET")
        response_json = self._load_json(req, not_found_returns={})
        vulnerabilities = response_json.get("vulnerabilities") or []
        return {
            str(item.get("cveID") or ""): item
            for item in vulnerabilities
            if str(item.get("cveID") or "")
        }

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    def _load_json(self, req: request.Request, not_found_returns: dict[str, Any]) -> dict[str, Any]:
        try:
            with request.urlopen(req, timeout=20) as response:
                body = response.read().decode("utf-8")
        except error.HTTPError as exc:
            if exc.code == 404:
                return not_found_returns
            raise RuntimeError(f"NVD/KEV lookup failed with HTTP {exc.code}.") from exc
        except error.URLError as exc:
            raise RuntimeError(f"NVD/KEV lookup failed: {exc.reason}") from exc
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise RuntimeError("NVD/KEV lookup returned invalid JSON.") from exc


def _virustotal_path_for_observable(observable: Observable) -> str:
    if observable.type == "ip":
        return f"/ip_addresses/{parse.quote(observable.value, safe='')}"
    if observable.type == "domain":
        return f"/domains/{parse.quote(observable.value, safe='')}"
    if observable.type in {"md5", "sha1", "sha256"}:
        return f"/files/{parse.quote(observable.value, safe='')}"
    if observable.type == "url":
        return f"/urls/{_virustotal_url_id(observable.value)}"
    return ""


def _virustotal_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def _english_description(cve: dict[str, Any]) -> str:
    descriptions = cve.get("descriptions") or []
    for item in descriptions:
        if str(item.get("lang") or "").lower() == "en":
            return str(item.get("value") or "")
    return str(descriptions[0].get("value") or "") if descriptions else ""


def _best_cvss_score(metrics: dict[str, Any]) -> float | None:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if not values:
            continue
        cvss_data = (values[0] or {}).get("cvssData") or {}
        score = cvss_data.get("baseScore")
        if score is not None:
            try:
                return float(score)
            except (TypeError, ValueError):
                return None
    return None


def extract_observables(value: Any) -> list[Observable]:
    seen: set[tuple[str, str]] = set()
    observables: list[Observable] = []

    def add(observable_type: str, observable_value: str, source: str) -> None:
        normalized = observable_value.strip()
        if not normalized:
            return
        key = (observable_type, normalized.lower() if observable_type in {"domain", "url"} else normalized)
        if key in seen:
            return
        seen.add(key)
        observables.append(Observable(observable_type, normalized, source))

    def visit(item: Any, source: str) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                visit(child, str(key))
            return
        if isinstance(item, list):
            for child in item:
                visit(child, source)
            return
        if item is None:
            return

        text = str(item)
        source_name = source or "value"

        if source_name in {"raddr", "laddr"} and ":" in text:
            host, _, _ = text.rpartition(":")
            text = host or text

        for match in URL_RE.findall(text):
            add("url", match, source_name)
            hostname = parse.urlparse(match).hostname or ""
            if hostname:
                add("ip" if IPV4_RE.fullmatch(hostname) else "domain", hostname, source_name)

        for match in SHA256_RE.findall(text):
            add("sha256", match, source_name)
        for match in SHA1_RE.findall(text):
            add("sha1", match, source_name)
        for match in MD5_RE.findall(text):
            add("md5", match, source_name)
        for match in IPV4_RE.findall(text):
            add("ip", match, source_name)
        if source_name in {"raddr", "remote_host", "domain", "hostname"}:
            host_value = text.strip()
            if DOMAIN_RE.fullmatch(host_value) and not IPV4_RE.fullmatch(host_value):
                add("domain", host_value, source_name)
        for match in DOMAIN_RE.findall(text):
            if not IPV4_RE.fullmatch(match):
                add("domain", match, source_name)

    visit(value, "evidence")
    return observables
