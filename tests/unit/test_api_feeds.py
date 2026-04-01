"""Unit tests for feeds/api_feeds.py using the responses library."""
from __future__ import annotations

import json

import pytest
import responses as resp_mock

from feeds.api_feeds import (
    TIMEOUT,
    fetch_cisa_kev,
    fetch_feodo_tracker,
    fetch_malware_bazaar,
    fetch_threatfox,
    fetch_urlhaus,
    fetch_generic_api,
)


# ── Feodo Tracker ─────────────────────────────────────────────────────────────

class TestFetchFeodoTracker:
    FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

    @resp_mock.activate
    def test_success_returns_ip_list(self):
        resp_mock.add(
            resp_mock.GET,
            self.FEODO_URL,
            json=[
                {"ip_address": "192.0.2.1", "port": 443, "malware": "Emotet",
                 "first_seen": "2024-01-01", "last_online": "2024-02-01", "country": "RU"},
            ],
        )
        result = fetch_feodo_tracker(limit=10)
        assert len(result) == 1
        assert result[0]["ip"] == "192.0.2.1"
        assert result[0]["type"] == "ip_indicator"
        assert result[0]["source"] == "Feodo Tracker"

    @resp_mock.activate
    def test_limit_respected(self):
        resp_mock.add(
            resp_mock.GET,
            self.FEODO_URL,
            json=[{"ip_address": f"192.0.2.{i}", "malware": "Emotet"} for i in range(50)],
        )
        result = fetch_feodo_tracker(limit=5)
        assert len(result) == 5

    @resp_mock.activate
    def test_http_error_raises(self):
        resp_mock.add(resp_mock.GET, self.FEODO_URL, status=500)
        with pytest.raises(Exception):
            fetch_feodo_tracker()

    @resp_mock.activate
    def test_non_list_response_returns_empty(self):
        resp_mock.add(resp_mock.GET, self.FEODO_URL, json={"error": "not a list"})
        result = fetch_feodo_tracker()
        assert result == []

    @resp_mock.activate
    def test_missing_optional_fields_handled(self):
        resp_mock.add(resp_mock.GET, self.FEODO_URL, json=[{"ip_address": "10.0.0.1"}])
        result = fetch_feodo_tracker(limit=1)
        assert result[0]["ip"] == "10.0.0.1"
        assert result[0]["malware"] == ""


# ── ThreatFox ─────────────────────────────────────────────────────────────────

class TestFetchThreatFox:
    THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"

    @resp_mock.activate
    def test_success_returns_ioc_list(self):
        resp_mock.add(
            resp_mock.POST,
            self.THREATFOX_URL,
            json={
                "query_status": "ok",
                "data": [
                    {"ioc": "192.0.2.100", "ioc_type": "ip:port", "threat_type": "botnet",
                     "malware": "Mirai", "confidence_level": 90, "first_seen": "2024-02-15", "tags": ["iot"]},
                ],
            },
        )
        result = fetch_threatfox()
        assert len(result) == 1
        assert result[0]["ioc_value"] == "192.0.2.100"
        assert result[0]["type"] == "ioc"
        assert result[0]["source"] == "ThreatFox"

    @resp_mock.activate
    def test_non_ok_status_returns_empty(self):
        resp_mock.add(resp_mock.POST, self.THREATFOX_URL, json={"query_status": "no_results"})
        assert fetch_threatfox() == []

    @resp_mock.activate
    def test_http_error_raises(self):
        resp_mock.add(resp_mock.POST, self.THREATFOX_URL, status=429)
        with pytest.raises(Exception):
            fetch_threatfox()

    @resp_mock.activate
    def test_limit_respected(self):
        resp_mock.add(
            resp_mock.POST,
            self.THREATFOX_URL,
            json={"query_status": "ok", "data": [{"ioc": f"10.0.0.{i}"} for i in range(20)]},
        )
        result = fetch_threatfox(limit=5)
        assert len(result) == 5


# ── URLhaus ───────────────────────────────────────────────────────────────────

class TestFetchUrlhaus:
    URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

    @resp_mock.activate
    def test_success(self):
        resp_mock.add(
            resp_mock.GET,
            self.URLHAUS_URL,
            json={
                "query_status": "ok",
                "urls": [
                    {"url": "http://evil.example.com/payload", "url_status": "online",
                     "threat": "malware_download", "date_added": "2024-02-15 10:00:00", "tags": [], "host": "evil.example.com"},
                ],
            },
        )
        result = fetch_urlhaus(limit=5)
        assert len(result) == 1
        assert result[0]["type"] == "url_indicator"
        assert result[0]["source"] == "URLhaus"

    @resp_mock.activate
    def test_non_dict_response_returns_empty(self):
        resp_mock.add(resp_mock.GET, self.URLHAUS_URL, json=[])
        assert fetch_urlhaus() == []

    @resp_mock.activate
    def test_http_error_raises(self):
        resp_mock.add(resp_mock.GET, self.URLHAUS_URL, status=503)
        with pytest.raises(Exception):
            fetch_urlhaus()


# ── MalwareBazaar ─────────────────────────────────────────────────────────────

class TestFetchMalwareBazaar:
    MB_URL = "https://mb-api.abuse.ch/api/v1/"

    @resp_mock.activate
    def test_success(self):
        resp_mock.add(
            resp_mock.POST,
            self.MB_URL,
            json={
                "query_status": "ok",
                "data": [
                    {"sha256_hash": "abc123", "file_name": "evil.exe", "file_type": "exe",
                     "signature": "AgentTesla", "first_seen": "2024-02-10", "tags": [], "reporter": "user1"},
                ],
            },
        )
        result = fetch_malware_bazaar(limit=5)
        assert len(result) == 1
        assert result[0]["sha256"] == "abc123"
        assert result[0]["type"] == "malware_sample"

    @resp_mock.activate
    def test_non_ok_status_returns_empty(self):
        resp_mock.add(resp_mock.POST, self.MB_URL, json={"query_status": "error"})
        assert fetch_malware_bazaar() == []


# ── CISA KEV ──────────────────────────────────────────────────────────────────

class TestFetchCisaKev:
    CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    @resp_mock.activate
    def test_success_returns_vulns(self):
        resp_mock.add(
            resp_mock.GET,
            self.CISA_URL,
            json={
                "vulnerabilities": [
                    {"cveID": "CVE-2024-0001", "vendorProject": "Acme", "product": "Widget",
                     "vulnerabilityName": "RCE Vuln", "dateAdded": "2024-01-01",
                     "shortDescription": "RCE", "requiredAction": "Patch", "dueDate": "2024-02-01"},
                    {"cveID": "CVE-2024-0002", "vendorProject": "Corp", "product": "Thing",
                     "vulnerabilityName": "SQLi", "dateAdded": "2024-01-15",
                     "shortDescription": "SQLi", "requiredAction": "Patch", "dueDate": "2024-02-15"},
                ]
            },
        )
        result = fetch_cisa_kev(limit=5)
        assert len(result) == 2
        assert result[0]["type"] == "vulnerability"
        assert result[0]["source"] == "CISA KEV"
        cve_ids = [v["cve_id"] for v in result]
        assert "CVE-2024-0001" in cve_ids

    @resp_mock.activate
    def test_non_dict_response_returns_empty(self):
        resp_mock.add(resp_mock.GET, self.CISA_URL, json=[])
        assert fetch_cisa_kev() == []

    @resp_mock.activate
    def test_http_error_raises(self):
        resp_mock.add(resp_mock.GET, self.CISA_URL, status=404)
        with pytest.raises(Exception):
            fetch_cisa_kev()


# ── fetch_generic_api ─────────────────────────────────────────────────────────

class TestFetchGenericApi:
    URL = "https://api.example.com/intel"

    @resp_mock.activate
    def test_list_response(self):
        resp_mock.add(resp_mock.GET, self.URL, json=[{"id": 1}, {"id": 2}])
        result = fetch_generic_api(self.URL, limit=10)
        assert len(result) == 2
        assert result[0]["type"] == "generic_intel"

    @resp_mock.activate
    def test_nested_data_key(self):
        resp_mock.add(resp_mock.GET, self.URL, json={"data": [{"id": 1}, {"id": 2}]})
        result = fetch_generic_api(self.URL, limit=10)
        assert len(result) == 2

    @resp_mock.activate
    def test_limit_respected(self):
        resp_mock.add(resp_mock.GET, self.URL, json=[{"id": i} for i in range(100)])
        result = fetch_generic_api(self.URL, limit=10)
        assert len(result) == 10

    @resp_mock.activate
    def test_http_error_raises(self):
        resp_mock.add(resp_mock.GET, self.URL, status=500)
        with pytest.raises(Exception):
            fetch_generic_api(self.URL)
