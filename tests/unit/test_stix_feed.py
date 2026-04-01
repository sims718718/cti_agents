"""Unit tests for feeds/stix_feed.py."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import responses as resp_mock

from feeds.stix_feed import _parse_bundle, fetch_from_file, fetch_from_url


SAMPLE_BUNDLE = {
    "type": "bundle",
    "objects": [
        {
            "id": "malware--1",
            "type": "malware",
            "name": "Emotet",
            "description": "Banking trojan",
            "malware_types": ["trojan"],
            "created": "2024-01-01T00:00:00Z",
            "modified": "2024-02-01T00:00:00Z",
        },
        {
            "id": "identity--1",
            "type": "identity",  # NOT in RELEVANT_TYPES — should be filtered
            "name": "Some Org",
        },
        {
            "id": "threat-actor--1",
            "type": "threat-actor",
            "name": "APT28",
            "description": "Russian threat actor",
        },
    ],
}


class TestParseBundleFilterTypes:
    def test_filters_to_relevant_types(self):
        result = _parse_bundle(SAMPLE_BUNDLE, limit=20)
        types = {obj["type"] for obj in result}
        assert "identity" not in types

    def test_includes_relevant_types(self):
        result = _parse_bundle(SAMPLE_BUNDLE, limit=20)
        types = {obj["type"] for obj in result}
        assert "malware" in types
        assert "threat-actor" in types

    def test_limit_enforced(self):
        result = _parse_bundle(SAMPLE_BUNDLE, limit=1)
        assert len(result) == 1

    def test_empty_bundle(self):
        result = _parse_bundle({"objects": []}, limit=20)
        assert result == []

    def test_missing_objects_key(self):
        result = _parse_bundle({}, limit=20)
        assert result == []


class TestFetchFromUrl:
    BUNDLE_URL = "https://example.com/stix-bundle.json"

    @resp_mock.activate
    def test_success_returns_objects(self):
        resp_mock.add(resp_mock.GET, self.BUNDLE_URL, json=SAMPLE_BUNDLE)
        result = fetch_from_url(self.BUNDLE_URL, limit=20)
        assert len(result) == 2  # malware + threat-actor (identity filtered out)

    @resp_mock.activate
    def test_http_error_raises(self):
        resp_mock.add(resp_mock.GET, self.BUNDLE_URL, status=404)
        with pytest.raises(Exception):
            fetch_from_url(self.BUNDLE_URL)

    @resp_mock.activate
    def test_limit_respected(self):
        resp_mock.add(resp_mock.GET, self.BUNDLE_URL, json=SAMPLE_BUNDLE)
        result = fetch_from_url(self.BUNDLE_URL, limit=1)
        assert len(result) == 1


class TestFetchFromFile:
    def test_success_reads_and_parses(self, tmp_path):
        bundle_file = tmp_path / "bundle.json"
        bundle_file.write_text(json.dumps(SAMPLE_BUNDLE), encoding="utf-8")
        result = fetch_from_file(str(bundle_file), limit=20)
        assert len(result) == 2

    def test_nonexistent_file_raises(self):
        with pytest.raises(FileNotFoundError):
            fetch_from_file("/nonexistent/path/bundle.json")

    def test_invalid_json_raises(self, tmp_path):
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not valid json {{", encoding="utf-8")
        with pytest.raises(Exception):
            fetch_from_file(str(bad_file))

    def test_limit_respected(self, tmp_path):
        bundle_file = tmp_path / "bundle.json"
        bundle_file.write_text(json.dumps(SAMPLE_BUNDLE), encoding="utf-8")
        result = fetch_from_file(str(bundle_file), limit=1)
        assert len(result) == 1


class TestFetchFromTaxii:
    def test_taxii_unavailable_returns_empty(self):
        """When taxii2-client is not installed, returns empty list silently."""
        with patch("feeds.stix_feed.TAXII_AVAILABLE", False):
            from feeds.stix_feed import fetch_from_taxii
            result = fetch_from_taxii("https://example.com/taxii", "collection-id")
            assert result == []

    def test_empty_api_roots_raises(self):
        """TAXII server with no API roots raises ValueError (Phase 1.4 fix)."""
        mock_server = MagicMock()
        mock_server.api_roots = []  # empty — previously caused IndexError

        with patch("feeds.stix_feed.TAXII_AVAILABLE", True), \
             patch("feeds.stix_feed.TaxiiServer", return_value=mock_server):
            from feeds.stix_feed import fetch_from_taxii
            with pytest.raises(ValueError, match="no API roots"):
                fetch_from_taxii("https://example.com/taxii", "collection-id")

    def test_collection_not_found_raises(self):
        mock_server = MagicMock()
        mock_collection = MagicMock()
        mock_collection.id = "other-id"
        mock_server.api_roots = [MagicMock()]
        mock_server.api_roots[0].collections = [mock_collection]

        with patch("feeds.stix_feed.TAXII_AVAILABLE", True), \
             patch("feeds.stix_feed.TaxiiServer", return_value=mock_server):
            from feeds.stix_feed import fetch_from_taxii
            with pytest.raises(ValueError, match="not found"):
                fetch_from_taxii("https://example.com/taxii", "target-collection-id")
