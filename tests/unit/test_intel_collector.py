"""Unit tests for IntelCollectorAgent."""
from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from agents.intel_collector import IntelCollectorAgent


# ── _filter_by_time ────────────────────────────────────────────────────────────

class TestFilterByTime:
    """Tests for IntelCollectorAgent._filter_by_time."""

    ITEMS = [
        {"id": 1, "published": "2024-01-15T10:00:00Z"},
        {"id": 2, "published": "2024-02-15T10:00:00Z"},
        {"id": 3, "published": "2024-03-15T10:00:00Z"},
    ]

    def _filter(self, items, time_from=None, time_to=None, field="published"):
        return IntelCollectorAgent._filter_by_time(items, field, time_from, time_to)

    def test_no_bounds_returns_all(self):
        result = self._filter(self.ITEMS)
        assert len(result) == 3

    def test_time_from_excludes_older_items(self):
        cutoff = datetime(2024, 2, 1, tzinfo=timezone.utc)
        result = self._filter(self.ITEMS, time_from=cutoff)
        ids = {i["id"] for i in result}
        assert 1 not in ids
        assert 2 in ids
        assert 3 in ids

    def test_time_to_excludes_newer_items(self):
        cutoff = datetime(2024, 2, 28, tzinfo=timezone.utc)
        result = self._filter(self.ITEMS, time_to=cutoff)
        ids = {i["id"] for i in result}
        assert 1 in ids
        assert 2 in ids
        assert 3 not in ids

    def test_window_only_includes_middle_item(self):
        time_from = datetime(2024, 2, 1, tzinfo=timezone.utc)
        time_to = datetime(2024, 2, 28, tzinfo=timezone.utc)
        result = self._filter(self.ITEMS, time_from=time_from, time_to=time_to)
        assert len(result) == 1
        assert result[0]["id"] == 2

    def test_boundary_is_inclusive(self):
        # Item published exactly at the cutoff should be included
        items = [{"id": 1, "published": "2024-02-15T10:00:00Z"}]
        time_from = datetime(2024, 2, 15, 10, 0, 0, tzinfo=timezone.utc)
        result = self._filter(items, time_from=time_from)
        assert len(result) == 1

    def test_no_timestamp_field_kept(self):
        """Items with no timestamp field are always kept (no time context)."""
        items = [{"id": 1}, {"id": 2, "published": "2024-02-15T10:00:00Z"}]
        time_from = datetime(2024, 3, 1, tzinfo=timezone.utc)
        result = self._filter(items, time_from=time_from)
        # Item 1 (no field) kept, item 2 (old) excluded
        ids = {i["id"] for i in result}
        assert 1 in ids
        assert 2 not in ids

    def test_unparseable_timestamp_excluded(self):
        """Unparseable timestamps are excluded (fail-closed)."""
        items = [
            {"id": 1, "published": "not-a-date"},
            {"id": 2, "published": "2024-02-15T10:00:00Z"},
        ]
        time_from = datetime(2024, 1, 1, tzinfo=timezone.utc)
        result = self._filter(items, time_from=time_from)
        ids = {i["id"] for i in result}
        assert 1 not in ids  # unparseable → excluded
        assert 2 in ids

    def test_naive_time_from_coerced_to_utc(self):
        """Naive time_from/time_to bounds are treated as UTC."""
        items = [{"id": 1, "published": "2024-02-15T10:00:00Z"}]
        naive_from = datetime(2024, 1, 1)  # no tzinfo
        result = self._filter(items, time_from=naive_from)
        assert len(result) == 1  # item is after naive Jan 1

    def test_empty_items_returns_empty(self):
        assert self._filter([], time_from=datetime(2024, 1, 1, tzinfo=timezone.utc)) == []

    def test_different_time_field(self):
        items = [{"id": 1, "first_seen": "2024-02-15"}]
        time_from = datetime(2024, 2, 1, tzinfo=timezone.utc)
        result = IntelCollectorAgent._filter_by_time(items, "first_seen", time_from, None)
        assert len(result) == 1


# ── run() error collection ─────────────────────────────────────────────────────

class TestRunErrorCollection:
    """Tests that feed failures are collected in raw['errors']."""

    FEEDS = {
        "rss": [{"id": "sans", "name": "SANS ISC", "url": "https://example.com"}],
        "api": {
            "feodo_tracker": {"description": "Feodo"},
        },
        "stix": {},
    }
    LIMITS = {"rss_per_feed": 5, "feodo_ips": 25}

    @patch("agents.intel_collector.fetch_rss_feeds")
    def test_rss_exception_appended_to_errors(self, mock_rss):
        mock_rss.side_effect = RuntimeError("Connection refused")
        collector = IntelCollectorAgent()
        raw = collector.run(self.FEEDS, feed_types=["rss"], limits=self.LIMITS)
        assert any("RSS" in e.get("feed", "") for e in raw["errors"])

    @patch("agents.intel_collector.fetch_feodo_tracker")
    def test_api_exception_appended_to_errors(self, mock_feodo):
        mock_feodo.side_effect = ConnectionError("Network timeout")
        collector = IntelCollectorAgent()
        raw = collector.run(self.FEEDS, feed_types=["api"], limits=self.LIMITS)
        errors = raw["errors"]
        assert any("Feodo" in e.get("feed", "") for e in errors)

    @patch("agents.intel_collector.fetch_from_taxii")
    def test_stix_exception_appended_to_errors(self, mock_taxii):
        mock_taxii.side_effect = ValueError("No API roots")
        feeds = {
            "rss": [],
            "api": {},
            "stix": {
                "mitre": {
                    "type": "taxii",
                    "url": "https://example.com/taxii",
                    "collection_id": "test-id",
                    "description": "MITRE",
                }
            },
        }
        collector = IntelCollectorAgent()
        raw = collector.run(feeds, feed_types=["stix"], limits=self.LIMITS)
        assert any("STIX" in e.get("feed", "") for e in raw["errors"])

    @patch("agents.intel_collector.fetch_rss_feeds")
    def test_successful_feed_no_errors(self, mock_rss):
        mock_rss.return_value = [
            {"source": "SANS ISC", "title": "Test", "type": "news_article"}
        ]
        collector = IntelCollectorAgent()
        raw = collector.run(self.FEEDS, feed_types=["rss"], limits=self.LIMITS)
        assert raw["errors"] == []
        assert len(raw["news_articles"]) == 1

    @patch("agents.intel_collector.process_uploads")
    def test_document_errors_appended(self, mock_uploads):
        mock_uploads.return_value = (
            [{"type": "document_intel", "source": "good.txt", "content": "ok", "char_count": 2, "doc_type": "document"}],
            [{"source": "bad.pdf", "error": "pypdf not installed"}],
        )
        collector = IntelCollectorAgent()
        feeds = {"rss": [], "api": {}, "stix": {}}
        raw = collector.run(feeds, feed_types=[], limits={}, document_uploads=[{"filename": "x"}])
        assert len(raw["document_intel"]) == 1
        assert any("bad.pdf" in e.get("source", "") for e in raw["errors"])
