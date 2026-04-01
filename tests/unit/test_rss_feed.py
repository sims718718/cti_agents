"""Unit tests for feeds/rss_feed.py."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from feeds.rss_feed import _clean_html, fetch_rss_feeds


class TestCleanHtml:
    def test_strips_tags(self):
        assert _clean_html("<b>Alert</b>") == "Alert"

    def test_strips_nested_tags(self):
        # Each tag is replaced with a space, so extra whitespace may appear;
        # the important thing is that tag characters are removed and content preserved.
        result = _clean_html("<p><b>Bold</b> text</p>")
        assert "<" not in result and ">" not in result
        assert "Bold" in result and "text" in result

    def test_empty_string(self):
        assert _clean_html("") == ""

    def test_none_input(self):
        assert _clean_html(None) == ""

    def test_plain_text_unchanged(self):
        assert _clean_html("No tags here") == "No tags here"


class TestFetchRssFeeds:
    CONFIGS = [{"id": "test", "name": "Test Feed", "url": "https://example.com/feed"}]

    def _make_entry(self, title="Alert", summary="Summary text", link="https://example.com/1", published="Mon, 01 Jan 2024"):
        entry = MagicMock()
        entry.get = lambda k, default="": {
            "title": title, "summary": summary, "link": link, "published": published
        }.get(k, default)
        return entry

    def _make_feed(self, entries):
        feed = MagicMock()
        feed.entries = entries
        return feed

    @patch("feeds.rss_feed.feedparser.parse")
    def test_returns_articles(self, mock_parse):
        mock_parse.return_value = self._make_feed([self._make_entry()])
        result = fetch_rss_feeds(self.CONFIGS, limit_per_feed=5)
        assert len(result) == 1
        assert result[0]["source"] == "Test Feed"
        assert result[0]["type"] == "news_article"

    @patch("feeds.rss_feed.feedparser.parse")
    def test_limit_per_feed_respected(self, mock_parse):
        mock_parse.return_value = self._make_feed([self._make_entry(f"Article {i}") for i in range(10)])
        result = fetch_rss_feeds(self.CONFIGS, limit_per_feed=3)
        assert len(result) == 3

    @patch("feeds.rss_feed.feedparser.parse")
    def test_html_stripped_from_summary(self, mock_parse):
        mock_parse.return_value = self._make_feed([self._make_entry(summary="<b>Bold</b> text")])
        result = fetch_rss_feeds(self.CONFIGS)
        assert "<b>" not in result[0]["summary"]
        assert "Bold" in result[0]["summary"]

    @patch("feeds.rss_feed.feedparser.parse")
    def test_exception_appended_to_errors(self, mock_parse):
        mock_parse.side_effect = Exception("Connection refused")
        errors = []
        result = fetch_rss_feeds(self.CONFIGS, errors=errors)
        assert result == []
        assert len(errors) == 1
        assert errors[0]["feed"] == "Test Feed"

    @patch("feeds.rss_feed.feedparser.parse")
    def test_exception_without_errors_list_swallowed(self, mock_parse):
        mock_parse.side_effect = Exception("Connection refused")
        result = fetch_rss_feeds(self.CONFIGS)  # no errors list
        assert result == []

    @patch("feeds.rss_feed.feedparser.parse")
    def test_multiple_feeds_aggregated(self, mock_parse):
        mock_parse.return_value = self._make_feed([self._make_entry()])
        configs = [
            {"name": "Feed A", "url": "https://a.com"},
            {"name": "Feed B", "url": "https://b.com"},
        ]
        result = fetch_rss_feeds(configs, limit_per_feed=5)
        assert len(result) == 2

    @patch("feeds.rss_feed.feedparser.parse")
    def test_one_feed_fails_others_still_collected(self, mock_parse):
        good_feed = self._make_feed([self._make_entry(title="Good")])
        mock_parse.side_effect = [Exception("fail"), good_feed]
        configs = [
            {"name": "Bad Feed", "url": "https://bad.com"},
            {"name": "Good Feed", "url": "https://good.com"},
        ]
        errors = []
        result = fetch_rss_feeds(configs, errors=errors)
        assert len(result) == 1
        assert result[0]["source"] == "Good Feed"
        assert len(errors) == 1
