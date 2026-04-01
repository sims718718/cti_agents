"""RSS/Atom feed collection."""
from __future__ import annotations

import re
from typing import Any

import feedparser


def _clean_html(text: str) -> str:
    """Strip HTML tags from summary text."""
    return re.sub(r"<[^>]+>", " ", text or "").strip()


def fetch_rss_feeds(
    feed_configs: list[dict],
    limit_per_feed: int = 5,
    errors: list | None = None,
) -> list[dict[str, Any]]:
    """Fetch and parse a list of RSS/Atom feed configs.

    Args:
        feed_configs: List of {"name": str, "url": str} dicts.
        limit_per_feed: Max entries to collect per feed.
        errors: If provided, per-feed fetch failures are appended here as
            {"feed": name, "error": message} dicts instead of being silently
            dropped.

    Returns:
        List of article dicts ready for analysis.
    """
    articles: list[dict] = []

    for cfg in feed_configs:
        try:
            # feedparser handles both RSS and Atom transparently
            feed = feedparser.parse(cfg["url"])
            for entry in feed.entries[:limit_per_feed]:
                articles.append(
                    {
                        "source": cfg["name"],
                        "title": entry.get("title", ""),
                        "summary": _clean_html(
                            entry.get("summary", entry.get("description", ""))
                        )[:1200],
                        "link": entry.get("link", ""),
                        "published": entry.get("published", ""),
                        "type": "news_article",
                    }
                )
        except Exception as exc:
            if errors is not None:
                errors.append({"feed": cfg.get("name", cfg.get("url", "unknown")), "error": str(exc)})

    return articles
