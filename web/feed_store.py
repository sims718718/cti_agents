"""Persistent custom feed store.

Built-in feeds come from config.py; custom feeds are persisted to
reports/custom_feeds.json and merged in at runtime.
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path

from config import API_FEEDS, RSS_FEEDS

_STORE_PATH = Path(__file__).parent.parent / "reports" / "custom_feeds.json"


def _load_custom() -> dict:
    """Return custom feeds dict from disk, creating the file if missing."""
    _STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    if _STORE_PATH.exists():
        try:
            return json.loads(_STORE_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"rss": [], "api": []}


def _save_custom(data: dict) -> None:
    _STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _STORE_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")


def get_all_feeds() -> dict:
    """Return merged built-in + custom feeds, each entry with a 'builtin' flag."""
    custom = _load_custom()

    rss_feeds = [
        {**f, "builtin": True}
        for f in RSS_FEEDS
    ]
    rss_feeds += [
        {**f, "builtin": False}
        for f in custom.get("rss", [])
    ]

    api_feeds = []
    for key, cfg in API_FEEDS.items():
        api_feeds.append({
            "id": key,
            "name": cfg.get("description", key),
            "url": cfg["url"],
            "method": cfg.get("method", "GET"),
            "builtin": True,
        })
    api_feeds += [
        {**f, "builtin": False}
        for f in custom.get("api", [])
    ]

    return {"rss": rss_feeds, "api": api_feeds}


def add_rss_feed(name: str, url: str) -> dict:
    """Append a custom RSS feed and return the new feed dict."""
    custom = _load_custom()
    feed = {"id": str(uuid.uuid4()), "name": name, "url": url}
    custom.setdefault("rss", []).append(feed)
    _save_custom(custom)
    return {**feed, "builtin": False}


def add_api_feed(name: str, url: str, method: str = "GET") -> dict:
    """Append a custom API feed and return the new feed dict."""
    custom = _load_custom()
    feed = {"id": str(uuid.uuid4()), "name": name, "url": url, "method": method}
    custom.setdefault("api", []).append(feed)
    _save_custom(custom)
    return {**feed, "builtin": False}


def delete_feed(feed_id: str) -> bool:
    """Remove a custom feed by ID (built-ins are silently ignored).

    Returns True if a feed was deleted, False otherwise.
    """
    custom = _load_custom()
    original_rss = list(custom.get("rss", []))
    original_api = list(custom.get("api", []))

    custom["rss"] = [f for f in original_rss if f.get("id") != feed_id]
    custom["api"] = [f for f in original_api if f.get("id") != feed_id]

    deleted = len(custom["rss"]) < len(original_rss) or len(custom["api"]) < len(original_api)
    if deleted:
        _save_custom(custom)
    return deleted
