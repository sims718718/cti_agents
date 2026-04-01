"""Intel Collector Agent.

Responsibility: Pull raw OSINT from RSS feeds, REST APIs, and STIX sources.
This agent does NOT call an LLM – it's a pure data-collection worker.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

try:
    from dateutil import parser as _dateutil_parser
    _HAS_DATEUTIL = True
except ImportError:
    _HAS_DATEUTIL = False

from feeds.api_feeds import (
    fetch_cisa_kev,
    fetch_feodo_tracker,
    fetch_generic_api,
    fetch_malware_bazaar,
    fetch_threatfox,
    fetch_urlhaus,
)
from feeds.document_feed import process_uploads
from feeds.rss_feed import fetch_rss_feeds
from feeds.stix_feed import fetch_from_file, fetch_from_taxii, fetch_from_url

# Maps built-in API feed IDs → set of valid IDs used by _fetch_api_feeds().
# The actual dispatch lives inside _fetch_api_feeds for clarity.
BUILTIN_API_HANDLERS: dict = {
    "feodo_tracker": True,
    "threatfox":     True,
    "urlhaus":       True,
    "malware_bazaar":True,
    "cisa_kev":      True,
}


class IntelCollectorAgent:
    """Aggregates raw OSINT from all configured sources."""

    def run(
        self,
        feeds: dict,
        feed_types: list[str] | None = None,
        limits: dict | None = None,
        document_uploads: list[dict] | None = None,
        selected_rss_feeds: list[dict] | None = None,
        selected_api_feeds: list[dict] | None = None,
        time_from: datetime | None = None,
        time_to: datetime | None = None,
    ) -> dict[str, Any]:
        """Collect intelligence from all requested feed types.

        Args:
            feeds: Feed configuration dict (from config.FEEDS).
            feed_types: Which feed categories to use: ["rss", "api", "stix"].
                        Defaults to ["rss", "api"].
            limits: Override per-source item limits.
            document_uploads: List of uploaded document dicts
                (keys: filename, content_type, bytes) to inject as document_intel.
            selected_rss_feeds: If provided, only fetch these RSS feeds (list of
                feed dicts with at least 'id', 'name', 'url').
            selected_api_feeds: If provided, only fetch these API feeds (list of
                feed dicts with at least 'id', 'name').
            time_from: If set, discard items published before this UTC datetime.
            time_to: If set, discard items published after this UTC datetime.

        Returns:
            Raw intel dict keyed by data type.
        """
        if feed_types is None:
            feed_types = ["rss", "api"]
        if limits is None:
            limits = {}
        if document_uploads is None:
            document_uploads = []

        raw: dict[str, Any] = {
            "collection_timestamp": datetime.now(timezone.utc).isoformat(),
            "feed_types_used": feed_types,
            "news_articles": [],
            "ip_indicators": [],
            "iocs": [],
            "url_indicators": [],
            "malware_samples": [],
            "vulnerabilities": [],
            "stix_objects": [],
            "document_intel": [],
            "errors": [],
        }

        if "rss" in feed_types:
            rss_list = selected_rss_feeds if selected_rss_feeds is not None else feeds["rss"]
            try:
                raw["news_articles"] = fetch_rss_feeds(
                    rss_list,
                    limit_per_feed=limits.get("rss_per_feed", 5),
                    errors=raw["errors"],
                )
            except Exception as exc:
                raw["errors"].append({"feed": "RSS", "error": str(exc)})

        if "api" in feed_types:
            api_list = selected_api_feeds if selected_api_feeds is not None else None
            self._fetch_api_feeds(raw, limits, api_list)

        if "stix" in feed_types:
            for name, cfg in feeds["stix"].items():
                stix_type = cfg.get("type")
                try:
                    if stix_type == "taxii":
                        objs = fetch_from_taxii(
                            cfg["url"],
                            cfg["collection_id"],
                            limit=limits.get("stix_objects", 20),
                        )
                    elif stix_type == "file":
                        objs = fetch_from_file(
                            cfg["path"],
                            limit=limits.get("stix_objects", 20),
                        )
                    else:
                        objs = fetch_from_url(
                            cfg["url"],
                            limit=limits.get("stix_objects", 20),
                        )
                    raw["stix_objects"].extend(objs)
                except Exception as exc:
                    raw["errors"].append({"feed": f"STIX:{name}", "error": str(exc)})

        if document_uploads:
            doc_results, doc_errors = process_uploads(document_uploads)
            raw["document_intel"].extend(doc_results)
            raw["errors"].extend(doc_errors)

        # ── Time-range filtering ───────────────────────────────────────────────
        if time_from is not None or time_to is not None:
            _field_map = {
                "news_articles":  "published",
                "ip_indicators":  "first_seen",
                "iocs":           "first_seen",
                "url_indicators": "date_added",
                "malware_samples":"first_seen",
                "vulnerabilities":"date_added",
            }
            for key, field in _field_map.items():
                before = len(raw[key])
                raw[key] = self._filter_by_time(raw[key], field, time_from, time_to)
                after = len(raw[key])
                if before != after:
                    pass  # Filtered silently; display handles reporting

        return raw

    def _fetch_api_feeds(
        self,
        raw: dict[str, Any],
        limits: dict,
        api_list: list[dict] | None,
    ) -> None:
        """Fetch API feeds, dispatching built-ins by ID and custom feeds generically.

        If api_list is None, all built-in feeds are fetched (legacy behaviour).
        If api_list is provided, only the listed feeds are fetched.
        """
        # Determine which built-in feed IDs to run
        if api_list is None:
            builtin_ids = set(BUILTIN_API_HANDLERS.keys())
            custom_feeds: list[dict] = []
        else:
            builtin_ids = {f["id"] for f in api_list if f["id"] in BUILTIN_API_HANDLERS}
            custom_feeds = [f for f in api_list if f["id"] not in BUILTIN_API_HANDLERS]

        # ── Built-in handlers ──────────────────────────────────────────────────
        if "feodo_tracker" in builtin_ids:
            try:
                raw["ip_indicators"] = fetch_feodo_tracker(limit=limits.get("feodo_ips", 25))
            except Exception as exc:
                raw["errors"].append({"feed": "Feodo Tracker", "error": str(exc)})

        if "threatfox" in builtin_ids:
            try:
                raw["iocs"] = fetch_threatfox(limit=limits.get("threatfox_iocs", 15))
            except Exception as exc:
                raw["errors"].append({"feed": "ThreatFox", "error": str(exc)})

        if "urlhaus" in builtin_ids:
            try:
                raw["url_indicators"] = fetch_urlhaus(limit=limits.get("urlhaus_urls", 15))
            except Exception as exc:
                raw["errors"].append({"feed": "URLhaus", "error": str(exc)})

        if "malware_bazaar" in builtin_ids:
            try:
                raw["malware_samples"] = fetch_malware_bazaar(limit=limits.get("malware_samples", 10))
            except Exception as exc:
                raw["errors"].append({"feed": "MalwareBazaar", "error": str(exc)})

        if "cisa_kev" in builtin_ids:
            try:
                raw["vulnerabilities"] = fetch_cisa_kev(limit=limits.get("cisa_kevs", 20))
            except Exception as exc:
                raw["errors"].append({"feed": "CISA KEV", "error": str(exc)})

        # ── Custom (generic) feeds ─────────────────────────────────────────────
        for feed in custom_feeds:
            url = feed.get("url", "")
            method = feed.get("method", "GET")
            name = feed.get("name", url)
            try:
                items = fetch_generic_api(url, method=method, limit=50)
                raw.setdefault("generic_intel", []).extend(items)
            except Exception as exc:
                raw["errors"].append({"feed": name, "error": str(exc)})

    @staticmethod
    def _filter_by_time(
        items: list[dict],
        time_field: str,
        time_from: datetime | None,
        time_to: datetime | None,
    ) -> list[dict]:
        """Return only items whose `time_field` falls within [time_from, time_to].

        Items with no timestamp field at all are kept (no timestamp = always relevant).
        Items whose timestamp *cannot be parsed* are excluded (fail-closed) to avoid
        silently including out-of-range data when a time filter is explicitly set.
        """
        if time_from is None and time_to is None:
            return items

        # Normalise bounds to UTC-aware so comparisons are always tz-consistent.
        if time_from is not None and time_from.tzinfo is None:
            time_from = time_from.replace(tzinfo=timezone.utc)
        if time_to is not None and time_to.tzinfo is None:
            time_to = time_to.replace(tzinfo=timezone.utc)

        result = []
        for item in items:
            raw_ts = item.get(time_field)
            if not raw_ts:
                # No timestamp present — keep the item (it has no time context)
                result.append(item)
                continue
            try:
                if _HAS_DATEUTIL:
                    ts = _dateutil_parser.parse(str(raw_ts))
                else:
                    # Minimal fallback: try ISO 8601 and YYYY-MM-DD
                    s = str(raw_ts).strip()
                    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
                        try:
                            ts = datetime.strptime(s, fmt)
                            break
                        except ValueError:
                            continue
                    else:
                        # Could not parse — exclude (fail-closed)
                        continue
                # Make timezone-aware for comparison
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if time_from is not None and ts < time_from:
                    continue
                if time_to is not None and ts > time_to:
                    continue
                result.append(item)
            except Exception:
                # Unparseable timestamp — exclude (fail-closed)
                continue
        return result

    @staticmethod
    def summary_counts(raw: dict) -> dict[str, int]:
        """Return item counts per category for display purposes."""
        return {
            "news_articles": len(raw.get("news_articles", [])),
            "ip_indicators": len(raw.get("ip_indicators", [])),
            "iocs": len(raw.get("iocs", [])),
            "url_indicators": len(raw.get("url_indicators", [])),
            "malware_samples": len(raw.get("malware_samples", [])),
            "vulnerabilities": len(raw.get("vulnerabilities", [])),
            "stix_objects": len(raw.get("stix_objects", [])),
        }
