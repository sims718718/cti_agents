"""REST API-based OSINT feed collectors.

Sources (all free, no authentication required):
  - Feodo Tracker  – botnet C2 IPs
  - ThreatFox      – multi-type IOCs
  - URLhaus        – malicious URLs
  - MalwareBazaar  – recent malware samples
  - CISA KEV       – known exploited vulnerabilities
"""
from __future__ import annotations

from typing import Any

import requests

TIMEOUT = 15  # seconds per request


def _get(url: str, **kwargs) -> dict | list:
    """Perform a GET request and return parsed JSON. Raises on any error."""
    r = requests.get(url, timeout=TIMEOUT, **kwargs)
    r.raise_for_status()
    return r.json()


def _post(url: str, payload: dict, **kwargs) -> dict:
    """Perform a POST request and return parsed JSON. Raises on any error."""
    r = requests.post(url, json=payload, timeout=TIMEOUT, **kwargs)
    r.raise_for_status()
    return r.json()


# ── Feodo Tracker ─────────────────────────────────────────────────────────────

def fetch_feodo_tracker(limit: int = 25) -> list[dict[str, Any]]:
    """Return botnet C2 IP entries from Feodo Tracker."""
    data = _get("https://feodotracker.abuse.ch/downloads/ipblocklist.json")
    if not isinstance(data, list):
        return []

    iocs = []
    for entry in data[:limit]:
        iocs.append(
            {
                "type": "ip_indicator",
                "source": "Feodo Tracker",
                "ip": entry.get("ip_address", ""),
                "port": entry.get("port"),
                "malware": entry.get("malware", ""),
                "first_seen": entry.get("first_seen", ""),
                "last_online": entry.get("last_online", ""),
                "country": entry.get("country", ""),
            }
        )
    return iocs


# ── ThreatFox ─────────────────────────────────────────────────────────────────

def fetch_threatfox(days: int = 1, limit: int = 15) -> list[dict[str, Any]]:
    """Return recent IOCs from ThreatFox (abuse.ch)."""
    data = _post(
        "https://threatfox-api.abuse.ch/api/v1/",
        {"query": "get_iocs", "days": days},
    )
    if not isinstance(data, dict) or data.get("query_status") != "ok":
        return []

    iocs = []
    for entry in (data.get("data") or [])[:limit]:
        iocs.append(
            {
                "type": "ioc",
                "source": "ThreatFox",
                "ioc_value": entry.get("ioc", ""),
                "ioc_type": entry.get("ioc_type", ""),
                "threat_type": entry.get("threat_type", ""),
                "malware": entry.get("malware", ""),
                "confidence": entry.get("confidence_level", 0),
                "first_seen": entry.get("first_seen", ""),
                "tags": entry.get("tags") or [],
            }
        )
    return iocs


# ── URLhaus ───────────────────────────────────────────────────────────────────

def fetch_urlhaus(limit: int = 15) -> list[dict[str, Any]]:
    """Return recently reported malicious URLs from URLhaus."""
    data = _get("https://urlhaus-api.abuse.ch/v1/urls/recent/")
    if not isinstance(data, dict):
        return []

    urls = []
    for entry in (data.get("urls") or [])[:limit]:
        urls.append(
            {
                "type": "url_indicator",
                "source": "URLhaus",
                "url": entry.get("url", ""),
                "url_status": entry.get("url_status", ""),
                "threat": entry.get("threat", ""),
                "date_added": entry.get("date_added", ""),
                "tags": entry.get("tags") or [],
                "host": entry.get("host", ""),
            }
        )
    return urls


# ── MalwareBazaar ─────────────────────────────────────────────────────────────

def fetch_malware_bazaar(limit: int = 10) -> list[dict[str, Any]]:
    """Return recent malware sample metadata from MalwareBazaar."""
    data = _post(
        "https://mb-api.abuse.ch/api/v1/",
        {"query": "get_recent", "selector": "time"},
    )
    if not isinstance(data, dict) or data.get("query_status") != "ok":
        return []

    samples = []
    for entry in (data.get("data") or [])[:limit]:
        samples.append(
            {
                "type": "malware_sample",
                "source": "MalwareBazaar",
                "sha256": entry.get("sha256_hash", ""),
                "file_name": entry.get("file_name", ""),
                "file_type": entry.get("file_type", ""),
                "malware_family": entry.get("signature", ""),
                "first_seen": entry.get("first_seen", ""),
                "tags": entry.get("tags") or [],
                "reporter": entry.get("reporter", ""),
            }
        )
    return samples


# ── CISA Known Exploited Vulnerabilities ──────────────────────────────────────

def fetch_cisa_kev(limit: int = 20) -> list[dict[str, Any]]:
    """Return recently added CISA Known Exploited Vulnerabilities."""
    data = _get(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    if not isinstance(data, dict):
        return []

    # Catalog is sorted oldest-first; grab the most recent additions
    vulns_raw = data.get("vulnerabilities", [])
    vulns = []
    for entry in reversed(vulns_raw[:limit]):
        vulns.append(
            {
                "type": "vulnerability",
                "source": "CISA KEV",
                "cve_id": entry.get("cveID", ""),
                "vendor_project": entry.get("vendorProject", ""),
                "product": entry.get("product", ""),
                "vulnerability_name": entry.get("vulnerabilityName", ""),
                "date_added": entry.get("dateAdded", ""),
                "short_description": entry.get("shortDescription", ""),
                "required_action": entry.get("requiredAction", ""),
                "due_date": entry.get("dueDate", ""),
            }
        )
    return vulns


def fetch_generic_api(url: str, method: str = "GET", limit: int = 50) -> list[dict[str, Any]]:
    """Fetch a custom API endpoint with no authentication.

    If the response is a JSON list, returns up to `limit` items wrapped in a
    generic intel dict.  On any error raises so the caller can log it.
    """
    if method.upper() == "POST":
        data = _post(url, {})
    else:
        data = _get(url)

    items = data if isinstance(data, list) else (data.get("data") or data.get("results") or data.get("items") or [])
    if not isinstance(items, list):
        # Wrap entire response as a single item
        items = [data]

    result = []
    for item in items[:limit]:
        result.append({
            "type": "generic_intel",
            "source": url,
            "data": item,
        })
    return result
