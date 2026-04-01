"""STIX 2.x feed collection.

Supports:
  - TAXII 2.1 servers (e.g., MITRE ATT&CK public TAXII)
  - Raw STIX 2.x JSON bundle URLs
  - Local STIX bundle files
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import requests

# taxii2-client is an optional dep; fall back gracefully if absent
try:
    from taxii2client.v21 import Server as TaxiiServer, as_pages
    TAXII_AVAILABLE = True
except ImportError:
    TAXII_AVAILABLE = False

TIMEOUT = int(os.getenv("STIX_TIMEOUT", "20"))

# STIX object types we actually care about for threat hunting
RELEVANT_TYPES = {
    "threat-actor",
    "intrusion-set",
    "campaign",
    "malware",
    "tool",
    "attack-pattern",
    "vulnerability",
    "indicator",
    "course-of-action",
    "report",
}


def _extract_fields(obj: dict) -> dict[str, Any]:
    """Flatten a STIX object to the fields useful for analysis."""
    return {
        "id": obj.get("id", ""),
        "type": obj.get("type", ""),
        "name": obj.get("name", ""),
        "description": (obj.get("description", "") or "")[:800],
        "aliases": obj.get("aliases", []),
        "labels": obj.get("labels", []),
        "created": obj.get("created", ""),
        "modified": obj.get("modified", ""),
        # Indicator-specific
        "pattern": obj.get("pattern", ""),
        "indicator_types": obj.get("indicator_types", []),
        # Malware/tool-specific
        "malware_types": obj.get("malware_types", []),
        "tool_types": obj.get("tool_types", []),
        # ATT&CK technique ref (x_ extensions)
        "kill_chain_phases": obj.get("kill_chain_phases", []),
        "external_references": [
            {
                "source_name": ref.get("source_name", ""),
                "external_id": ref.get("external_id", ""),
                "url": ref.get("url", ""),
            }
            for ref in obj.get("external_references", [])[:3]
        ],
    }


def fetch_from_taxii(
    server_url: str,
    collection_id: str,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Fetch STIX objects from a TAXII 2.1 server collection.

    Args:
        server_url: Base URL of the TAXII server.
        collection_id: TAXII collection ID to query.
        limit: Max number of STIX objects to return.

    Returns:
        List of simplified STIX object dicts.

    Raises:
        RuntimeError: If taxii2-client is not installed.
        ValueError: If the server returns no API roots or the collection is not found.
        Exception: On network or server errors.
    """
    if not TAXII_AVAILABLE:
        return []

    server = TaxiiServer(server_url, verify=True)

    if not server.api_roots:
        raise ValueError(f"TAXII server returned no API roots: {server_url}")

    api_root = server.api_roots[0]
    collection = None
    for c in api_root.collections:
        if c.id == collection_id:
            collection = c
            break

    if collection is None:
        raise ValueError(f"TAXII collection not found: {collection_id}")

    objects = []
    for bundle_page in as_pages(collection.get_objects, per_request=100):
        for obj in bundle_page.get("objects", []):
            if obj.get("type") in RELEVANT_TYPES:
                objects.append(_extract_fields(obj))
            if len(objects) >= limit:
                break
        if len(objects) >= limit:
            break

    return objects


def fetch_from_url(url: str, limit: int = 20) -> list[dict[str, Any]]:
    """Download and parse a STIX 2.x JSON bundle from a URL.

    Raises:
        requests.HTTPError: On HTTP error responses.
        Exception: On network or parse errors.
    """
    r = requests.get(url, timeout=TIMEOUT)
    r.raise_for_status()
    bundle = r.json()
    return _parse_bundle(bundle, limit)


def fetch_from_file(path: str, limit: int = 20) -> list[dict[str, Any]]:
    """Parse a local STIX 2.x JSON bundle file.

    Raises:
        FileNotFoundError: If the path does not exist.
        Exception: On JSON parse errors.
    """
    with open(path, "r", encoding="utf-8") as f:
        bundle = json.load(f)
    return _parse_bundle(bundle, limit)


def _parse_bundle(bundle: dict, limit: int) -> list[dict[str, Any]]:
    objects = []
    for obj in bundle.get("objects", []):
        if obj.get("type") in RELEVANT_TYPES:
            objects.append(_extract_fields(obj))
        if len(objects) >= limit:
            break
    return objects
