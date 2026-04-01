"""Configuration for the CTI Multi-Agent System."""
import os
from dotenv import load_dotenv

load_dotenv()

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")

MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")
MAX_ITERATIONS = 3       # Max lead-analyst review cycles
QUALITY_THRESHOLD = 7    # Score out of 10 needed for approval

# ── RSS feeds ─────────────────────────────────────────────────────────────────
RSS_FEEDS = [
    {"id": "sans",          "name": "SANS Internet Storm Center", "url": "https://isc.sans.edu/rssfeed_full.xml"},
    {"id": "krebs",         "name": "Krebs on Security",          "url": "https://krebsonsecurity.com/feed/"},
    {"id": "bleeping",      "name": "Bleeping Computer",          "url": "https://www.bleepingcomputer.com/feed/"},
    {"id": "hackernews",    "name": "The Hacker News",            "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"id": "recordedfuture","name": "Recorded Future",            "url": "https://www.recordedfuture.com/feed"},
]

# ── Abuse.ch / CISA API endpoints ─────────────────────────────────────────────
API_FEEDS = {
    "feodo_tracker": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        "method": "GET",
        "description": "Botnet C2 IP block-list (Feodo Tracker)",
    },
    "threatfox": {
        "url": "https://threatfox-api.abuse.ch/api/v1/",
        "method": "POST",
        "payload": {"query": "get_iocs", "days": 1},
        "description": "Recent IOCs from ThreatFox",
    },
    "urlhaus": {
        "url": "https://urlhaus-api.abuse.ch/v1/urls/recent/",
        "method": "GET",
        "description": "Recent malicious URLs (URLhaus)",
    },
    "malware_bazaar": {
        "url": "https://mb-api.abuse.ch/api/v1/",
        "method": "POST",
        "payload": {"query": "get_recent", "selector": "time"},
        "description": "Recent malware samples (MalwareBazaar)",
    },
    "cisa_kev": {
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "method": "GET",
        "description": "CISA Known Exploited Vulnerabilities",
    },
}

# ── STIX sources ──────────────────────────────────────────────────────────────
STIX_FEEDS = {
    # MITRE ATT&CK TAXII 2.1 (public, no auth)
    "mitre_attack_taxii": {
        "type": "taxii",
        "url": "https://attack-taxii.mitre.org/api/v21/",
        "collection_id": "x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019",
        "description": "MITRE ATT&CK Enterprise via TAXII 2.1",
    },
}

# Consolidated feed config passed to agents
FEEDS = {
    "rss": RSS_FEEDS,
    "api": API_FEEDS,
    "stix": STIX_FEEDS,
}

# Items per source (to stay within LLM context limits)
LIMITS = {
    "rss_per_feed":   5,
    "feodo_ips":      25,
    "threatfox_iocs": 15,
    "urlhaus_urls":   15,
    "malware_samples":10,
    "cisa_kevs":      20,
    "stix_objects":   20,
}
