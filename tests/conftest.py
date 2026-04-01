"""Shared pytest fixtures for CTI Agents tests."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from rich.console import Console


@pytest.fixture
def mock_anthropic_client():
    """A MagicMock standing in for anthropic.Anthropic — prevents real API calls."""
    client = MagicMock()
    # Default: content[0].text returns a JSON string that _parse_json can handle
    client.messages.create.return_value.content = [
        MagicMock(text='{"result": "ok"}')
    ]
    return client


@pytest.fixture
def sample_raw_intel():
    """Minimal but valid raw_intel dict covering all keys."""
    return {
        "collection_timestamp": "2024-03-01T12:00:00+00:00",
        "feed_types_used": ["rss", "api"],
        "news_articles": [
            {
                "source": "SANS ISC",
                "title": "Test Alert",
                "summary": "A test article summary.",
                "link": "https://example.com/1",
                "published": "2024-03-01T10:00:00Z",
                "type": "news_article",
            }
        ],
        "ip_indicators": [
            {
                "type": "ip_indicator",
                "source": "Feodo Tracker",
                "ip": "192.0.2.1",
                "port": 443,
                "malware": "Emotet",
                "first_seen": "2024-02-20",
                "last_online": "2024-03-01",
                "country": "RU",
            }
        ],
        "iocs": [],
        "url_indicators": [],
        "malware_samples": [],
        "vulnerabilities": [],
        "stix_objects": [],
        "document_intel": [],
        "errors": [],
    }


@pytest.fixture
def sample_intel_summary():
    """Minimal valid IntelSummarizerAgent output."""
    return {
        "executive_summary": "Test threat landscape summary.",
        "threat_landscape": {
            "primary_threats": [
                {
                    "name": "Emotet",
                    "type": "botnet",
                    "severity": "high",
                    "description": "Banking trojan.",
                    "affected_sectors": ["finance"],
                    "iocs": ["192.0.2.1"],
                    "mitre_techniques": ["T1071"],
                    "sources": ["Feodo Tracker"],
                }
            ],
            "active_campaigns": [],
            "exploited_vulnerabilities": [],
        },
        "key_iocs": {"ips": ["192.0.2.1"], "urls": [], "hashes": [], "domains": []},
        "recommended_priorities": ["Block Emotet C2 IPs"],
        "intelligence_gaps": [],
    }


@pytest.fixture
def sample_hunt_plan():
    """Minimal valid ThreatHunterAgent output."""
    return {
        "hunt_plan": {
            "title": "Emotet Hunt",
            "objective": "Detect Emotet C2 communications.",
            "priority": "high",
            "estimated_duration": "4 hours",
            "analyst_skill_level": "intermediate",
        },
        "hypotheses": [
            {
                "id": "H1",
                "title": "Emotet C2 Beaconing",
                "description": "Look for beaconing to known Emotet C2 IPs.",
                "risk_level": "high",
                "mitre_technique": "T1071",
                "hunt_queries": [
                    {
                        "query_type": "KQL",
                        "data_source": "Network Logs",
                        "query": "NetworkConnection | where DestinationIP == '192.0.2.1'",
                        "description": "Detect connections to Emotet C2.",
                    }
                ],
            }
        ],
        "ioc_hunt_list": {"ips": ["192.0.2.1"], "urls": [], "hashes": [], "domains": []},
    }


@pytest.fixture
def sample_review_approved():
    """Review dict representing an approved analysis."""
    return {
        "overall_score": 8,
        "approved": True,
        "scores": {
            "intel_completeness": 8,
            "intel_accuracy": 8,
            "intel_actionability": 8,
            "hunt_hypothesis_quality": 8,
            "hunt_query_quality": 8,
            "hunt_coverage": 8,
        },
        "strengths": ["Good IOC coverage", "Clear prioritization"],
        "critical_gaps": [],
        "summarizer_feedback": "",
        "hunter_feedback": "",
        "reviewer_notes": "Solid analysis.",
    }


@pytest.fixture
def quiet_display():
    """Display instance that suppresses all terminal output during tests."""
    from utils.display import Display
    d = Display()
    d.console = Console(quiet=True)
    return d
