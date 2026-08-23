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
                    "mitre_techniques": [
                        {
                            "technique_id": "T1071",
                            "technique_name": "Application Layer Protocol",
                            "tactic": "Command and Control",
                            "confidence": "high",
                        }
                    ],
                    "diamond_model": {
                        "adversary": "Unattributed Emotet operators.",
                        "capability": "Emotet banking trojan with modular loader.",
                        "infrastructure": "C2 over HTTPS to 192.0.2.1.",
                        "victim": "Financial sector organizations.",
                    },
                    "narrative": (
                        "Unattributed operators are using Emotet's modular loader "
                        "to establish C2 over HTTPS to 192.0.2.1, targeting financial "
                        "sector victims via App Layer Protocol beaconing."
                    ),
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
                "diamond_vertex_focus": ["infrastructure"],
                "risk_level": "high",
                "mitre_techniques": [
                    {
                        "technique_id": "T1071",
                        "technique_name": "Application Layer Protocol",
                        "tactic": "Command and Control",
                        "confidence": "high",
                    }
                ],
                "hunt_queries": [
                    {
                        "platform": "KQL",
                        "description": "Detect connections to Emotet C2.",
                        "query": "NetworkConnection | where DestinationIP == '192.0.2.1'",
                    }
                ],
            }
        ],
        "ioc_hunt_list": {"ips_to_hunt": ["192.0.2.1"], "urls_to_hunt": [], "hashes_to_hunt": [], "domains_to_hunt": []},
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
            "intel_diamond_narrative_quality": 8,
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
def mock_feed_collection(mocker):
    """Patch every built-in feed fetcher used by IntelCollectorAgent to return
    no items, so tests can exercise pipeline/orchestration layers without
    touching the network. Was previously a 6-line block duplicated across
    every integration test.
    """
    for name in (
        "fetch_rss_feeds",
        "fetch_feodo_tracker",
        "fetch_threatfox",
        "fetch_urlhaus",
        "fetch_malware_bazaar",
        "fetch_cisa_kev",
    ):
        mocker.patch(f"agents.intel_collector.{name}", return_value=[])
    return mocker


@pytest.fixture
def mock_llm_client(mocker):
    """Factory fixture for pipeline-level tests: call with a list of raw
    response strings and get back a MagicMock(spec=anthropic.Anthropic)
    that returns them in order from messages.create, already patched into
    pipeline.anthropic.Anthropic with a valid ANTHROPIC_API_KEY.

    Distinct from mock_anthropic_client below (single canned response, no
    ordering) because pipeline-level tests need a *sequence* of distinct
    responses — one per agent call in order.
    """
    import anthropic

    def _build(responses: list[str]):
        client = MagicMock(spec=anthropic.Anthropic)
        client.messages.create.side_effect = [
            MagicMock(content=[MagicMock(text=r)]) for r in responses
        ]
        mocker.patch("pipeline.anthropic.Anthropic", return_value=client)
        mocker.patch("pipeline.ANTHROPIC_API_KEY", "test-key")
        return client

    return _build


@pytest.fixture
def quiet_display():
    """Display instance that suppresses all terminal output during tests."""
    from utils.display import Display
    d = Display()
    d.console = Console(quiet=True)
    return d
